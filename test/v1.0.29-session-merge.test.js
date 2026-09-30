import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  cpSync,
  existsSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifySignature } from '../dist/lib/sign.js';
import { listReceiptFiles } from '../dist/lib/retention.js';
import { isInsideSessionPackage, isSessionPackageDirName } from '../dist/lib/receipt.js';
import { cmdSessionImport } from '../dist/commands/session-import.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const LINK_ENV = [
  'AGENT_RECEIPT_SESSION',
  'AGENT_RECEIPT_PARENT',
  'AGENT_RECEIPT_AGENT',
  'AGENT_RECEIPT_HOST',
];

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function spawnEnv(extra = {}) {
  const env = { ...process.env, NO_COLOR: '1' };
  for (const key of LINK_ENV) delete env[key];
  for (const [key, value] of Object.entries(extra)) {
    if (value === undefined || value === null) delete env[key];
    else env[key] = value;
  }
  return env;
}

function cliResult(cwd, args, extraEnv) {
  const r = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: spawnEnv(extraEnv),
    timeout: 30000,
  });
  return { code: r.status === null ? 1 : r.status, out: r.stdout || '', err: r.stderr || '' };
}

function cli(cwd, args, extraEnv) {
  const r = cliResult(cwd, args, extraEnv);
  if (r.code !== 0) throw new Error(`exit ${r.code}\n${r.out}\n${r.err}`);
  return r.out;
}

function parseJson(out) {
  return JSON.parse(out);
}

function field(md, label) {
  const prefix = `- **${label}**:`;
  for (const line of md.split('\n')) {
    if (!line.startsWith(prefix)) continue;
    const value = line.slice(prefix.length).trim().replace(/^`|`$/g, '');
    return value || null;
  }
  return null;
}

function fileSha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function auditText(dir) {
  const path = join(dir, '.agent-receipt', 'audit.jsonl');
  return existsSync(path) ? readFileSync(path, 'utf8') : '';
}

function indexDoc(dir) {
  const path = join(dir, '.agent-receipt', 'index.json');
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function packageMarks(dir) {
  const base = join(dir, '.agent-receipt');
  if (!existsSync(base)) return [];
  return readdirSync(base).filter((name) => name.includes('.session') || name.includes('.partial'));
}

function flipEmbeddedHash(markdown) {
  return markdown.replace(/agent-receipt-sha256:\s*([0-9a-f]{64})/, (all, hex) => {
    const flipped = (hex[0] === 'a' ? 'b' : 'a') + hex.slice(1);
    return all.replace(hex, flipped);
  });
}

describe('v1.0.29 cross-host session merge', () => {
  const dirs = [];
  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo() {
    const dir = mkdtempSync(join(tmpdir(), 'agent-receipt-1029-'));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# session-merge\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function commitFile(dir, name, content) {
    writeFileSync(join(dir, name), content);
    git(dir, ['add', name]);
    git(dir, ['commit', '-m', name]);
  }

  function wrapJson(dir, args) {
    const wrapped = cliResult(dir, ['wrap', ...args, '--json']);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    return parseJson(wrapped.out);
  }

  function sessionPair(dir, session, host) {
    const slug = session.replace(/[^A-Za-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'sess';
    const hostArgs = host ? ['--host', host] : [];
    commitFile(dir, `parent-${slug}.txt`, 'parent\n');
    const parent = wrapJson(dir, [
      '--session', session,
      '--agent', 'parent',
      '--message', 'parent',
      ...hostArgs,
    ]);
    const parentId = field(readFileSync(parent.path, 'utf8'), 'Id');
    assert.match(parentId, /^r-[0-9a-f]{16}$/);
    commitFile(dir, `child-${slug}.txt`, 'child\n');
    const child = wrapJson(dir, [
      '--session', session,
      '--parent', parentId,
      '--agent', 'child',
      '--message', 'child',
      ...hostArgs,
    ]);
    return { parent, child, parentId };
  }

  function exportSession(dir, session, extra = []) {
    const exported = cliResult(dir, ['session', 'export', session, ...extra, '--json']);
    assert.equal(exported.code, 0, exported.out + exported.err);
    return parseJson(exported.out);
  }

  const NESTED_HOST = 'hostA-secret';
  const NESTED_AWS = 'AKIAIOSFODNN7EXAMPLE';
  const NESTED_OMIT = '[REDACTED — nested receipt/index body omitted]';
  const GIT_CLEAN = {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  };

  function countHits(dir, needle) {
    const buf = Buffer.from(needle);
    let hits = 0;
    const walk = (current) => {
      for (const ent of readdirSync(current, { withFileTypes: true })) {
        const path = join(current, ent.name);
        if (ent.isSymbolicLink()) continue;
        if (ent.isDirectory()) {
          walk(path);
          continue;
        }
        if (!ent.isFile()) continue;
        const data = readFileSync(path);
        let from = 0;
        while (from <= data.length - buf.length) {
          const at = data.indexOf(buf, from);
          if (at < 0) break;
          hits += 1;
          from = at + buf.length;
        }
      }
    };
    walk(dir);
    return hits;
  }

  function receiptBodies(dir) {
    const out = join(dir, '.agent-receipt', 'receipts');
    return readdirSync(out)
      .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
      .map((name) => readFileSync(join(out, name), 'utf8'));
  }

  it('documents 1.0.29, the session package, and no new runtime dependencies', () => {
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.29\]/);
    assert.match(changelog, /session export/);
    assert.match(changelog, /session import/);
    assert.match(changelog, /session-manifest\.json/);
    assert.match(changelog, /signed HTML report \/ signed one-pager/);
    assert.match(changelog, /native adapters/);
    assert.match(changelog, /in-toto\/SLSA/);
    assert.match(changelog, /Sigstore keyless/);
    assert.match(changelog, /published GitHub Action/);
    assert.match(changelog, /policy packs/);
    assert.match(changelog, /local web viewer/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /npm Trusted Publishing/);
    assert.match(changelog, /does not publish to npm/);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.29');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.29');
    assert.equal(lock.packages[''].version, '1.0.29');
    assert.equal(lock.packages[''].dependencies, undefined);
    assert.match(readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8'), /1\.0\.29/);
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'session-package.schema.json'), 'utf8'));
    assert.equal(schema.properties.kind.const, 'agent-receipt-session');
    assert.equal(schema.properties.version.const, 1);
    assert.equal(schema.additionalProperties, false);
    const itemRequired = schema.properties.receipts.items.required;
    assert.ok(itemRequired.includes('originalFingerprint'));
    assert.ok(itemRequired.includes('resignedBy'));
    assert.match(changelog, /--resign/);
    assert.match(changelog, /originalFingerprint/);
    assert.match(changelog, /nested receipt/);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /## Cross-host session merge/);
    assert.match(readme, /session export/);
    assert.match(readme, /session import/);
    assert.match(readme, /originalFingerprint/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /### Cross-host session merge/);
    assert.match(business, /session-manifest\.sig\.json/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.29/);
    assert.match(mirror, /session export/);
    assert.match(mirror, /session import/);
    assert.match(mirror, /ci-link-1028/);
    for (const name of readdirSync(join(root, '.github', 'workflows'))) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /v1\.0\.29/);
      assert.doesNotMatch(live, /session export/);
    }
    const help = cli(root, ['help', 'session']);
    assert.match(help, /session <id>/);
    assert.match(help, /session export/);
    assert.match(help, /session pack/);
    assert.match(help, /session import/);
    assert.match(help, /session merge/);
    assert.match(help, /\*\.session/);
    assert.match(help, /--require-sig/);
    assert.match(help, /--dry-run/);
    assert.match(help, /--resign/);
    assert.match(help, /--max-receipt-bytes/);
    assert.match(cli(root, ['help']), /session export <id>/);
    const dir = initRepo();
    const doctor = parseJson(cli(dir, ['doctor', '--json']));
    const link = doctor.checks.find((check) => check.id === 'link');
    assert.ok(link);
    assert.equal(link.status, 'info');
    assert.match(link.detail, /wrap --link/);
    assert.match(link.detail, /session export/);
    assert.match(link.detail, /session import/);
  });

  it('ignores *.session package directories the way it ignores *.share', () => {
    assert.equal(isSessionPackageDirName('ci-link.session'), true);
    assert.equal(isSessionPackageDirName('notes.session.md'), false);
    assert.equal(isSessionPackageDirName('session-manifest.json'), false);
    assert.equal(
      isInsideSessionPackage('/repo/.agent-receipt/receipts/held.session/receipts/a.md'),
      true,
    );
    assert.equal(
      isInsideSessionPackage('/repo/.agent-receipt/ci-link.session/session-manifest.json'),
      true,
    );
    assert.equal(isInsideSessionPackage('/repo/.agent-receipt/receipts/receipt-a.md'), false);

    const dir = initRepo();
    commitFile(dir, 'keep.txt', 'keep\n');
    const kept = wrapJson(dir, ['--agent', 'ci', '--message', 'keep']);
    const outDir = join(dir, '.agent-receipt', 'receipts');
    const hidden = join(outDir, 'held.session', 'receipts');
    mkdirSync(hidden, { recursive: true });
    const hiddenReceipt = join(hidden, 'receipt-hidden.md');
    writeFileSync(hiddenReceipt, `${readFileSync(kept.path, 'utf8')}\n`);
    const listed = listReceiptFiles(dir);
    assert.ok(listed.every((file) => !String(file.rel).includes('.session')));
    assert.equal(listed.some((file) => file.abs === hiddenReceipt || file.path === hiddenReceipt), false);

    const indexPath = join(dir, '.agent-receipt', 'index.json');
    const indexBackup = readFileSync(indexPath, 'utf8');
    rmSync(indexPath);
    const last = parseJson(cli(dir, ['last', '--json']));
    assert.equal(String(last.path).includes('.session'), false);
    const history = parseJson(cli(dir, ['history', '--json']));
    assert.ok(history.every((row) => !String(row.path).includes('.session')));
    writeFileSync(indexPath, indexBackup);
    const pruned = parseJson(cli(dir, ['prune', '--dry-run', '--json']));
    assert.ok(pruned.deleted.every((row) => !String(row.path).includes('.session')));
    assert.equal(existsSync(hiddenReceipt), true);
  });

  it('exports a masked package, refuses an empty session, and blocks a verify failure', () => {
    const dir = initRepo();
    const session = 'sess-mask';
    const { parent } = sessionPair(dir, session, 'hq-host');
    const original = readFileSync(parent.path, 'utf8');
    assert.equal(field(original, 'Host'), 'hq-host');
    const auditBefore = auditText(dir);
    const indexBefore = JSON.stringify(indexDoc(dir));

    const human = cliResult(dir, ['session', 'export', session]);
    assert.equal(human.code, 0, human.out + human.err);
    assert.match(human.out, /VERIFIED/);
    assert.match(human.out, /wrote:/);
    assert.match(human.out, /keygen/);

    const report = exportSession(dir, session, ['--out', 'again-mask']);
    assert.equal(report.command, 'session-export');
    assert.equal(report.version, '1.0.29');
    assert.equal(report.ok, true);
    assert.equal(report.exitCode, 0);
    assert.equal(report.session, session);
    assert.equal(report.receiptCount, 2);
    assert.equal(report.includeHost, false);
    assert.equal(report.written, true);
    assert.equal(report.manifestSigPath, null);
    assert.equal(basename(report.packagePath), 'again-mask');
    const manifest = JSON.parse(readFileSync(report.manifestPath, 'utf8'));
    assert.equal(manifest.kind, 'agent-receipt-session');
    assert.equal(manifest.version, 1);
    assert.equal(manifest.cliVersion, '1.0.29');
    assert.equal(manifest.session, session);
    assert.equal(manifest.receiptCount, 2);
    assert.equal(manifest.includeHost, false);
    assert.equal(manifest.receipts.length, 2);
    assert.equal(existsSync(join(report.packagePath, 'session-manifest.sig.json')), false);
    const agents = new Set();
    for (const entry of manifest.receipts) {
      assert.match(entry.path, /^receipts\/[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.md$/);
      assert.equal(entry.signed, false);
      assert.equal(entry.fingerprint, null);
      assert.equal(entry.sigBytes, undefined);
      assert.equal(entry.host, '[REDACTED]');
      const packed = join(report.packagePath, entry.path);
      assert.equal(fileSha256(packed), entry.bytes);
      const text = readFileSync(packed, 'utf8');
      assert.equal(field(text, 'Host'), '[REDACTED]');
      assert.equal(field(text, 'Session'), session);
      assert.match(text, /- \*\*Host\*\*: \[REDACTED\]/);
      assert.equal(existsSync(packed.replace(/\.md$/, '.sig.json')), false);
      const checked = parseJson(cli(dir, ['verify', packed, '--json']));
      assert.equal(checked.ok, true);
      assert.equal(checked.sha256, entry.sha256);
      agents.add(entry.agent);
    }
    assert.deepEqual(agents, new Set(['parent', 'child']));
    const child = manifest.receipts.find((entry) => entry.agent === 'child');
    const parentEntry = manifest.receipts.find((entry) => entry.agent === 'parent');
    assert.equal(child.parent, parentEntry.id);
    assert.equal(parentEntry.parent, null);
    assert.equal(readFileSync(parent.path, 'utf8'), original);
    assert.equal(auditText(dir), auditBefore);
    assert.equal(JSON.stringify(indexDoc(dir)), indexBefore);

    const included = exportSession(dir, session, ['--include-host', '--out', 'with-host']);
    const includedManifest = JSON.parse(readFileSync(included.manifestPath, 'utf8'));
    assert.equal(includedManifest.includeHost, true);
    for (const entry of includedManifest.receipts) {
      const text = readFileSync(join(included.packagePath, entry.path), 'utf8');
      assert.equal(field(text, 'Host'), 'hq-host');
      assert.equal(entry.host, 'hq-host');
    }
    const parentPacked = includedManifest.receipts.find((entry) => entry.id === field(original, 'Id'));
    assert.equal(readFileSync(join(included.packagePath, parentPacked.path), 'utf8'), original);

    const empty = cliResult(dir, ['session', 'export', 'missing-sess', '--json']);
    assert.equal(empty.code, 1);
    const emptyBody = parseJson(empty.out);
    assert.equal(emptyBody.ok, false);
    assert.equal(emptyBody.written, false);
    assert.equal(emptyBody.receiptCount, 0);
    assert.match(emptyBody.reason, /no receipts/);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'missing-sess.session')), false);

    const brokenDir = initRepo();
    const broken = sessionPair(brokenDir, 'sess-broken', 'hq-host');
    const beforeMarks = packageMarks(brokenDir);
    const intact = readFileSync(broken.parent.path, 'utf8');
    const flipped = flipEmbeddedHash(intact);
    assert.notEqual(flipped, intact);
    writeFileSync(broken.parent.path, flipped);
    const refused = cliResult(brokenDir, ['session', 'export', 'sess-broken', '--json']);
    assert.equal(refused.code, 2);
    const refusedBody = parseJson(refused.out);
    assert.equal(refusedBody.ok, false);
    assert.equal(refusedBody.written, false);
    assert.match(refusedBody.reason, /failed verify/);
    assert.deepEqual(packageMarks(brokenDir), beforeMarks);

    const sidecarDir = initRepo();
    const side = sessionPair(sidecarDir, 'sess-side');
    writeFileSync(side.parent.path.replace(/\.md$/, '.sig.json'), '{', 'utf8');
    const badSig = cliResult(sidecarDir, ['session', 'export', 'sess-side', '--json']);
    assert.equal(badSig.code, 2, badSig.out + badSig.err);
    assert.match(parseJson(badSig.out).reason, /signature/);
    assert.equal(existsSync(join(sidecarDir, '.agent-receipt', 'sess-side.session')), false);
  });

  it('signs the manifest and re-signed receipts when local keys load', () => {
    const dir = initRepo();
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    sessionPair(dir, 'sess-signed', 'hq-host');
    const report = exportSession(dir, 'sess-signed');
    assert.equal(report.manifestSigPath, join(report.packagePath, 'session-manifest.sig.json'));
    assert.equal(existsSync(report.manifestSigPath), true);
    const manifestSig = JSON.parse(readFileSync(report.manifestSigPath, 'utf8'));
    const manifestCheck = verifySignature(manifestSig, fileSha256(report.manifestPath));
    assert.equal(manifestCheck.ok, true, manifestCheck.reason || '');
    assert.equal(manifestSig.fingerprint, keys.fingerprint);
    assert.doesNotMatch(readFileSync(report.manifestSigPath, 'utf8'), /PRIVATE KEY/);
    const manifest = JSON.parse(readFileSync(report.manifestPath, 'utf8'));
    assert.equal(manifest.cliVersion, '1.0.29');
    for (const entry of manifest.receipts) {
      assert.equal(entry.signed, true);
      assert.equal(entry.fingerprint, keys.fingerprint);
      assert.match(entry.sigBytes, /^[0-9a-f]{64}$/);
      const sigPath = join(report.packagePath, entry.path.replace(/\.md$/, '.sig.json'));
      assert.equal(fileSha256(sigPath), entry.sigBytes);
      assert.doesNotMatch(readFileSync(sigPath, 'utf8'), /PRIVATE KEY/);
      const receiptSig = JSON.parse(readFileSync(sigPath, 'utf8'));
      const receiptCheck = verifySignature(receiptSig, entry.sha256);
      assert.equal(receiptCheck.ok, true, receiptCheck.reason || '');
    }
    assert.equal(basename(join(dir, '.agent-receipt', 'sess-signed.session')), 'sess-signed.session');
    assert.equal(existsSync(join(dir, '.agent-receipt', 'sess-signed.session', 'session-manifest.json')), true);
  });

  it('names an unsafe session id from a hash and keeps the real id in the manifest', () => {
    const dir = initRepo();
    const session = 'old sess/1';
    sessionPair(dir, session);
    const report = exportSession(dir, session);
    const digest = createHash('sha256').update(session, 'utf8').digest('hex').slice(0, 12);
    assert.equal(basename(report.packagePath), `session-${digest}.session`);
    const manifest = JSON.parse(readFileSync(report.manifestPath, 'utf8'));
    assert.equal(manifest.session, session);
    assert.equal(manifest.receiptCount, 2);
  });

  it('packs orphan and cross-session warnings and refuses an existing destination', () => {
    const dir = initRepo();
    commitFile(dir, 'solo.txt', 'solo\n');
    wrapJson(dir, [
      '--session', 'orphan-sess',
      '--parent', 'ab'.repeat(32),
      '--agent', 'solo',
      '--message', 'solo',
    ]);
    const orphan = exportSession(dir, 'orphan-sess');
    const orphanManifest = JSON.parse(readFileSync(orphan.manifestPath, 'utf8'));
    assert.equal(orphanManifest.receipts.length, 1);
    assert.equal(orphanManifest.receipts[0].orphan, true);
    assert.ok(orphanManifest.warnings.includes('orphan'));
    assert.ok(orphanManifest.receipts[0].warnings.includes('orphan'));

    const { parentId } = sessionPair(dir, 'sess-a');
    commitFile(dir, 'other.txt', 'other\n');
    wrapJson(dir, [
      '--session', 'sess-b',
      '--parent', parentId,
      '--agent', 'child',
      '--message', 'other session',
    ]);
    const crossed = exportSession(dir, 'sess-b');
    const crossedManifest = JSON.parse(readFileSync(crossed.manifestPath, 'utf8'));
    assert.ok(crossedManifest.warnings.includes('cross-session-parent'));
    assert.equal(crossed.exitCode, 0);

    const firstManifest = readFileSync(orphan.manifestPath);
    const again = cliResult(dir, ['session', 'export', 'orphan-sess', '--json']);
    assert.equal(again.code, 1);
    assert.match(parseJson(again.out).reason, /already exists/);
    assert.equal(readFileSync(orphan.manifestPath).equals(firstManifest), true);

    const packed = cliResult(dir, ['session', 'pack', 'sess-b', '--out', 'alias-pack', '--json']);
    assert.equal(packed.code, 0, packed.out + packed.err);
    assert.equal(parseJson(packed.out).command, 'session-export');
    assert.equal(basename(parseJson(packed.out).packagePath), 'alias-pack');
  });

  it('imports into a second outDir, skips a repeat, and refuses a divergent id', () => {
    const source = initRepo();
    const session = 'sess-merge';
    sessionPair(source, session, 'hq-host');
    const exported = exportSession(source, session);
    const back = cliResult(source, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(back.code, 1, back.out + back.err);
    const backBody = parseJson(back.out);
    assert.equal(backBody.copied, 0);
    assert.equal(backBody.written, false);
    assert.ok(backBody.conflicts >= 1);
    assert.match(backBody.reason, /different sha256/);

    const dest = initRepo();
    commitFile(dest, 'local.txt', 'local\n');
    wrapJson(dest, ['--session', 'local-only', '--agent', 'local', '--message', 'local']);
    const indexBefore = indexDoc(dest).receipts.length;
    const auditBefore = auditText(dest);
    const receiptNamesBefore = readdirSync(join(dest, '.agent-receipt', 'receipts')).sort();

    const dry = cliResult(dest, ['session', 'import', exported.packagePath, '--dry-run', '--json']);
    assert.equal(dry.code, 0, dry.out + dry.err);
    const dryBody = parseJson(dry.out);
    assert.equal(dryBody.command, 'session-import');
    assert.equal(dryBody.dryRun, true);
    assert.equal(dryBody.written, false);
    assert.equal(dryBody.copied, 2);
    assert.equal(dryBody.conflicts, 0);
    assert.deepEqual(readdirSync(join(dest, '.agent-receipt', 'receipts')).sort(), receiptNamesBefore);
    const humanDry = cliResult(dest, ['session', 'merge', exported.packagePath, '--dry-run']);
    assert.equal(humanDry.code, 0, humanDry.out + humanDry.err);
    assert.match(humanDry.out, /VERIFIED/);
    assert.match(humanDry.out, /plan:/);
    assert.match(humanDry.out, /dry-run: true/);

    const imported = cliResult(dest, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(imported.code, 0, imported.out + imported.err);
    const body = parseJson(imported.out);
    assert.equal(body.ok, true);
    assert.equal(body.version, '1.0.29');
    assert.equal(body.copied, 2);
    assert.equal(body.skipped, 0);
    assert.equal(body.conflicts, 0);
    assert.equal(body.written, true);
    assert.equal(body.session, session);
    assert.equal(indexDoc(dest).receipts.length, indexBefore);
    assert.equal(auditText(dest), auditBefore);
    for (const file of body.files) {
      assert.equal(file.action, 'copy');
      assert.equal(existsSync(file.to), true);
      assert.equal(indexDoc(dest).receipts.some((row) => row.path === relative(dest, file.to)), false);
    }
    const history = parseJson(cli(dest, ['history', '--json']));
    assert.equal(history.length, indexBefore);
    const tree = parseJson(cli(dest, ['session', session, '--json']));
    assert.equal(tree.ok, true);
    assert.equal(tree.command, 'session');
    assert.equal(tree.receipts.length, 2);
    assert.ok(tree.receipts.every((row) => row.verified === true));
    const parent = tree.receipts.find((row) => row.agent === 'parent');
    const child = tree.receipts.find((row) => row.agent === 'child');
    assert.equal(parent.parent, null);
    assert.equal(child.parent, parent.id);
    assert.equal(field(readFileSync(child.path, 'utf8'), 'Host'), '[REDACTED]');
    assert.equal(field(readFileSync(child.path, 'utf8'), 'Session'), session);

    const again = cliResult(dest, [
      'session', 'import', join(exported.packagePath, 'session-manifest.json'), '--json',
    ]);
    assert.equal(again.code, 0, again.out + again.err);
    const skip = parseJson(again.out);
    assert.equal(skip.copied, 0);
    assert.equal(skip.skipped, 2);
    assert.equal(skip.written, false);
    assert.equal(skip.conflicts, 0);

    const childBefore = readFileSync(child.path, 'utf8');
    const parentBefore = readFileSync(parent.path, 'utf8');
    writeFileSync(child.path, childBefore.replace('- **Agent**: child', '- **Agent**: child-edited'));
    const tampered = readFileSync(child.path, 'utf8');
    const conflict = cliResult(dest, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(conflict.code, 1, conflict.out + conflict.err);
    const conflictBody = parseJson(conflict.out);
    assert.equal(conflictBody.copied, 0);
    assert.equal(conflictBody.written, false);
    assert.ok(conflictBody.conflicts >= 1);
    assert.match(conflictBody.reason, /import refused/);
    assert.match(conflictBody.reason, /different sha256/);
    assert.equal(readFileSync(child.path, 'utf8'), tampered);
    assert.equal(readFileSync(parent.path, 'utf8'), parentBefore);
    const humanConflict = cliResult(dest, ['session', 'import', exported.packagePath]);
    assert.equal(humanConflict.code, 1);
    assert.match(humanConflict.out, /FAILED/);
    assert.match(humanConflict.out, /conflict:/);
    assert.match(humanConflict.out, /import: refused/);
  });

  it('fails closed on a tampered receipt, manifest, or signature', () => {
    const source = initRepo();
    sessionPair(source, 'sess-tamper');
    const exported = exportSession(source, 'sess-tamper');
    const dest = initRepo();
    const snapshot = () => {
      const dir = join(dest, '.agent-receipt', 'receipts');
      return existsSync(dir) ? readdirSync(dir).sort() : [];
    };
    const before = snapshot();

    const receiptClone = join(source, 'tamper-receipt.session');
    cpSync(exported.packagePath, receiptClone, { recursive: true });
    const receiptManifest = JSON.parse(readFileSync(join(receiptClone, 'session-manifest.json'), 'utf8'));
    const receiptPath = join(receiptClone, receiptManifest.receipts[0].path);
    writeFileSync(receiptPath, readFileSync(receiptPath, 'utf8').replace('parent', 'parent-tampered'));
    const badReceipt = cliResult(dest, ['session', 'import', receiptClone, '--json']);
    assert.equal(badReceipt.code, 2, badReceipt.out + badReceipt.err);
    assert.equal(parseJson(badReceipt.out).written, false);
    assert.deepEqual(snapshot(), before);

    const manifestClone = join(source, 'tamper-manifest.session');
    cpSync(exported.packagePath, manifestClone, { recursive: true });
    rmSync(join(manifestClone, 'session-manifest.sig.json'), { force: true });
    const manifest = JSON.parse(readFileSync(join(manifestClone, 'session-manifest.json'), 'utf8'));
    const hex = manifest.receipts[0].sha256;
    manifest.receipts[0].sha256 = (hex[0] === 'a' ? 'b' : 'a') + hex.slice(1);
    writeFileSync(join(manifestClone, 'session-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    const badManifest = cliResult(dest, ['session', 'import', manifestClone, '--json']);
    assert.equal(badManifest.code, 2, badManifest.out + badManifest.err);
    assert.match(parseJson(badManifest.out).reason, /sha256|hash/);
    assert.deepEqual(snapshot(), before);

    const sigClone = join(source, 'tamper-sig.session');
    cpSync(exported.packagePath, sigClone, { recursive: true });
    const sigPath = join(sigClone, 'session-manifest.sig.json');
    if (!existsSync(sigPath)) {
      writeFileSync(sigPath, '{"alg":"ed25519","version":1,"sha256":"aa","fingerprint":"bb","signature":"cc","publicKey":"dd"}\n');
    } else {
      const sig = JSON.parse(readFileSync(sigPath, 'utf8'));
      sig.signature = `${sig.signature.slice(0, -1)}${sig.signature.endsWith('A') ? 'B' : 'A'}`;
      writeFileSync(sigPath, `${JSON.stringify(sig, null, 2)}\n`);
    }
    const badSig = cliResult(dest, ['session', 'import', sigClone, '--json']);
    assert.equal(badSig.code, 2, badSig.out + badSig.err);
    assert.match(parseJson(badSig.out).reason, /signature/i);
    assert.deepEqual(snapshot(), before);

    const kindClone = join(source, 'tamper-kind.session');
    cpSync(exported.packagePath, kindClone, { recursive: true });
    const kindDoc = JSON.parse(readFileSync(join(kindClone, 'session-manifest.json'), 'utf8'));
    kindDoc.kind = 'agent-receipt-share';
    writeFileSync(join(kindClone, 'session-manifest.json'), `${JSON.stringify(kindDoc, null, 2)}\n`);
    const badKind = cliResult(dest, ['session', 'import', kindClone, '--json']);
    assert.equal(badKind.code, 1, badKind.out + badKind.err);
    assert.match(parseJson(badKind.out).reason, /kind/);
    assert.deepEqual(snapshot(), before);
  });

  it('enforces --require-sig, including an active allowlist and trust add --self', () => {
    const unsigned = initRepo();
    sessionPair(unsigned, 'sess-unsigned', 'hq-host');
    const unsignedPkg = exportSession(unsigned, 'sess-unsigned');
    const unsignedDest = initRepo();
    const missing = cliResult(unsignedDest, [
      'session', 'import', unsignedPkg.packagePath, '--require-sig', '--json',
    ]);
    assert.equal(missing.code, 2, missing.out + missing.err);
    assert.match(parseJson(missing.out).reason, /signature/);
    assert.equal(parseJson(missing.out).written, false);

    const source = initRepo();
    const keys = parseJson(cli(source, ['keygen', '--json']));
    sessionPair(source, 'sess-required', 'hq-host');
    const signedPkg = exportSession(source, 'sess-required');

    const open = initRepo();
    const accepted = cliResult(open, [
      'session', 'import', signedPkg.packagePath, '--require-sig', '--json',
    ]);
    assert.equal(accepted.code, 0, accepted.out + accepted.err);
    const acceptedBody = parseJson(accepted.out);
    assert.equal(acceptedBody.written, true);
    assert.equal(acceptedBody.copied, 2);
    assert.equal(acceptedBody.manifestSig.ok, true);
    const listed = parseJson(cli(open, ['session', 'sess-required', '--json']));
    assert.equal(listed.receipts.length, 2);
    assert.ok(listed.receipts.every((row) => row.verified === true));

    const closed = initRepo();
    cli(closed, ['trust', 'add', 'ab'.repeat(32)]);
    const rejected = cliResult(closed, [
      'session', 'import', signedPkg.packagePath, '--require-sig', '--json',
    ]);
    assert.equal(rejected.code, 2, rejected.out + rejected.err);
    assert.match(parseJson(rejected.out).reason, /trust/);
    assert.equal(existsSync(join(closed, '.agent-receipt', 'receipts')), false);

    const self = initRepo();
    mkdirSync(join(self, '.agent-receipt'), { recursive: true });
    cpSync(join(source, '.agent-receipt', 'keys'), join(self, '.agent-receipt', 'keys'), {
      recursive: true,
    });
    const added = parseJson(cli(self, ['trust', 'add', '--self', '--json']));
    assert.equal(added.fingerprint, keys.fingerprint);
    const trusted = cliResult(self, [
      'session', 'import', signedPkg.packagePath, '--require-sig', '--json',
    ]);
    assert.equal(trusted.code, 0, trusted.out + trusted.err);
    assert.equal(parseJson(trusted.out).copied, 2);
    const inside = join(self, '.agent-receipt', 'receipts', 'nested.session');
    mkdirSync(join(inside, 'receipts'), { recursive: true });
    writeFileSync(join(inside, 'receipts', 'receipt-decoy.md'), readFileSync(listed.receipts[0].path));
    const after = parseJson(cli(self, ['session', 'sess-required', '--json']));
    assert.equal(after.receipts.length, 2);
    assert.ok(after.receipts.every((row) => !String(row.path).includes('.session')));
  });

  function nestedLink(dir, session, sign) {
    writeFileSync(join(dir, 'secret.txt'), `${NESTED_AWS}\n`);
    const signArgs = sign ? ['--sign'] : [];
    const wrapped = cliResult(dir, [
      'wrap',
      '--link',
      '--session',
      session,
      '--host',
      NESTED_HOST,
      '--agent',
      'parent',
      '--message',
      'parent',
      ...signArgs,
      '--',
      process.execPath,
      bin,
      'wrap',
      '--cwd',
      dir,
      '--full',
      '--agent',
      'child',
      '--message',
      'child',
      ...signArgs,
    ], GIT_CLEAN);
    assert.equal(wrapped.code, 0, wrapped.out + wrapped.err);
    const bodies = receiptBodies(dir);
    const child = bodies.find((md) => field(md, 'Agent') === 'child');
    const parent = bodies.find((md) => field(md, 'Agent') === 'parent');
    assert.ok(child, 'child receipt');
    assert.ok(parent, 'parent receipt');
    assert.match(child, new RegExp(NESTED_HOST));
    assert.match(child, new RegExp(NESTED_AWS));
    assert.match(parent, new RegExp(NESTED_AWS));
    return { child, parent };
  }

  it('redacts nested receipt bodies and planted secrets on default export', () => {
    const unsigned = initRepo();
    nestedLink(unsigned, 'sess-nested-redact', false);
    const exported = exportSession(unsigned, 'sess-nested-redact');
    assert.equal(countHits(exported.packagePath, NESTED_HOST), 0);
    assert.equal(countHits(exported.packagePath, NESTED_AWS), 0);
    const manifest = JSON.parse(readFileSync(exported.manifestPath, 'utf8'));
    assert.equal(manifest.includeHost, false);
    let omitted = 0;
    for (const entry of manifest.receipts) {
      const text = readFileSync(join(exported.packagePath, entry.path), 'utf8');
      if (text.includes(NESTED_OMIT)) omitted += 1;
      assert.equal(entry.originalFingerprint, null);
      assert.equal(entry.resignedBy, null);
      assert.equal(entry.fingerprint, null);
      const checked = parseJson(cli(unsigned, ['verify', join(exported.packagePath, entry.path), '--json']));
      assert.equal(checked.ok, true, checked.reason || '');
    }
    assert.ok(omitted >= 1);
    const dest = initRepo();
    const imported = cliResult(dest, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(imported.code, 0, imported.out + imported.err);
    const body = parseJson(imported.out);
    assert.equal(body.copied, manifest.receipts.length);
    for (const file of body.files) {
      assert.equal(file.action, 'copy');
      assert.equal(file.originalFingerprint, null);
      assert.equal(file.resignedBy, null);
      const checked = parseJson(cli(dest, ['verify', file.to, '--json']));
      assert.equal(checked.ok, true, checked.reason || '');
      assert.equal(readFileSync(file.to, 'utf8').includes(NESTED_HOST), false);
      assert.equal(readFileSync(file.to, 'utf8').includes(NESTED_AWS), false);
    }

    const signed = initRepo();
    const keys = parseJson(cli(signed, ['keygen', '--json']));
    nestedLink(signed, 'sess-nested-signed', true);
    const signedPkg = exportSession(signed, 'sess-nested-signed');
    assert.equal(countHits(signedPkg.packagePath, NESTED_HOST), 0);
    assert.equal(countHits(signedPkg.packagePath, NESTED_AWS), 0);
    const signedManifest = JSON.parse(readFileSync(signedPkg.manifestPath, 'utf8'));
    const signedCheck = verifySignature(
      JSON.parse(readFileSync(signedPkg.manifestSigPath, 'utf8')),
      fileSha256(signedPkg.manifestPath),
    );
    assert.equal(signedCheck.ok, true, signedCheck.reason || '');
    for (const entry of signedManifest.receipts) {
      assert.equal(entry.fingerprint, keys.fingerprint);
      assert.equal(entry.resignedBy, null);
      const checked = parseJson(cli(signed, ['verify', join(signedPkg.packagePath, entry.path), '--require-sig', '--json']));
      assert.equal(checked.ok, true, checked.reason || '');
    }
    const signedDest = initRepo();
    const signedImport = cliResult(signedDest, [
      'session', 'import', signedPkg.packagePath, '--require-sig', '--json',
    ]);
    assert.equal(signedImport.code, 0, signedImport.out + signedImport.err);
    assert.equal(parseJson(signedImport.out).copied, signedManifest.receipts.length);
    for (const file of parseJson(signedImport.out).files) {
      const checked = parseJson(cli(signedDest, ['verify', file.to, '--require-sig', '--json']));
      assert.equal(checked.ok, true, checked.reason || '');
      assert.equal(checked.signature.fingerprint, keys.fingerprint);
    }
  });

  it('refuses to re-sign a foreign sidecar unless --resign records both fingerprints', () => {
    const session = 'sess-laundry';
    const hostA = initRepo();
    const keysA = parseJson(cli(hostA, ['keygen', '--json']));
    const pair = sessionPair(hostA, session, NESTED_HOST);
    cli(hostA, ['sign', pair.parent.path]);
    cli(hostA, ['sign', pair.child.path]);
    const parentSig = readFileSync(pair.parent.path.replace(/\.md$/, '.sig.json'));
    const packed = exportSession(hostA, session, ['--include-host']);
    const packedManifest = JSON.parse(readFileSync(packed.manifestPath, 'utf8'));
    for (const entry of packedManifest.receipts) {
      assert.equal(entry.fingerprint, keysA.fingerprint);
      assert.equal(entry.originalFingerprint, keysA.fingerprint);
      assert.equal(entry.resignedBy, null);
      assert.equal(entry.host, NESTED_HOST);
    }

    const hostB = initRepo();
    const keysB = parseJson(cli(hostB, ['keygen', '--json']));
    assert.notEqual(keysA.fingerprint, keysB.fingerprint);
    const imported = cliResult(hostB, ['session', 'import', packed.packagePath, '--json']);
    assert.equal(imported.code, 0, imported.out + imported.err);
    const importedBody = parseJson(imported.out);
    assert.equal(importedBody.copied, 2);
    const localSigs = importedBody.files.map((file) => ({
      to: file.to,
      bytes: readFileSync(file.to.replace(/\.md$/, '.sig.json')),
    }));
    for (const file of importedBody.files) {
      assert.equal(file.fingerprint, keysA.fingerprint);
      assert.equal(file.originalFingerprint, keysA.fingerprint);
      assert.equal(file.resignedBy, null);
    }
    cli(hostB, ['trust', 'add', '--self']);
    for (const file of importedBody.files) {
      const checked = cliResult(hostB, ['verify', file.to, '--require-sig', '--json']);
      assert.equal(checked.code, 2, checked.out + checked.err);
      const gate = parseJson(checked.out);
      assert.equal(gate.signature.fingerprint, keysA.fingerprint);
      assert.equal(gate.signature.trusted, false);
      assert.notEqual(gate.signature.fingerprint, keysB.fingerprint);
    }

    const refused = cliResult(hostB, ['session', 'export', session, '--json']);
    assert.equal(refused.code, 2, refused.out + refused.err);
    const refusedBody = parseJson(refused.out);
    assert.equal(refusedBody.written, false);
    assert.match(refusedBody.reason, /different key/);
    assert.match(refusedBody.reason, /--resign/);
    assert.match(refusedBody.reason, /Nothing was written/);
    assert.equal(existsSync(join(hostB, '.agent-receipt', `${session}.session`)), false);
    for (const sig of localSigs) {
      assert.equal(readFileSync(sig.to.replace(/\.md$/, '.sig.json')).equals(sig.bytes), true);
    }
    assert.equal(readFileSync(pair.parent.path.replace(/\.md$/, '.sig.json')).equals(parentSig), true);

    const resigned = cliResult(hostB, ['session', 'export', session, '--resign', '--out', 'resigned-pack', '--json']);
    assert.equal(resigned.code, 0, resigned.out + resigned.err);
    assert.match(resigned.err, /warning: --resign/);
    assert.match(resigned.err, new RegExp(keysA.fingerprint));
    assert.match(resigned.err, new RegExp(keysB.fingerprint));
    const resignedBody = parseJson(resigned.out);
    const resignedManifestText = readFileSync(resignedBody.manifestPath, 'utf8');
    assert.match(resignedManifestText, /originalFingerprint/);
    assert.match(resignedManifestText, /resignedBy/);
    const resignedManifest = JSON.parse(resignedManifestText);
    const resignedSig = JSON.parse(readFileSync(resignedBody.manifestSigPath, 'utf8'));
    const covered = verifySignature(resignedSig, fileSha256(resignedBody.manifestPath));
    assert.equal(covered.ok, true, covered.reason || '');
    for (const entry of resignedManifest.receipts) {
      assert.equal(entry.originalFingerprint, keysA.fingerprint);
      assert.equal(entry.resignedBy, keysB.fingerprint);
      assert.equal(entry.fingerprint, keysB.fingerprint);
      const sidecar = JSON.parse(readFileSync(
        join(resignedBody.packagePath, entry.path.replace(/\.md$/, '.sig.json')),
        'utf8',
      ));
      assert.equal(sidecar.fingerprint, keysB.fingerprint);
      assert.equal(verifySignature(sidecar, entry.sha256).ok, true);
    }
    for (const sig of localSigs) {
      assert.equal(readFileSync(sig.to.replace(/\.md$/, '.sig.json')).equals(sig.bytes), true);
    }
    const peer = initRepo();
    const shown = cliResult(peer, ['session', 'import', resignedBody.packagePath, '--json']);
    assert.equal(shown.code, 0, shown.out + shown.err);
    for (const file of parseJson(shown.out).files) {
      assert.equal(file.originalFingerprint, keysA.fingerprint);
      assert.equal(file.fingerprint, keysB.fingerprint);
      assert.equal(file.resignedBy, keysB.fingerprint);
    }

    const redactedA = initRepo();
    const redactedKeys = parseJson(cli(redactedA, ['keygen', '--json']));
    const redactedPair = sessionPair(redactedA, 'sess-stable', 'hq-host');
    cli(redactedA, ['sign', redactedPair.parent.path]);
    cli(redactedA, ['sign', redactedPair.child.path]);
    const redactedPkg = exportSession(redactedA, 'sess-stable');
    const redactedManifest = JSON.parse(readFileSync(redactedPkg.manifestPath, 'utf8'));
    for (const entry of redactedManifest.receipts) {
      assert.equal(entry.fingerprint, redactedKeys.fingerprint);
      assert.equal(entry.resignedBy, null);
    }
    const redactedB = initRepo();
    const redactedBKeys = parseJson(cli(redactedB, ['keygen', '--json']));
    const redactedImport = cliResult(redactedB, ['session', 'import', redactedPkg.packagePath, '--json']);
    assert.equal(redactedImport.code, 0, redactedImport.out + redactedImport.err);
    const again = cliResult(redactedB, ['session', 'export', 'sess-stable', '--out', 'b-again', '--json']);
    if (again.code === 0) {
      const againManifest = JSON.parse(readFileSync(parseJson(again.out).manifestPath, 'utf8'));
      for (const entry of againManifest.receipts) {
        assert.equal(entry.fingerprint, redactedKeys.fingerprint);
        assert.equal(entry.originalFingerprint, redactedKeys.fingerprint);
        assert.equal(entry.resignedBy, null);
        assert.notEqual(entry.fingerprint, redactedBKeys.fingerprint);
      }
    } else {
      assert.equal(again.code, 2, again.out + again.err);
      assert.match(parseJson(again.out).reason, /different key/);
      assert.equal(existsSync(join(redactedB, 'b-again')), false);
    }
  });

  it('refuses symlink, stray, unreadable, and case-only import destinations', () => {
    const source = initRepo();
    sessionPair(source, 'sess-plant', 'hq-host');
    const exported = exportSession(source, 'sess-plant');
    const manifest = JSON.parse(readFileSync(exported.manifestPath, 'utf8'));
    const entry = manifest.receipts[0];
    const base = basename(entry.path);

    const signedSource = initRepo();
    cli(signedSource, ['keygen']);
    const signedPair = sessionPair(signedSource, 'sess-plant-sig', 'hq-host');
    cli(signedSource, ['sign', signedPair.parent.path]);
    cli(signedSource, ['sign', signedPair.child.path]);
    const signedPkg = exportSession(signedSource, 'sess-plant-sig');
    const signedManifest = JSON.parse(readFileSync(signedPkg.manifestPath, 'utf8'));
    const signedBase = basename(signedManifest.receipts[0].path);
    const sigBase = signedBase.replace(/\.md$/, '.sig.json');

    function plantDest() {
      const dest = initRepo();
      const out = join(dest, '.agent-receipt', 'receipts');
      mkdirSync(out, { recursive: true });
      return { dest, out };
    }

    const evil = mkdtempSync(join(tmpdir(), 'agent-receipt-evil-'));
    dirs.push(evil);
    const danglingTarget = join(evil, 'pwn.md');
    const { dest: danglingDest, out: danglingOut } = plantDest();
    symlinkSync(danglingTarget, join(danglingOut, base));
    const danglingBefore = readlinkSync(join(danglingOut, base));
    const dangling = cliResult(danglingDest, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(dangling.code, 2, dangling.out + dangling.err);
    assert.match(parseJson(dangling.out).reason, /symlink/);
    assert.equal(parseJson(dangling.out).written, false);
    assert.equal(existsSync(danglingTarget), false);
    assert.equal(lstatSync(join(danglingOut, base)).isSymbolicLink(), true);
    assert.equal(readlinkSync(join(danglingOut, base)), danglingBefore);
    assert.equal(readdirSync(danglingOut).some((name) => name.startsWith('.import-staging-')), false);

    const external = join(evil, 'external.txt');
    writeFileSync(external, 'external-bytes\n');
    const externalBefore = readFileSync(external);
    const { dest: linkDest, out: linkOut } = plantDest();
    symlinkSync(external, join(linkOut, sigBase));
    const linked = cliResult(linkDest, ['session', 'import', signedPkg.packagePath, '--json']);
    assert.equal(linked.code, 2, linked.out + linked.err);
    assert.match(parseJson(linked.out).reason, /symlink/);
    assert.equal(parseJson(linked.out).written, false);
    assert.equal(readFileSync(external).equals(externalBefore), true);
    assert.equal(lstatSync(join(linkOut, sigBase)).isSymbolicLink(), true);
    assert.equal(existsSync(join(linkOut, signedBase)), false);

    const { dest: strayDest, out: strayOut } = plantDest();
    const strayPath = join(strayOut, sigBase);
    writeFileSync(strayPath, '{"stray":true}\n');
    const strayBefore = readFileSync(strayPath);
    const stray = cliResult(strayDest, ['session', 'import', signedPkg.packagePath, '--json']);
    assert.equal(stray.code, 1, stray.out + stray.err);
    assert.match(parseJson(stray.out).reason, /sidecar|conflict|already exists/);
    assert.equal(parseJson(stray.out).written, false);
    assert.equal(readFileSync(strayPath).equals(strayBefore), true);
    assert.equal(existsSync(join(strayOut, signedBase)), false);

    const { dest: modeDest, out: modeOut } = plantDest();
    const modePath = join(modeOut, base);
    const modeText = 'mode-0200-keep\n';
    writeFileSync(modePath, modeText);
    chmodSync(modePath, 0o200);
    const mode = cliResult(modeDest, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(mode.code, 1, mode.out + mode.err);
    assert.match(parseJson(mode.out).reason, /unreadable/);
    assert.equal(parseJson(mode.out).written, false);
    chmodSync(modePath, 0o644);
    assert.equal(readFileSync(modePath, 'utf8'), modeText);
    assert.equal(readdirSync(modeOut).filter((name) => name.endsWith('.md')).length, 1);

    const { dest: caseDest, out: caseOut } = plantDest();
    const caseName = `${base.slice(0, -3)}.MD`;
    assert.notEqual(caseName, base);
    const casePath = join(caseOut, caseName);
    writeFileSync(casePath, 'case-clash\n');
    const caseBefore = readFileSync(casePath);
    const clash = cliResult(caseDest, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(clash.code, 1, clash.out + clash.err);
    assert.match(parseJson(clash.out).reason, /basename|case-insensitive|different sha256/);
    assert.equal(parseJson(clash.out).written, false);
    assert.equal(readFileSync(casePath).equals(caseBefore), true);
    assert.equal(existsSync(join(caseOut, base)), false);

    const dup = join(source, 'case-dup.session');
    cpSync(exported.packagePath, dup, { recursive: true });
    const dupManifest = JSON.parse(readFileSync(join(dup, 'session-manifest.json'), 'utf8'));
    const first = dupManifest.receipts[0];
    const second = dupManifest.receipts[1];
    const firstBase = basename(first.path);
    const flippedBase = `R${firstBase.slice(1)}`;
    assert.notEqual(flippedBase, firstBase);
    assert.equal(flippedBase.toLowerCase(), firstBase.toLowerCase());
    const flipped = `receipts/${flippedBase}`;
    const flippedAbs = join(dup, flipped);
    cpSync(join(dup, second.path), flippedAbs);
    second.path = flipped;
    second.bytes = fileSha256(flippedAbs);
    writeFileSync(join(dup, 'session-manifest.json'), `${JSON.stringify(dupManifest, null, 2)}\n`);
    const { dest: dupDest, out: dupOut } = plantDest();
    const dupNames = readdirSync(dupOut).sort();
    const duplicated = cliResult(dupDest, ['session', 'import', dup, '--json']);
    assert.equal(duplicated.code, 1, duplicated.out + duplicated.err);
    assert.match(parseJson(duplicated.out).reason, /case-insensitive duplicate/);
    assert.equal(parseJson(duplicated.out).written, false);
    assert.deepEqual(readdirSync(dupOut).sort(), dupNames);

    const real = mkdtempSync(join(tmpdir(), 'agent-receipt-real-'));
    dirs.push(real);
    writeFileSync(join(real, 'already.txt'), 'safe\n');
    const linkRoot = initRepo();
    const outLink = join(linkRoot, '.agent-receipt', 'receipts');
    rmSync(outLink, { recursive: true, force: true });
    symlinkSync(real, outLink);
    const through = cliResult(linkRoot, ['session', 'import', exported.packagePath, '--json']);
    assert.equal(through.code, 2, through.out + through.err);
    assert.match(parseJson(through.out).reason, /symlink/);
    assert.equal(readFileSync(join(real, 'already.txt'), 'utf8'), 'safe\n');
    assert.deepEqual(readdirSync(real).sort(), ['already.txt']);
  });

  it('fails closed on oversized session files and a mid-copy failure', () => {
    const dir = initRepo();
    const { parent } = sessionPair(dir, 'sess-huge', 'hq-host');
    const fd = openSync(parent.path, 'w');
    try {
      ftruncateSync(fd, 700 * 1024 * 1024);
    } finally {
      closeSync(fd);
    }
    const huge = cliResult(dir, ['session', 'export', 'sess-huge', '--json']);
    assert.equal(huge.code, 2, huge.out + huge.err);
    assert.match(huge.out, /over the/);
    assert.doesNotMatch(huge.out + huge.err, /Cannot create a string/);
    assert.equal(parseJson(huge.out).written, false);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'sess-huge.session')), false);

    const small = initRepo();
    sessionPair(small, 'sess-cap', 'hq-host');
    const capped = cliResult(small, [
      'session', 'export', 'sess-cap', '--max-receipt-bytes', '64', '--json',
    ]);
    assert.equal(capped.code, 2, capped.out + capped.err);
    assert.match(capped.out, /over the 64 byte limit/);
    assert.equal(parseJson(capped.out).written, false);

    const side = initRepo();
    const sidePair = sessionPair(side, 'sess-sidecap');
    writeFileSync(sidePair.parent.path.replace(/\.md$/, '.sig.json'), 'x'.repeat(400));
    const sideCap = cliResult(side, [
      'session', 'export', 'sess-sidecap', '--max-sidecar-bytes', '10', '--json',
    ]);
    assert.equal(sideCap.code, 2, sideCap.out + sideCap.err);
    assert.match(sideCap.out, /over the 10 byte limit/);
    assert.doesNotMatch(sideCap.out + sideCap.err, /Cannot create a string/);
    assert.equal(existsSync(join(side, '.agent-receipt', 'sess-sidecap.session')), false);

    const source = initRepo();
    sessionPair(source, 'sess-manifest-cap');
    const pkg = exportSession(source, 'sess-manifest-cap');
    const dest = initRepo();
    const manifestCap = cliResult(dest, [
      'session', 'import', pkg.packagePath, '--max-manifest-bytes', '32', '--json',
    ]);
    assert.equal(manifestCap.code, 2, manifestCap.out + manifestCap.err);
    assert.match(manifestCap.out, /over the 32 byte limit/);
    assert.equal(parseJson(manifestCap.out).written, false);
    assert.equal(existsSync(join(dest, '.agent-receipt', 'receipts')), false);

    const stageDest = initRepo();
    const out = join(stageDest, '.agent-receipt', 'receipts');
    const before = existsSync(out) ? readdirSync(out).sort() : [];
    const failed = cmdSessionImport(stageDest, pkg.packagePath, { failAfterStageCopies: 1 });
    assert.equal(failed.exitCode, 2);
    assert.match(failed.reason, /simulated mid-copy failure/);
    assert.equal(failed.written, false);
    const after = existsSync(out) ? readdirSync(out) : [];
    assert.deepEqual(after.filter((name) => !name.startsWith('.import-staging-')).sort(), before);
    assert.equal(after.some((name) => name.startsWith('.import-staging-')), false);
  });

  it('prune deletes the sidecar of each receipt it removes', () => {
    const dir = initRepo();
    cli(dir, ['keygen']);
    commitFile(dir, 'one.txt', 'one\n');
    wrapJson(dir, ['--sign', '--agent', 'a', '--message', 'one']);
    commitFile(dir, 'two.txt', 'two\n');
    wrapJson(dir, ['--sign', '--agent', 'b', '--message', 'two']);
    const out = join(dir, '.agent-receipt', 'receipts');
    const mds = readdirSync(out).filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'));
    assert.equal(mds.length, 2);
    for (const name of mds) {
      assert.equal(existsSync(join(out, name.replace(/\.md$/, '.sig.json'))), true);
    }
    const stray = join(out, 'keep-me.txt');
    writeFileSync(stray, 'keep\n');
    const pruned = cliResult(dir, ['prune', '--max-count', '1', '--force', '--json']);
    assert.equal(pruned.code, 0, pruned.out + pruned.err);
    const body = parseJson(pruned.out);
    assert.equal(body.deleted.length, 1);
    const gone = basename(body.deleted[0].path);
    assert.equal(existsSync(join(out, gone)), false);
    assert.equal(existsSync(join(out, gone.replace(/\.md$/, '.sig.json'))), false);
    const kept = mds.filter((name) => name !== gone);
    assert.equal(kept.length, 1);
    assert.equal(existsSync(join(out, kept[0])), true);
    assert.equal(existsSync(join(out, kept[0].replace(/\.md$/, '.sig.json'))), true);
    assert.equal(readFileSync(stray, 'utf8'), 'keep\n');
  });
});
