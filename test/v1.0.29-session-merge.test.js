import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifySignature } from '../dist/lib/sign.js';
import { listReceiptFiles } from '../dist/lib/retention.js';
import { isInsideSessionPackage, isSessionPackageDirName } from '../dist/lib/receipt.js';

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
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /## Cross-host session merge/);
    assert.match(readme, /session export/);
    assert.match(readme, /session import/);
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
});
