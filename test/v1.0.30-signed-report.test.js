import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const LINK_ENV = [
  'AGENT_RECEIPT_SESSION',
  'AGENT_RECEIPT_PARENT',
  'AGENT_RECEIPT_AGENT',
  'AGENT_RECEIPT_HOST',
];
const AWS = 'AKIAIOSFODNN7EXAMPLE';
const GHP = `ghp_${'abcdefghijklmnopqrstuvwxyz0123456789'}`;
const HOST = 'planted-host.example';
const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'";

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

function receiptFiles(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  return readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .map((name) => join(out, name));
}

function latestReceipt(dir) {
  const files = receiptFiles(dir);
  assert.ok(files.length > 0, 'expected a receipt');
  files.sort((a, b) => lstatSync(b).mtimeMs - lstatSync(a).mtimeMs);
  return files[0];
}

function payloadOf(html) {
  const match = html.match(
    /<script type="application\/json" id="agent-receipt-report">([\s\S]*?)<\/script>/,
  );
  assert.ok(match, 'embedded payload missing');
  return JSON.parse(match[1]);
}

function visibleHtml(html) {
  return html
    .replace(/<script type="application\/json" id="agent-receipt-report">[\s\S]*?<\/script>/g, '')
    .replace(/<script type="application\/json" id="agent-receipt-report-sig">[\s\S]*?<\/script>/g, '');
}

describe('v1.0.30 signed one-page report', () => {
  const dirs = [];
  after(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  function initRepo(slug = 'agent-receipt-1030-') {
    const dir = mkdtempSync(join(tmpdir(), slug));
    dirs.push(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    writeFileSync(join(dir, 'README.md'), '# report\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    cli(dir, ['init']);
    return dir;
  }

  function commitFile(dir, name, content, message = name) {
    writeFileSync(join(dir, name), content);
    git(dir, ['add', name]);
    git(dir, ['commit', '-m', message]);
  }

  function enableFullDiffs(dir) {
    writeFileSync(join(dir, '.agent-receipt.yml'), 'fullDiffs: true\n', { flag: 'a' });
  }

  it('documents 1.0.30, the report payload, and no new runtime dependencies', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.0.30');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.30');
    assert.equal(lock.packages[''].version, '1.0.30');
    assert.equal(lock.packages[''].dependencies, undefined);
    assert.match(readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8'), /1\.0\.30/);
    const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    assert.match(changelog, /## \[1\.0\.30\]/);
    assert.match(changelog, /agent-receipt report/);
    assert.match(changelog, /canonical JSON payload/);
    assert.match(changelog, /native adapters/);
    assert.match(changelog, /in-toto\/SLSA/);
    assert.match(changelog, /Sigstore keyless/);
    assert.match(changelog, /published GitHub Action/);
    assert.match(changelog, /policy packs/);
    assert.match(changelog, /local web viewer/);
    assert.match(changelog, /full PKI\/CA/);
    assert.match(changelog, /npm Trusted Publishing/);
    assert.match(changelog, /Share HTML had no CSP meta tag in 1\.0\.28/);
    const schema = JSON.parse(readFileSync(join(root, 'docs', 'report-payload.schema.json'), 'utf8'));
    assert.equal(schema.properties.kind.const, 'agent-receipt-report');
    assert.equal(schema.properties.version.const, 1);
    assert.equal(schema.additionalProperties, false);
    assert.ok(schema.properties.receipts.items.required.includes('signedBy'));
    const sessionSchema = JSON.parse(readFileSync(join(root, 'docs', 'session-package.schema.json'), 'utf8'));
    assert.ok(sessionSchema.properties.receipts.items.properties.signedBy);
    assert.equal(sessionSchema.properties.receipts.items.required.includes('signedBy'), false);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /Signed one-page|signed one-page HTML report/);
    assert.match(readme, /symlinked `\.agent-receipt` parent is followed/);
    assert.match(readme, /originalFingerprint` is the manifest signer's claim/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /### Signed one-page report/);
    const mirror = readFileSync(join(root, 'docs', 'github-actions-ci.yml'), 'utf8');
    assert.match(mirror, /1\.0\.30/);
    assert.match(mirror, /# v1\.0\.29:/);
    assert.match(mirror, /report verify/);
    const proveSrc = readFileSync(join(root, 'src', 'lib', 'prove-html.ts'), 'utf8');
    assert.doesNotMatch(proveSrc, /script-src/);
    for (const name of readdirSync(join(root, '.github', 'workflows'))) {
      const live = readFileSync(join(root, '.github', 'workflows', name), 'utf8');
      assert.doesNotMatch(live, /v1\.0\.30/);
      assert.doesNotMatch(live, /report verify/);
    }
    const help = cli(root, ['help', 'report']);
    assert.match(help, /report verify/);
    assert.match(help, /canonical JSON payload/);
    assert.match(help, /does not cover CSS/);
    assert.match(help, /UNREDACTED/);
  });

  it('writes an unsigned single-receipt report and verifies it', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'hello\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'unsigned report', '--session', 's-unsigned']);
    assert.equal(cliResult(dir, ['report']).code, 1);
    assert.equal(cliResult(dir, ['report', 'last', '--session', 's-unsigned']).code, 1);
    const made = cliResult(dir, ['report', 'last', '--json']);
    assert.equal(made.code, 0, made.err);
    const body = parseJson(made.out);
    assert.equal(body.command, 'report');
    assert.equal(body.version, '1.0.30');
    assert.equal(body.exitCode, 0);
    assert.equal(body.verdict, 'UNSIGNED');
    assert.equal(body.signed, false);
    assert.equal(body.sigPath, null);
    assert.equal(body.redacted, true);
    assert.equal(body.exposure, 'redacted');
    assert.equal(body.receiptCount, 1);
    assert.equal(dirname(body.htmlPath), join(dir, '.agent-receipt'));
    assert.match(basename(body.htmlPath), /\.report\.html$/);
    assert.equal(existsSync(`${body.htmlPath}.sig.json`), false);
    const html = readFileSync(body.htmlPath, 'utf8');
    assert.match(html, /UNSIGNED/);
    assert.match(html, new RegExp(CSP.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.doesNotMatch(html, /UNREDACTED/);
    assert.doesNotMatch(html, /\ssrc\s*=\s*["']https?:/i);
    assert.doesNotMatch(html, /\shref\s*=\s*["']https?:/i);
    assert.doesNotMatch(html, /<h2>Session tree<\/h2>/);
    const payload = payloadOf(html);
    assert.equal(payload.kind, 'agent-receipt-report');
    assert.equal(payload.version, 1);
    assert.equal(payload.cliVersion, '1.0.30');
    assert.equal(payload.subject, 'receipt');
    assert.equal(payload.session, 's-unsigned');
    assert.equal(payload.manifestSha256, null);
    assert.equal(payload.exposure, 'redacted');
    assert.equal(payload.verdict, 'UNSIGNED');
    assert.equal(payload.receipts.length, 1);
    assert.equal(payload.receipts[0].signature, 'unsigned');
    assert.match(payload.verifyCommands[0], /^agent-receipt report verify \S+\.report\.html$/);
    const checked = cliResult(dir, ['report', 'verify', body.htmlPath, '--json']);
    assert.equal(checked.code, 0, checked.err);
    const verified = parseJson(checked.out);
    assert.equal(verified.command, 'report-verify');
    assert.equal(verified.exitCode, 0);
    assert.equal(verified.signed, false);
    assert.equal(verified.verdict, 'UNSIGNED');
    assert.ok(verified.checked >= 1);
    const required = cliResult(dir, ['report', 'verify', body.htmlPath, '--require-sig', '--json']);
    assert.equal(required.code, 2);
    assert.equal(parseJson(required.out).exitCode, 2);
    const last = parseJson(cli(dir, ['last', '--json']));
    assert.match(last.path, /\.md$/);
    const outDir = join(dir, 'out-reports');
    mkdirSync(outDir);
    const placed = parseJson(cli(dir, ['report', 'last', '--out', `${outDir}/`, '--json']));
    assert.equal(dirname(placed.htmlPath), outDir);
    assert.match(basename(placed.htmlPath), /\.report\.html$/);
  });

  it('signs the payload, rejects tampering, and enforces --require-sig', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'signed\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'signed report']);
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const made = parseJson(cli(dir, ['report', 'last', '--json']));
    assert.equal(made.exitCode, 0);
    assert.equal(made.verdict, 'VERIFIED');
    assert.equal(made.signed, true);
    assert.equal(made.fingerprint, keys.fingerprint);
    assert.ok(existsSync(made.sigPath));
    assert.match(basename(made.sigPath), /\.report\.html\.sig\.json$/);
    const html = readFileSync(made.htmlPath, 'utf8');
    assert.match(html, /id="agent-receipt-report-sig"/);
    assert.match(html, /VERIFIED/);
    const payload = payloadOf(html);
    assert.equal(payload.receipts[0].signature, 'unsigned');
    assert.equal(payload.verdict, 'VERIFIED');
    const ok = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(ok.code, 0, ok.err);
    assert.equal(parseJson(ok.out).fingerprint, keys.fingerprint);

    const cssCopy = join(dir, 'css.report.html');
    writeFileSync(cssCopy, html.replace('#1a7f37', '#1a7f38'));
    assert.equal(cliResult(dir, ['report', 'verify', cssCopy, '--json']).code, 0);

    const visibleCopy = join(dir, 'visible.report.html');
    writeFileSync(
      visibleCopy,
      html.replace('<span data-covered="verdict">VERIFIED</span>', '<span data-covered="verdict">FAILED</span>'),
    );
    assert.equal(cliResult(dir, ['report', 'verify', visibleCopy, '--json']).code, 2);

    const payloadCopy = join(dir, 'payload.report.html');
    const sha = payload.receipts[0].sha256;
    const flippedSha = (sha[0] === 'a' ? 'b' : 'a') + sha.slice(1);
    writeFileSync(payloadCopy, html.replace(sha, flippedSha));
    assert.equal(cliResult(dir, ['report', 'verify', payloadCopy, '--json']).code, 2);

    const embedded = JSON.parse(
      html.match(/<script type="application\/json" id="agent-receipt-report-sig">([\s\S]*?)<\/script>/)[1],
    );
    const badSig = embedded.signature.slice(0, -2) + (embedded.signature.endsWith('aa') ? 'bb' : 'aa');
    const sigCopy = join(dir, 'sig.report.html');
    writeFileSync(sigCopy, html.replace(embedded.signature, badSig));
    assert.equal(cliResult(dir, ['report', 'verify', sigCopy, '--json']).code, 2);

    const detached = readFileSync(made.sigPath, 'utf8');
    const detachedDoc = JSON.parse(detached);
    detachedDoc.signature = badSig;
    writeFileSync(made.sigPath, JSON.stringify(detachedDoc));
    assert.equal(cliResult(dir, ['report', 'verify', made.htmlPath, '--json']).code, 2);
    writeFileSync(made.sigPath, detached);

    const miss = cliResult(dir, [
      'report', 'verify', made.htmlPath, '--require-sig', '--trusted-key', 'ab'.repeat(32), '--json',
    ]);
    assert.equal(miss.code, 2);
    assert.equal(parseJson(miss.out).ok, false);

    cli(dir, ['trust', 'add', '--self']);
    assert.equal(cliResult(dir, ['report', 'verify', made.htmlPath, '--require-sig', '--json']).code, 0);
    rmSync(made.sigPath);
    const embeddedOnly = cliResult(dir, ['report', 'verify', made.htmlPath, '--require-sig', '--json']);
    assert.equal(embeddedOnly.code, 0, embeddedOnly.err);

    const receipt = latestReceipt(dir);
    const original = readFileSync(receipt, 'utf8');
    writeFileSync(receipt, original.replace(/agent-receipt-sha256:\s*[0-9a-f]{64}/, (line) => line.replace(/a/g, 'b').replace(/b/g, 'c')));
    const drifted = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(drifted.code, 2, drifted.out + drifted.err);
    writeFileSync(receipt, original);
  });

  it('redacts host, an AWS key, and a ghp_ token unless opted out', () => {
    const dir = initRepo();
    enableFullDiffs(dir);
    commitFile(dir, 'secret.txt', `aws ${AWS}\ntoken ${GHP}\n`, 'add secrets');
    cli(dir, ['wrap', '--host', HOST, '--agent', 'ci', '--message', `see ${AWS} and ${GHP}`]);
    const made = parseJson(cli(dir, ['report', 'last', '--json']));
    const html = readFileSync(made.htmlPath, 'utf8');
    assert.equal(html.includes(HOST), false);
    assert.equal(html.includes(AWS), false);
    assert.equal(html.includes(GHP), false);
    assert.equal(html.includes('UNREDACTED'), false);
    assert.equal(payloadOf(html).exposure, 'redacted');

    const hostKept = parseJson(cli(dir, ['report', 'last', '--include-host', '--out', join(dir, 'host.report.html'), '--json']));
    const hostHtml = readFileSync(hostKept.htmlPath, 'utf8');
    assert.equal(hostHtml.includes(HOST), true);
    assert.equal(hostHtml.includes(AWS), false);
    assert.equal(hostHtml.includes(GHP), false);
    assert.equal(hostHtml.includes('UNREDACTED'), true);
    assert.equal(payloadOf(hostHtml).exposure, 'host');

    const open = parseJson(cli(dir, ['report', 'last', '--no-redact', '--include-host', '--out', join(dir, 'open.report.html'), '--json']));
    const openHtml = readFileSync(open.htmlPath, 'utf8');
    assert.equal(openHtml.includes(HOST), true);
    assert.equal(openHtml.includes(AWS), true);
    assert.equal(openHtml.includes(GHP), true);
    assert.equal(openHtml.includes('UNREDACTED'), true);
    assert.equal(payloadOf(openHtml).exposure, 'unredacted');
  });

  it('renders hostile content inert and still verifies', () => {
    const dir = initRepo();
    enableFullDiffs(dir);
    const hostile = [
      '<script>alert(1)</script>',
      '</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '# Agent Receipt',
      '## What to review',
      '## Session',
      '`backtick`',
    ].join('\n');
    commitFile(dir, 'hostile.txt', `${hostile}\n`, '<script>alert(1)</script>');
    const message = `${hostile}\nonclick="alert(1)"`;
    cli(dir, ['capture', '--agent', '<script>alert(1)</script>', '--message', message, '--session', 's-hostile']);
    const receipt = latestReceipt(dir);
    assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
    const made = cliResult(dir, ['report', receipt, '--json']);
    assert.equal(made.code, 0, made.out + made.err);
    const html = readFileSync(parseJson(made.out).htmlPath, 'utf8');
    const visible = visibleHtml(html);
    assert.doesNotMatch(visible, /<script/i);
    assert.doesNotMatch(visible, /<\/script/i);
    assert.doesNotMatch(visible, /<[a-zA-Z][^>]*\son[a-z]+\s*=/i);
    assert.doesNotMatch(visible, /(?:href|src)\s*=\s*["']?\s*javascript:/i);
    assert.match(visible, /&lt;script&gt;/);
    assert.match(visible, /# Agent Receipt/);
    assert.match(visible, /`backtick`/);
    assert.match(html, /<h2>Diff lines<\/h2>/);
    assert.equal(cliResult(dir, ['report', 'verify', parseJson(made.out).htmlPath]).code, 0);
  });

  it('reports a session tree and a session package', () => {
    const dir = initRepo();
    commitFile(dir, 'parent.txt', 'parent\n');
    const parent = parseJson(cli(dir, ['wrap', '--session', 's-rep30', '--agent', 'parent', '--message', 'parent', '--json']));
    commitFile(dir, 'child.txt', 'child\n');
    cli(dir, ['wrap', '--session', 's-rep30', '--parent', parent.path, '--agent', 'child', '--message', 'child', '--json']);
    const local = parseJson(cli(dir, ['report', '--session', 's-rep30', '--json']));
    assert.equal(local.exitCode, 0);
    assert.equal(local.receiptCount, 2);
    assert.equal(local.verdict, 'UNSIGNED');
    const localHtml = readFileSync(local.htmlPath, 'utf8');
    assert.match(localHtml, /<h2>Session tree<\/h2>/);
    assert.match(localHtml, /parent/);
    assert.match(localHtml, /child/);
    const localPayload = payloadOf(localHtml);
    assert.equal(localPayload.subject, 'session');
    assert.equal(localPayload.session, 's-rep30');
    assert.equal(localPayload.manifestSha256, null);
    assert.match(localPayload.verifyCommands[0], /--receipts receipts/);
    assert.equal(localPayload.verifyCommands.some((line) => line.startsWith('agent-receipt session import')), false);
    assert.equal(cliResult(dir, ['report', 'verify', local.htmlPath, '--json']).code, 0);

    const exported = parseJson(cli(dir, ['session', 'export', 's-rep30', '--json']));
    const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
    assert.equal(packaged.receiptCount, 2);
    const pkgHtml = readFileSync(packaged.htmlPath, 'utf8');
    const pkgPayload = payloadOf(pkgHtml);
    assert.equal(pkgPayload.subject, 'session');
    assert.match(pkgPayload.manifestSha256, /^[0-9a-f]{64}$/);
    assert.ok(pkgPayload.verifyCommands.some((line) => /session import /.test(line) && line.includes('--dry-run')));
    const verifyArgs = pkgPayload.verifyCommands[0].split(' ').slice(1);
    const checked = cliResult(join(dir, '.agent-receipt'), verifyArgs.concat(['--json']));
    assert.equal(checked.code, 0, checked.out + checked.err);
    assert.ok(parseJson(checked.out).checked >= 1);
  });

  it('writes FAILED when a receipt does not verify', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'fail\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'will fail']);
    const receipt = latestReceipt(dir);
    const bad = join(dir, 'bad.md');
    writeFileSync(bad, readFileSync(receipt, 'utf8').replace(/agent-receipt-sha256:\s*([0-9a-f]{64})/, (all, hex) => {
      return all.replace(hex, (hex[0] === 'a' ? 'b' : 'a') + hex.slice(1));
    }));
    const made = cliResult(dir, ['report', bad, '--out', join(dir, 'failed.report.html'), '--json']);
    assert.equal(made.code, 2, made.out + made.err);
    const body = parseJson(made.out);
    assert.equal(body.verdict, 'FAILED');
    assert.equal(body.exitCode, 2);
    assert.ok(existsSync(body.htmlPath));
    assert.match(readFileSync(body.htmlPath, 'utf8'), /FAILED/);
  });

  it('warns and records signedBy for an unsigned foreign-looking redacted export', () => {
    const dir = initRepo();
    enableFullDiffs(dir);
    commitFile(dir, 'secret.txt', `aws ${AWS}\n`, 'secret');
    cli(dir, ['wrap', '--session', 's-signby', '--agent', 'exporter', '--host', HOST, '--message', `token ${GHP}`]);
    const keys = parseJson(cli(dir, ['keygen', '--json']));
    const exported = cliResult(dir, ['session', 'export', 's-signby', '--json']);
    assert.equal(exported.code, 0, exported.out + exported.err);
    assert.match(exported.err, /signedBy/);
    assert.match(exported.err, /originalFingerprint is null/);
    assert.match(exported.err, /not the original author's signature/);
    const body = parseJson(exported.out);
    const manifest = JSON.parse(readFileSync(body.manifestPath, 'utf8'));
    assert.equal(manifest.receipts.length, 1);
    const entry = manifest.receipts[0];
    assert.equal(entry.signedBy, keys.fingerprint);
    assert.equal(entry.fingerprint, keys.fingerprint);
    assert.equal(entry.originalFingerprint, null);
    assert.equal(entry.resignedBy, null);
    assert.equal(entry.signed, true);
    const dest = initRepo();
    const imported = cliResult(dest, ['session', 'import', body.packagePath]);
    assert.equal(imported.code, 0, imported.out + imported.err);
    assert.match(imported.out, /originalFingerprint: null/);
    assert.match(imported.out, /resignedBy: null/);
    assert.match(imported.out, new RegExp(`signedBy: ${keys.fingerprint}`));
    const shown = cliResult(dest, ['session', 's-signby']);
    assert.equal(shown.code, 0, shown.err);
    assert.match(shown.out, new RegExp(`signedBy=${keys.fingerprint}`));
    assert.match(shown.out, /originalFingerprint=null/);
    assert.match(shown.out, /resignedBy=null/);
  });

  it('shows re-sign provenance after import', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'resign\n');
    const first = parseJson(cli(dir, ['keygen', '--json']));
    cli(dir, ['wrap', '--sign', '--session', 's-resign', '--agent', 'alice', '--host', 'host-a.example', '--message', 'signed source']);
    renameSync(join(dir, '.agent-receipt', 'keys'), join(dir, '.agent-receipt', 'keys-a'));
    const second = parseJson(cli(dir, ['keygen', '--json']));
    assert.notEqual(first.fingerprint, second.fingerprint);
    const refused = cliResult(dir, ['session', 'export', 's-resign', '--json']);
    assert.equal(refused.code, 2);
    const exported = cliResult(dir, ['session', 'export', 's-resign', '--resign', '--json']);
    assert.equal(exported.code, 0, exported.out + exported.err);
    const body = parseJson(exported.out);
    const manifest = JSON.parse(readFileSync(body.manifestPath, 'utf8'));
    const entry = manifest.receipts[0];
    assert.equal(entry.originalFingerprint, first.fingerprint);
    assert.equal(entry.resignedBy, second.fingerprint);
    assert.equal(entry.signedBy, null);
    const dest = initRepo();
    const imported = cliResult(dest, ['session', 'import', body.packagePath]);
    assert.equal(imported.code, 0, imported.out + imported.err);
    assert.match(imported.out, new RegExp(`originalFingerprint: ${first.fingerprint}`));
    assert.match(imported.out, new RegExp(`resignedBy: ${second.fingerprint}`));
    const shown = cliResult(dest, ['session', 's-resign']);
    assert.equal(shown.code, 0, shown.err);
    assert.match(shown.out, new RegExp(`originalFingerprint=${first.fingerprint}`));
    assert.match(shown.out, new RegExp(`resignedBy=${second.fingerprint}`));
  });

  it('refuses a symlinked sidecar before deleting any prune target', () => {
    const dir = initRepo();
    for (const name of ['a.txt', 'b.txt', 'c.txt']) {
      commitFile(dir, name, `${name}\n`);
      cli(dir, ['capture', '--message', name]);
    }
    const indexPath = join(dir, '.agent-receipt', 'index.json');
    const index = JSON.parse(readFileSync(indexPath, 'utf8'));
    assert.equal(index.receipts.length, 3);
    index.receipts.forEach((entry, i) => {
      entry.timestamp = new Date(Date.UTC(2020, 0, i + 1)).toISOString();
    });
    writeFileSync(indexPath, JSON.stringify(index));
    const oldest = join(dir, index.receipts[0].path);
    symlinkSync('missing-target', oldest.replace(/\.md$/i, '.sig.json'));
    const before = receiptFiles(dir).map((file) => basename(file)).sort();
    assert.equal(before.length, 3);
    const pruned = cliResult(dir, ['prune', '--max-count', '1']);
    assert.equal(pruned.code, 1, pruned.out + pruned.err);
    assert.match(pruned.err, /refusing to delete symlink/);
    const after = receiptFiles(dir).map((file) => basename(file)).sort();
    assert.deepEqual(after, before);
  });

  it('cleans stale import staging directories that it owns', () => {
    const src = initRepo();
    commitFile(src, 'note.txt', 'stage\n');
    cli(src, ['wrap', '--session', 's-stage', '--agent', 'ci', '--message', 'stage']);
    const exported = parseJson(cli(src, ['session', 'export', 's-stage', '--json']));
    const dest = initRepo();
    const receipts = join(dest, '.agent-receipt', 'receipts');
    mkdirSync(receipts, { recursive: true });
    const past = new Date(Date.now() - 3600_000);
    const ahead = new Date(Date.now() + 3600_000);
    const stale = join(receipts, '.import-staging-stale');
    mkdirSync(stale);
    writeFileSync(join(stale, '.agent-receipt-import-staging'), 'agent-receipt-import-staging\n');
    utimesSync(stale, past, past);
    const plain = join(receipts, '.import-staging-plain');
    mkdirSync(plain);
    writeFileSync(join(plain, 'note.txt'), 'keep\n');
    utimesSync(plain, past, past);
    const future = join(receipts, '.import-staging-new');
    mkdirSync(future);
    writeFileSync(join(future, '.agent-receipt-import-staging'), 'agent-receipt-import-staging\n');
    utimesSync(future, ahead, ahead);
    const target = join(receipts, 'not-staging');
    mkdirSync(target);
    writeFileSync(join(target, '.agent-receipt-import-staging'), 'agent-receipt-import-staging\n');
    const link = join(receipts, '.import-staging-link');
    symlinkSync(target, link);
    const dry = cliResult(dest, ['session', 'import', exported.packagePath, '--dry-run']);
    assert.equal(dry.code, 0, dry.out + dry.err);
    assert.equal(existsSync(stale), true);
    const imported = cliResult(dest, ['session', 'import', exported.packagePath]);
    assert.equal(imported.code, 0, imported.out + imported.err);
    assert.equal(existsSync(stale), false);
    assert.equal(existsSync(plain), true);
    assert.equal(existsSync(future), true);
    assert.equal(lstatSync(link).isSymbolicLink(), true);
    assert.equal(existsSync(target), true);
  });

  it('decodes a percent-encoded branch in share HTML and sets CSP', () => {
    const parent = mkdtempSync(join(tmpdir(), 'ar-branch-'));
    dirs.push(parent);
    const dir = join(parent, 'ws');
    mkdirSync(dir);
    git(dir, ['init']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    git(dir, ['checkout', '-b', 'rel/a`b']);
    writeFileSync(join(dir, 'a.txt'), 'a\n');
    git(dir, ['add', 'a.txt']);
    git(dir, ['commit', '-m', 'tick']);
    cli(dir, ['init']);
    cli(dir, ['capture', '--message', 'tick stays literal', '--session', 'bt-sess']);
    const htmlPath = join(dir, 'share.html');
    cli(dir, ['share', '--out', htmlPath]);
    const html = readFileSync(htmlPath, 'utf8');
    assert.match(html, /<code>rel\/a`b<\/code>/);
    assert.doesNotMatch(html, /%60/);
    assert.match(html, /Content-Security-Policy/);
    assert.match(html, /script-src 'none'/);
    assert.match(html, new RegExp(CSP.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  });

  it('follows a symlinked .agent-receipt parent', () => {
    const dir = initRepo();
    const link = join(dir, '.agent-receipt');
    const real = join(dir, 'real-store');
    renameSync(link, real);
    symlinkSync(real, link);
    commitFile(dir, 'note.txt', 'through the link\n');
    cli(dir, ['capture', '--message', 'symlink store']);
    const names = readdirSync(join(real, 'receipts')).filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'));
    assert.ok(names.length >= 1);
    assert.equal(cliResult(dir, ['verify', join(real, 'receipts', names[0])]).code, 0);
  });
});
