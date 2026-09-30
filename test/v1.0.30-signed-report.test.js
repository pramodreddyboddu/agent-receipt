import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
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

const PAGE_MISMATCH = 'page content does not match signed payload';

/** Change only the part a reviewer reads. The signed blocks stay intact. */
function mutateVisible(html, from, to) {
  const marker = '<script type="application/json" id="agent-receipt-report">';
  const at = html.indexOf(marker);
  assert.ok(at > 0, 'payload script missing');
  const visible = html.slice(0, at);
  assert.ok(visible.includes(from), `visible page is missing ${from}`);
  const changed = visible.replace(from, to);
  assert.notEqual(changed, visible);
  return changed + html.slice(at);
}

function expectPageReject(dir, html, label) {
  const file = join(dir, `${label}.report.html`);
  writeFileSync(file, html);
  const plain = cliResult(dir, ['report', 'verify', file, '--json']);
  const required = cliResult(dir, ['report', 'verify', file, '--require-sig', '--json']);
  assert.equal(plain.code, 2, `${label} plain\n${plain.out}\n${plain.err}`);
  assert.equal(required.code, 2, `${label} require-sig\n${required.out}\n${required.err}`);
  assert.equal(parseJson(plain.out).reason, PAGE_MISMATCH);
  assert.equal(parseJson(required.out).reason, PAGE_MISMATCH);
  assert.notEqual(parseJson(plain.out).verdict, 'VERIFIED');
  assert.notEqual(parseJson(required.out).verdict, 'VERIFIED');
  const text = cliResult(dir, ['report', 'verify', file]);
  assert.equal(text.code, 2);
  assert.doesNotMatch(text.out, /^VERIFIED/m);
}

function expectStructureReject(dir, html, label, reason) {
  const file = join(dir, `${label}.report.html`);
  writeFileSync(file, html);
  for (const args of [
    ['report', 'verify', file, '--json'],
    ['report', 'verify', file, '--require-sig', '--json'],
  ]) {
    const result = cliResult(dir, args);
    assert.equal(result.code, 2, `${label}\n${result.out}\n${result.err}`);
    const body = parseJson(result.out);
    assert.equal(body.exitCode, 2);
    assert.match(body.reason, reason);
    assert.notEqual(body.verdict, 'VERIFIED');
  }
}

function scriptBlock(html, id) {
  const match = html.match(new RegExp(`<script type="application\\/json" id="${id}">[\\s\\S]*?<\\/script>`));
  assert.ok(match, `${id} missing`);
  return match[0];
}

function canonicalBodyOf(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  for (const line of lines) {
    if (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256')) break;
    out.push(line);
  }
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  return `${out.join('\n')}\n`;
}

/** Rewrite the receipt id and refresh the integrity footer. */
function withReceiptId(markdown, id) {
  const body = canonicalBodyOf(markdown).replace(/^- \*\*Id\*\*: .+$/m, `- **Id**: ${id}`);
  const hash = createHash('sha256').update(body, 'utf8').digest('hex');
  return `${body}\n## Integrity\n\n<!-- agent-receipt-sha256:${hash} -->\n\nSHA-256 of canonical body: \`${hash}\`\n`;
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
    assert.match(readme, /page content does not match signed payload/);
    assert.match(schema.description, /page content does not match signed payload/);
    assert.match(readme, /symlinked `\.agent-receipt` parent is followed/);
    assert.match(readme, /originalFingerprint` is the manifest signer's claim/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /### Signed one-page report/);
    assert.match(business, /page content does not match signed payload/);
    assert.match(changelog, /page content does not match signed payload/);
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
    assert.match(help, /page content does not match signed payload/);
    assert.doesNotMatch(help, /does not cover CSS/);
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
    assert.doesNotMatch(payload.receipts[0].range, /`/);
    assert.doesNotMatch(payload.receipts[0].range, /_\(/);
    assert.match(payload.receipts[0].summary, /^Files: /m);
    assert.doesNotMatch(payload.receipts[0].summary, /\|/);
    assert.doesNotMatch(payload.receipts[0].summary, /\*\*/);
    assert.doesNotMatch(visibleHtml(html), /\| Metric \|/);
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
    const css = cliResult(dir, ['report', 'verify', cssCopy, '--json']);
    assert.equal(css.code, 2);
    assert.equal(parseJson(css.out).reason, PAGE_MISMATCH);

    const visibleCopy = join(dir, 'visible.report.html');
    writeFileSync(
      visibleCopy,
      html.replace('<div class="verdict">VERIFIED</div>', '<div class="verdict">FAILED</div>'),
    );
    const visible = cliResult(dir, ['report', 'verify', visibleCopy, '--json']);
    assert.equal(visible.code, 2);
    assert.equal(parseJson(visible.out).reason, PAGE_MISMATCH);
    assert.notEqual(parseJson(visible.out).verdict, 'VERIFIED');

    const trimmed = join(dir, 'trimmed.report.html');
    writeFileSync(trimmed, html.replace(/\n$/, ''));
    assert.equal(cliResult(dir, ['report', 'verify', trimmed, '--json']).code, 0);

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
    assert.equal(parseJson(miss.out).verdict, 'FAILED');
    assert.notEqual(parseJson(miss.out).verdict, 'VERIFIED');

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

  it('rejects a hidden verdict, a flipped banner, and pill or title edits (B1)', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'b1\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'unsigned banner']);
    const html = readFileSync(parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath, 'utf8');
    let attacked = mutateVisible(
      html,
      '<body>\n',
      '<body>\n<span hidden data-covered="verdict">FAILED</span>\n',
    );
    attacked = mutateVisible(attacked, '<div class="banner unsigned"', '<div class="banner verified"');
    attacked = mutateVisible(
      attacked,
      '<div class="verdict">UNSIGNED</div>',
      '<div class="verdict">VERIFIED</div>',
    );
    attacked = mutateVisible(
      attacked,
      '<title>Agent Receipt report — UNSIGNED</title>',
      '<title>Agent Receipt report — VERIFIED</title>',
    );
    attacked = mutateVisible(
      attacked,
      '<th scope="row">Signature</th><td><span class="pill mid">UNSIGNED</span>',
      '<th scope="row">Signature</th><td><span class="pill ok">VALID</span>',
    );
    attacked = mutateVisible(
      attacked,
      '<th scope="row">Trust</th><td><span class="pill mid">UNSIGNED</span>',
      '<th scope="row">Trust</th><td><span class="pill ok">TRUSTED</span>',
    );
    attacked = mutateVisible(
      attacked,
      '<th scope="row">Verified</th><td><span class="pill ok">yes</span>',
      '<th scope="row">Verified</th><td><span class="pill ok">yes</span><!--pill-->',
    );
    expectPageReject(dir, attacked, 'b1-banner');
  });

  it('rejects edits to the agent, pills, fingerprint, status line, and narrative (B2)', () => {
    const dir = initRepo();
    git(dir, ['checkout', '-b', 'b2-branch']);
    commitFile(dir, 'b2-file.txt', 'b2-diff-token\n', 'b2-commit-token');
    cli(dir, ['wrap', '--base', 'HEAD~1', '--full', '--session', 's-b2page', '--agent', 'b2-agent', '--message', 'b2-message-token']);
    cli(dir, ['keygen']);
    cli(dir, ['trust', 'add', '--self']);
    const made = parseJson(cli(dir, ['report', '--session', 's-b2page', '--json']));
    assert.equal(made.verdict, 'VERIFIED');
    const html = readFileSync(made.htmlPath, 'utf8');
    assert.match(html, /Report signature: present \(trusted\)/);
    assert.match(html, /<h2>Session tree<\/h2>/);
    const fp = html.match(/<p>Fingerprint: <code>([0-9a-f]{64})<\/code><\/p>/);
    assert.ok(fp);
    const flipped = fp[1].slice(0, -1) + (fp[1].endsWith('a') ? 'b' : 'a');
    const edits = [
      ['agent', '<th scope="row">Agent</th><td>b2-agent</td>', '<th scope="row">Agent</th><td>other-agent</td>'],
      [
        'verified-pill',
        '<th scope="row">Verified</th><td><span class="pill ok">yes</span>',
        '<th scope="row">Verified</th><td><span class="pill ok">no</span>',
      ],
      [
        'trust-pill',
        '<th scope="row">Trust</th><td><span class="pill mid">UNSIGNED</span>',
        '<th scope="row">Trust</th><td><span class="pill ok">TRUSTED</span>',
      ],
      ['fingerprint', `<p>Fingerprint: <code>${fp[1]}</code></p>`, `<p>Fingerprint: <code>${flipped}</code></p>`],
      ['status', 'Report signature: present (trusted)', 'Report signature: present (untrusted)'],
      ['banner-class', '<div class="banner verified"', '<div class="banner failed"'],
      [
        'title',
        '<title>Agent Receipt report — VERIFIED</title>',
        '<title>Agent Receipt report — FAILED</title>',
      ],
      [
        'branch',
        '<th scope="row">Branch</th><td><code>b2-branch</code>',
        '<th scope="row">Branch</th><td><code>other-branch</code>',
      ],
      [
        'message',
        '<th scope="row">Message</th><td>b2-message-token</td>',
        '<th scope="row">Message</th><td>other-message</td>',
      ],
      ['files', 'b2-file.txt', 'other-file.txt'],
      ['diff', 'b2-diff-token', 'other-diff-token'],
      ['commits', 'b2-commit-token', 'other-commit-token'],
      ['risk', 'No risk findings.', 'Risk was cleared.'],
      ['tree', 'session s-b2page', 'session s-other'],
    ];
    for (const [label, from, to] of edits) {
      expectPageReject(dir, mutateVisible(html, from, to), `b2-${label}`);
    }
  });

  it('rejects a payload hidden in a comment, a second payload, and a second signature (B3)', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'b3\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'blocks']);
    const html = readFileSync(parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath, 'utf8');
    const payload = scriptBlock(html, 'agent-receipt-report');
    const signature = scriptBlock(html, 'agent-receipt-report-sig');
    assert.doesNotMatch(payload, /-->/);
    const forged = '<script type="application/json" id="agent-receipt-report">{"forged":true}</script>';
    expectStructureReject(
      dir,
      html.replace(payload, `<!-- ${payload} -->\n${forged}`),
      'b3-comment',
      /report payload block is inside a comment/,
    );
    expectStructureReject(
      dir,
      html.replace(payload, `${payload}\n${forged}`),
      'b3-duplicate-payload',
      /report has more than one payload block/,
    );
    expectStructureReject(
      dir,
      html.replace(signature, `${signature}\n${signature}`),
      'b3-duplicate-sig',
      /report has more than one signature block/,
    );
  });

  it('rejects a hidden, commented, or removed UNREDACTED marker (B4)', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'b4\n');
    cli(dir, ['wrap', '--host', HOST, '--agent', 'ci', '--message', 'show host']);
    const made = parseJson(cli(dir, ['report', 'last', '--include-host', '--json']));
    const html = readFileSync(made.htmlPath, 'utf8');
    const marker = html.match(/<div class="banner unredacted" role="status">[\s\S]*?<\/div>/);
    assert.ok(marker, 'expected a visible UNREDACTED banner');
    assert.match(marker[0], /<strong>UNREDACTED<\/strong>/);
    expectPageReject(dir, html.replace(marker[0], '<!-- UNREDACTED -->'), 'b4-comment');
    expectPageReject(dir, html.replace(marker[0], '<p hidden>UNREDACTED</p>'), 'b4-hidden');
    expectPageReject(dir, html.replace(marker[0], ''), 'b4-removed');
  });

  it('never accepts a one-byte flip or insert spread through the file', { timeout: 120000 }, () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'fuzz\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'fuzz']);
    cli(dir, ['keygen']);
    const html = readFileSync(parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath, 'utf8');
    const buf = Buffer.from(html, 'utf8');
    const spots = 10;
    for (let i = 0; i < spots; i += 1) {
      const at = Math.min(buf.length - 1, Math.floor(((buf.length - 1) * i) / (spots - 1)));
      const flipped = Buffer.from(buf);
      flipped[at] = flipped[at] ^ 0x01;
      const inserted = Buffer.concat([buf.subarray(0, at), Buffer.from([0x58]), buf.subarray(at)]);
      for (const [label, body] of [
        [`flip-${at}`, flipped],
        [`ins-${at}`, inserted],
      ]) {
        const file = join(dir, `${label}.report.html`);
        writeFileSync(file, body);
        for (const args of [
          ['report', 'verify', file],
          ['report', 'verify', file, '--require-sig'],
        ]) {
          const result = cliResult(dir, args);
          assert.notEqual(result.code, 0, `${label} ${args.join(' ')} exited 0`);
          assert.equal(result.code, 2, `${label} ${args.join(' ')}\n${result.out}\n${result.err}`);
          assert.doesNotMatch(result.out, /^VERIFIED/m);
        }
      }
    }
  });

  it('does not fail verify when a local receipt shares the id but not the bytes', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', `host ${HOST}\n`);
    cli(dir, ['keygen']);
    cli(dir, ['wrap', '--session', 's-sameid', '--agent', 'exporter', '--host', HOST, '--message', 'local host']);
    const localText = readFileSync(latestReceipt(dir), 'utf8');
    const exported = parseJson(cli(dir, ['session', 'export', 's-sameid', '--json']));
    const packaged = cliResult(dir, ['report', exported.packagePath, '--json']);
    assert.equal(packaged.code, 0, packaged.out + packaged.err);
    const body = parseJson(packaged.out);
    assert.equal(body.verdict, 'VERIFIED');
    const html = readFileSync(body.htmlPath, 'utf8');
    const payload = payloadOf(html);
    const localSha = createHash('sha256').update(canonicalBodyOf(localText), 'utf8').digest('hex');
    assert.notEqual(payload.receipts[0].sha256, localSha);
    const checked = cliResult(dir, ['report', 'verify', body.htmlPath, '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    assert.equal(parseJson(checked.out).verdict, 'VERIFIED');
    const text = cliResult(dir, ['report', 'verify', body.htmlPath]);
    assert.equal(text.code, 0, text.out + text.err);
    assert.match(text.out, /^VERIFIED  report verify/m);
  });

  it('signs a session report FAILED when the session root does not verify', () => {
    const dir = initRepo();
    commitFile(dir, 'parent.txt', 'parent\n');
    const parent = parseJson(cli(dir, ['wrap', '--session', 's-rootfail', '--agent', 'parent', '--message', 'parent', '--json']));
    commitFile(dir, 'child.txt', 'child\n');
    cli(dir, ['wrap', '--session', 's-rootfail', '--parent', parent.path, '--agent', 'child', '--message', 'child']);
    cli(dir, ['keygen']);
    cli(dir, ['trust', 'add', '--self']);
    const good = cliResult(dir, ['report', '--session', 's-rootfail', '--out', join(dir, 'good-root.report.html'), '--json']);
    assert.equal(good.code, 0, good.out + good.err);
    const goodBody = parseJson(good.out);
    assert.equal(goodBody.verdict, 'VERIFIED');
    const rootId = payloadOf(readFileSync(goodBody.htmlPath, 'utf8')).receipts.find((item) => !item.parent).id;
    const original = readFileSync(parent.path, 'utf8');
    writeFileSync(parent.path, original.replace(/agent-receipt-sha256:[0-9a-f]{64}/, (hex) => {
      return hex.replace(/[0-9a-f]$/, (ch) => (ch === 'a' ? 'b' : 'a'));
    }));
    const made = cliResult(dir, ['report', '--session', 's-rootfail', '--json']);
    assert.equal(made.code, 2, made.out + made.err);
    const body = parseJson(made.out);
    assert.equal(body.verdict, 'FAILED');
    assert.match(body.reason, new RegExp(`session root ${rootId} failed verification`));
    const html = readFileSync(body.htmlPath, 'utf8');
    assert.match(html, /<div class="banner failed"/);
    assert.match(html, /<div class="verdict">FAILED<\/div>/);
    assert.doesNotMatch(html, /<div class="banner verified"/);
    assert.match(html, /<title>Agent Receipt report — FAILED<\/title>/);
    for (const args of [
      ['report', 'verify', body.htmlPath],
      ['report', 'verify', body.htmlPath, '--require-sig'],
    ]) {
      const checked = cliResult(dir, args);
      assert.equal(checked.code, 2, checked.out + checked.err);
      assert.match(checked.out, /^FAILED  report verify/m);
      assert.doesNotMatch(checked.out, /^VERIFIED/m);
      assert.match(checked.err, new RegExp(rootId));
    }
    const json = cliResult(dir, ['report', 'verify', body.htmlPath, '--json']);
    assert.equal(json.code, 2);
    assert.equal(parseJson(json.out).verdict, 'FAILED');
  });

  it('exits 2 for FAILED and UNTRUSTED and never prints VERIFIED on failure', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'policy\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'policy']);
    const unsignedHtml = parseJson(cli(dir, ['report', 'last', '--out', join(dir, 'unsigned.report.html'), '--json'])).htmlPath;
    const honest = cliResult(dir, ['report', 'verify', unsignedHtml]);
    assert.equal(honest.code, 0, honest.err);
    assert.match(honest.out, /^UNSIGNED  report verify/m);
    assert.doesNotMatch(honest.out, /^VERIFIED/m);
    const needSig = cliResult(dir, ['report', 'verify', unsignedHtml, '--require-sig']);
    assert.equal(needSig.code, 2);
    assert.match(needSig.out, /^UNSIGNED  report verify/m);
    assert.doesNotMatch(needSig.out, /^VERIFIED/m);

    const receipt = latestReceipt(dir);
    const bad = join(dir, 'bad-policy.md');
    writeFileSync(bad, readFileSync(receipt, 'utf8').replace(/agent-receipt-sha256:[0-9a-f]{64}/, (hex) => {
      return hex.replace(/[0-9a-f]$/, (ch) => (ch === 'a' ? 'b' : 'a'));
    }));
    const failed = cliResult(dir, ['report', bad, '--out', join(dir, 'failed-policy.report.html'), '--json']);
    assert.equal(failed.code, 2);
    assert.equal(parseJson(failed.out).verdict, 'FAILED');
    for (const args of [
      ['report', 'verify', parseJson(failed.out).htmlPath],
      ['report', 'verify', parseJson(failed.out).htmlPath, '--require-sig'],
    ]) {
      const checked = cliResult(dir, args);
      assert.equal(checked.code, 2, checked.out + checked.err);
      assert.match(checked.out, /^FAILED  report verify/m);
      assert.doesNotMatch(checked.out, /^VERIFIED/m);
    }

    cli(dir, ['keygen']);
    cli(dir, ['trust', 'add', 'ab'.repeat(32)]);
    const untrusted = cliResult(dir, ['report', 'last', '--out', join(dir, 'untrusted.report.html'), '--json']);
    assert.equal(untrusted.code, 0, untrusted.out + untrusted.err);
    assert.equal(parseJson(untrusted.out).verdict, 'UNTRUSTED');
    for (const args of [
      ['report', 'verify', parseJson(untrusted.out).htmlPath],
      ['report', 'verify', parseJson(untrusted.out).htmlPath, '--require-sig'],
    ]) {
      const checked = cliResult(dir, args);
      assert.equal(checked.code, 2, checked.out + checked.err);
      assert.match(checked.out, /^UNTRUSTED  report verify/m);
      assert.doesNotMatch(checked.out, /^VERIFIED/m);
    }
    const untrustedJson = cliResult(dir, ['report', 'verify', parseJson(untrusted.out).htmlPath, '--json']);
    assert.equal(parseJson(untrustedJson.out).verdict, 'UNTRUSTED');
    assert.equal(parseJson(untrustedJson.out).exitCode, 2);
  });

  it('exits 1 when --receipts is missing or not a directory', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'receipts-dir\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'receipts dir']);
    const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    const missing = cliResult(dir, ['report', 'verify', htmlPath, '--receipts', join(dir, 'no-such-receipts')]);
    assert.equal(missing.code, 1);
    assert.match(missing.err, /--receipts directory not found/);
    const notDir = join(dir, 'not-a-receipts-dir');
    writeFileSync(notDir, 'x\n');
    const fileDir = cliResult(dir, ['report', 'verify', htmlPath, '--receipts', notDir]);
    assert.equal(fileDir.code, 1);
    assert.match(fileDir.err, /--receipts is not a directory/);
    const blocked = join(dir, 'blocked-receipts');
    mkdirSync(blocked);
    chmodSync(blocked, 0);
    let readable = true;
    try {
      readdirSync(blocked);
    } catch {
      readable = false;
    }
    const unread = cliResult(dir, ['report', 'verify', htmlPath, '--receipts', blocked]);
    chmodSync(blocked, 0o755);
    if (!readable) {
      assert.equal(unread.code, 1);
      assert.match(unread.err, /--receipts directory is unreadable/);
    }
  });

  it('treats a present payload that fails the schema as tampering', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'schema\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'schema']);
    const html = readFileSync(parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath, 'utf8');
    const match = html.match(/<script type="application\/json" id="agent-receipt-report">([\s\S]*?)<\/script>/);
    assert.ok(match);
    const obj = JSON.parse(match[1]);
    delete obj.title;
    const encoded = JSON.stringify(obj)
      .replace(/&/g, '\\u0026')
      .replace(/</g, '\\u003c')
      .replace(/>/g, '\\u003e');
    expectStructureReject(dir, html.replace(match[1], encoded), 'schema-title', /report payload title is missing/);
    expectStructureReject(
      dir,
      html.replace(match[1], '{'),
      'schema-json',
      /embedded report payload is malformed JSON/,
    );
  });

  it('checks several reports and exits with the worst code', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'multi\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'multi']);
    const good = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    const bad = join(dir, 'multi-bad.report.html');
    writeFileSync(bad, readFileSync(good, 'utf8').replace('<h1>', '<h1 data-x="1">'));
    const missing = join(dir, 'multi-missing.report.html');
    const both = cliResult(dir, ['report', 'verify', good, bad, '--json']);
    assert.equal(both.code, 2);
    const lines = both.out.trim().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[0]).exitCode, 0);
    assert.equal(JSON.parse(lines[0]).verdict, 'UNSIGNED');
    assert.equal(JSON.parse(lines[1]).exitCode, 2);
    assert.equal(JSON.parse(lines[1]).reason, PAGE_MISMATCH);
    const withMissing = cliResult(dir, ['report', 'verify', good, missing]);
    assert.equal(withMissing.code, 1);
    assert.match(withMissing.err, /report not found/);
    const worst = cliResult(dir, ['report', 'verify', good, missing, bad]);
    assert.equal(worst.code, 2);
    assert.doesNotMatch(worst.out, /^VERIFIED/m);
  });

  it('refuses to write a report from an existing report file', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'already\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'already']);
    const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    const refused = cliResult(dir, ['report', htmlPath]);
    assert.equal(refused.code, 1);
    assert.match(refused.err, /input is already a report; use report verify/);
    assert.equal(existsSync(`${htmlPath}.report.html`), false);
    const upper = cliResult(dir, ['report', 'NOPE.REPORT.HTML', '--json']);
    assert.equal(upper.code, 1);
    assert.equal(parseJson(upper.out).reason, 'input is already a report; use report verify');
    assert.equal(existsSync(join(dir, 'NOPE.REPORT.HTML.report.html')), false);
    assert.equal(existsSync(join(dir, '.agent-receipt', 'NOPE.REPORT.HTML.report.html')), false);
  });

  it('writes a complete session --json document when stdout is a pipe', { timeout: 60000 }, () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'bulk\n');
    cli(dir, ['wrap', '--session', 's-bigjson', '--agent', 'ci', '--message', 'bulk']);
    const original = readFileSync(latestReceipt(dir), 'utf8');
    assert.match(original, /^- \*\*Id\*\*: r-[0-9a-f]{16}$/m);
    const receipts = join(dir, '.agent-receipt', 'receipts');
    const count = 320;
    for (let i = 0; i < count; i += 1) {
      const id = `r-${i.toString(16).padStart(16, '0')}`;
      writeFileSync(join(receipts, `${id}.md`), withReceiptId(original, id));
    }
    const result = spawnSync(process.execPath, [bin, 'session', 's-bigjson', '--json'], {
      cwd: dir,
      encoding: 'utf8',
      env: spawnEnv(),
      timeout: 30000,
      maxBuffer: 8 * 1024 * 1024,
    });
    assert.equal(result.status, 0, result.stderr || result.error);
    assert.ok(Buffer.byteLength(result.stdout, 'utf8') > 65536, `stdout bytes ${Buffer.byteLength(result.stdout || '', 'utf8')}`);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.command, 'session');
    assert.equal(parsed.session, 's-bigjson');
    assert.ok(parsed.receipts.length >= count);
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
