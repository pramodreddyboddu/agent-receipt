import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
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
import { createSignatureDocument, loadKeys } from '../dist/lib/sign.js';
import { canonicalReportJson, embedJson, reportPayloadHash } from '../dist/lib/report-html.js';

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

/** Refresh the integrity footer after a body edit. */
function sealReceipt(markdown) {
  const body = canonicalBodyOf(markdown);
  const hash = createHash('sha256').update(body, 'utf8').digest('hex');
  return `${body}\n## Integrity\n\n<!-- agent-receipt-sha256:${hash} -->\n\nSHA-256 of canonical body: \`${hash}\`\n`;
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
    assert.equal(pkg.version, '1.0.31');
    assert.equal(pkg.dependencies, undefined);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    assert.equal(lock.version, '1.0.31');
    assert.equal(lock.packages[''].version, '1.0.31');
    assert.equal(lock.packages[''].dependencies, undefined);
    assert.match(readFileSync(join(root, 'src', 'lib', 'version.ts'), 'utf8'), /1\.0\.31/);
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
    assert.equal(schema.properties.renderVersion.type, 'integer');
    assert.equal(schema.properties.renderVersion.minimum, 1);
    assert.ok(schema.required.includes('renderVersion'));
    assert.match(schema.description, /renderVersion/);
    assert.doesNotMatch(schema.description, /not matched by id/);
    assert.equal(schema.additionalProperties, false);
    assert.ok(schema.properties.receipts.items.required.includes('signedBy'));
    const sessionSchema = JSON.parse(readFileSync(join(root, 'docs', 'session-package.schema.json'), 'utf8'));
    assert.ok(sessionSchema.properties.receipts.items.properties.signedBy);
    assert.equal(sessionSchema.properties.receipts.items.required.includes('signedBy'), false);
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(readme, /Signed one-page|signed one-page HTML report/);
    assert.match(readme, /page content does not match signed payload/);
    assert.match(readme, /core\.autocrlf/);
    assert.match(readme, /\*\.report\.html -text/);
    assert.match(readme, /any valid self-signed page/);
    assert.match(schema.description, /page content does not match signed payload/);
    assert.match(readme, /symlinked `\.agent-receipt` parent is followed/);
    assert.match(readme, /originalFingerprint` is the manifest signer's claim/);
    const business = readFileSync(join(root, 'docs', 'business.md'), 'utf8');
    assert.match(business, /### Signed one-page report/);
    assert.match(business, /page content does not match signed payload/);
    assert.match(changelog, /page content does not match signed payload/);
    assert.match(changelog, /88dad95/);
    assert.match(changelog, /985e363/);
    assert.match(changelog, /differs from the signed payload/);
    assert.match(changelog, /VERIFIED_PAYLOAD_ONLY/);
    assert.match(changelog, /planted copy/);
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
    assert.match(help, /differs from the signed payload/);
    assert.match(help, /VERIFIED_PAYLOAD_ONLY/);
    assert.match(help, /fails integrity/);
    assert.match(help, /is a symlink/);
    assert.match(help, /page has CR line endings/);
    assert.match(help, /UTF-8 BOM/);
    assert.match(help, /core\.autocrlf/);
    assert.match(help, /renderVersion/);
    assert.match(help, /any valid self-signed page/);
    assert.doesNotMatch(help, /is not a match/);
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
    assert.equal(body.version, '1.0.31');
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
    assert.equal(payload.renderVersion, 2);
    assert.equal(payload.cliVersion, '1.0.31');
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
    assert.match(body.reason, /^receipt /);
    assert.doesNotMatch(body.reason, /session root/);
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
    const checkedBody = parseJson(checked.out);
    assert.equal(checkedBody.verdict, 'VERIFIED');
    assert.equal(checkedBody.checked, 1);
    assert.equal(checkedBody.skipped, 0);
    assert.equal(checkedBody.reason, null);
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
    assert.match(needSig.out, /^FAILED \(unsigned\)  report verify/m);
    assert.doesNotMatch(needSig.out, /^UNSIGNED/m);
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
    const renamed = join(dir, 'renamed-report.md');
    writeFileSync(renamed, readFileSync(htmlPath));
    const asMd = cliResult(dir, ['report', renamed, '--json']);
    assert.equal(asMd.code, 1);
    assert.equal(parseJson(asMd.out).reason, 'input is already a report; use report verify');
    assert.equal(existsSync(join(dir, '.agent-receipt', 'renamed-report.report.html')), false);
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

  function signedGrandchild() {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'grandchild\n');
    cli(dir, ['wrap', '--session', 's-grand', '--agent', 'qa', '--message', 'A grandchild']);
    cli(dir, ['keygen']);
    const made = parseJson(cli(dir, ['report', 'last', '--json']));
    assert.equal(made.verdict, 'VERIFIED');
    const receipt = latestReceipt(dir);
    assert.match(readFileSync(receipt, 'utf8'), /A grandchild/);
    const before = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(before.code, 0, before.out + before.err);
    const prior = parseJson(before.out);
    assert.equal(prior.verdict, 'VERIFIED');
    assert.equal(prior.checked, 1);
    assert.equal(prior.skipped, 0);
    const id = payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0].id;
    return { dir, made, receipt, id };
  }

  function editGrandchild(receipt) {
    const text = readFileSync(receipt, 'utf8');
    const next = text.replaceAll('A grandchild', 'A grandchild (edited)');
    assert.notEqual(next, text);
    writeFileSync(receipt, next);
  }

  it('exits 2 when a referenced receipt is edited in place', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    editGrandchild(receipt);
    assert.equal(cliResult(dir, ['verify', receipt]).code, 2);
    const checked = cliResult(dir, ['report', 'verify', made.htmlPath]);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.ok(checked.err.includes(`receipt ${id} at ${receipt} fails integrity`), checked.err);
    assert.match(checked.out, /failed: [1-9]/);
    assert.doesNotMatch(checked.out, /^VERIFIED/m);
    assert.match(checked.out, /^FAILED  report verify/m);
    const json = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(json.code, 2);
    assert.equal(parseJson(json.out).verdict, 'FAILED');
  });

  it('exits 2 when a referenced receipt is re-hashed after a tamper', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    editGrandchild(receipt);
    writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
    assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
    const checked = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.ok(parseJson(checked.out).reason.includes(`receipt ${id} at ${receipt} differs from the signed payload`), checked.out);
    assert.equal(parseJson(checked.out).verdict, 'FAILED');
    const text = cliResult(dir, ['report', 'verify', made.htmlPath]);
    assert.doesNotMatch(text.out, /^VERIFIED/m);
  });

  it('exits 2 when --receipts is missing a referenced receipt and when a deleted receipt is still listed', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const copyDir = join(dir, 'receipts-copy');
    mkdirSync(copyDir);
    const copy = join(copyDir, basename(receipt));
    copyFileSync(receipt, copy);
    rmSync(copy);
    const missing = cliResult(dir, ['report', 'verify', made.htmlPath, '--receipts', copyDir]);
    assert.equal(missing.code, 2, missing.out + missing.err);
    assert.match(missing.err, new RegExp(`receipt ${id} referenced by report not found in --receipts`));
    assert.doesNotMatch(missing.out, /^VERIFIED/m);
    const stillThere = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(stillThere.code, 0, stillThere.out + stillThere.err);
    assert.equal(parseJson(stillThere.out).checked, 1);

    rmSync(receipt);
    const removed = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(removed.code, 2, removed.out + removed.err);
    const body = parseJson(removed.out);
    assert.equal(body.verdict, 'FAILED');
    assert.ok(body.failed >= 1);
    assert.match(body.reason, new RegExp(`receipt ${id} is missing but the store index or audit log still lists it`));
    assert.notEqual(body.verdict, 'VERIFIED');
    const text = cliResult(dir, ['report', 'verify', made.htmlPath]);
    assert.equal(text.code, 2, text.out + text.err);
    assert.doesNotMatch(text.out, /^VERIFIED/m);
    assert.match(text.out, /failed: [1-9]/);
  });

  it('exits 2 when --receipts points at a copied directory with one edited receipt', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const copyDir = join(dir, 'receipts-copy');
    mkdirSync(copyDir);
    const copy = join(copyDir, basename(receipt));
    copyFileSync(receipt, copy);
    editGrandchild(copy);
    const checked = cliResult(dir, ['report', 'verify', made.htmlPath, '--receipts', copyDir]);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.ok(checked.err.includes(`receipt ${id} at ${copy} fails integrity`), checked.err);
    assert.match(checked.out, /failed: [1-9]/);
    assert.doesNotMatch(checked.out, /^VERIFIED/m);
    const untouched = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(untouched.code, 0, untouched.out + untouched.err);
    assert.equal(parseJson(untouched.out).checked, 1);
  });

  it('exits 2 when --receipts points at a package with one edited receipt', () => {
    const { dir, id } = signedGrandchild();
    const exported = parseJson(cli(dir, ['session', 'export', 's-grand', '--json']));
    const packaged = cliResult(dir, ['report', exported.packagePath, '--json']);
    assert.equal(packaged.code, 0, packaged.out + packaged.err);
    const body = parseJson(packaged.out);
    const files = [];
    const walk = (current) => {
      for (const name of readdirSync(current)) {
        const filePath = join(current, name);
        const st = lstatSync(filePath);
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) walk(filePath);
        else if (name.endsWith('.md')) files.push(filePath);
      }
    };
    walk(exported.packagePath);
    const target = files.find((file) => readFileSync(file, 'utf8').includes('A grandchild'));
    assert.ok(target, 'packaged receipt missing the grandchild line');
    editGrandchild(target);
    const checked = cliResult(dir, ['report', 'verify', body.htmlPath, '--receipts', exported.packagePath]);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.ok(checked.err.includes(`receipt ${id} at ${target} fails integrity`), checked.err);
    assert.match(checked.out, /failed: [1-9]/);
    assert.doesNotMatch(checked.out, /^VERIFIED/m);
  });

  it('names CRLF line endings and does not treat them as a match', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'crlf\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'crlf page']);
    const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    const html = readFileSync(htmlPath, 'utf8');
    assert.equal(cliResult(dir, ['report', 'verify', htmlPath]).code, 0);
    const crlfPath = join(dir, 'crlf.report.html');
    writeFileSync(crlfPath, html.replace(/\n/g, '\r\n'));
    const crlf = cliResult(dir, ['report', 'verify', crlfPath]);
    assert.equal(crlf.code, 2, crlf.out + crlf.err);
    assert.match(crlf.err, /page has CRLF line endings/);
    assert.match(crlf.err, /core\.autocrlf/);
    assert.match(crlf.err, /\*\.report\.html -text/);
    assert.doesNotMatch(crlf.out, /^VERIFIED/m);
    const lonePath = join(dir, 'lone-cr.report.html');
    writeFileSync(lonePath, html.replace('CLI', 'CLI\r'));
    const lone = cliResult(dir, ['report', 'verify', lonePath, '--json']);
    assert.equal(lone.code, 2);
    assert.match(parseJson(lone.out).reason, /page has CR line endings/);
    assert.doesNotMatch(parseJson(lone.out).reason, /CRLF/);
  });

  it('exits 2 when a U+FFFD byte is replaced with 0xFF', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'utf8\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'bad\uFFFD byte']);
    const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    assert.equal(cliResult(dir, ['report', 'verify', htmlPath]).code, 0);
    const buf = readFileSync(htmlPath);
    const needle = Buffer.from('\uFFFD', 'utf8');
    const at = buf.indexOf(needle);
    assert.ok(at >= 0);
    const flipped = Buffer.concat([buf.subarray(0, at), Buffer.from([0xff]), buf.subarray(at + needle.length)]);
    const file = join(dir, 'bad-utf8.report.html');
    writeFileSync(file, flipped);
    const checked = cliResult(dir, ['report', 'verify', file, '--json']);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.match(parseJson(checked.out).reason, /not valid UTF-8/);
    assert.notEqual(parseJson(checked.out).verdict, 'VERIFIED');
    const text = cliResult(dir, ['report', 'verify', file]);
    assert.doesNotMatch(text.out, /^VERIFIED/m);
  });

  it('selects the renderer by renderVersion and rejects an unknown version', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'render\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'render version']);
    cli(dir, ['keygen']);
    const made = parseJson(cli(dir, ['report', 'last', '--json']));
    const html = readFileSync(made.htmlPath, 'utf8');
    const payload = payloadOf(html);
    assert.equal(payload.renderVersion, 2);
    payload.renderVersion = 99;
    const keys = loadKeys(dir);
    const signature = createSignatureDocument(reportPayloadHash(payload), keys);
    const payloadRe = /(<script type="application\/json" id="agent-receipt-report">)[\s\S]*?(<\/script>)/;
    const sigRe = /(<script type="application\/json" id="agent-receipt-report-sig">)[\s\S]*?(<\/script>)/;
    const next = html
      .replace(payloadRe, `$1${embedJson(canonicalReportJson(payload))}$2`)
      .replace(sigRe, `$1${embedJson(signature)}$2`);
    const file = join(dir, 'future.report.html');
    writeFileSync(file, next);
    const checked = cliResult(dir, ['report', 'verify', file, '--require-sig', '--json']);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.match(parseJson(checked.out).reason, /unsupported report renderVersion 99/);
    assert.notEqual(parseJson(checked.out).verdict, 'VERIFIED');
    const badPayload = { ...payloadOf(html), renderVersion: 'nope' };
    const badFile = join(dir, 'bad-render.report.html');
    writeFileSync(badFile, html.replace(payloadRe, `$1${embedJson(badPayload)}$2`));
    const bad = cliResult(dir, ['report', 'verify', badFile, '--json']);
    assert.equal(bad.code, 2);
    assert.match(parseJson(bad.out).reason, /report payload renderVersion is invalid/);
  });

  it('notes that --require-sig accepts any valid self-signed page when no trust store is configured', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'trust\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'self signed']);
    cli(dir, ['keygen']);
    const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    const open = cliResult(dir, ['report', 'verify', htmlPath, '--require-sig', '--json']);
    assert.equal(open.code, 0, open.out + open.err);
    assert.equal(parseJson(open.out).verdict, 'VERIFIED');
    assert.match(open.err, /no trust store: --require-sig accepts any valid self-signed page/);
    assert.match(open.err, /trust allowlist/);
    const text = cliResult(dir, ['report', 'verify', htmlPath, '--require-sig']);
    assert.equal(text.code, 0, text.err);
    assert.match(text.err, /no trust store: --require-sig accepts any valid self-signed page/);
    cli(dir, ['trust', 'add', '--self']);
    const pinned = cliResult(dir, ['report', 'verify', htmlPath, '--require-sig']);
    assert.equal(pinned.code, 0, pinned.out + pinned.err);
    assert.doesNotMatch(pinned.err, /accepts any valid self-signed page/);
  });

  it('renders bidi controls visibly, including the agent name', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'bidi\n');
    const agent = 'qa\u202E\u202A\u2066\u200E\u200Fname';
    cli(dir, ['wrap', '--session', 's-bidi', '--agent', agent, '--message', 'bidi\u202Etail']);
    const made = parseJson(cli(dir, ['report', '--session', 's-bidi', '--json']));
    assert.equal(made.exitCode, 0);
    const html = readFileSync(made.htmlPath, 'utf8');
    const visible = visibleHtml(html);
    for (const token of ['\\u202E', '\\u202A', '\\u2066', '\\u200E', '\\u200F']) {
      assert.ok(visible.includes(token), `missing ${token}`);
    }
    for (const ch of ['\u202E', '\u202A', '\u2066', '\u200E', '\u200F']) {
      assert.equal(visible.includes(ch), false);
    }
    assert.match(visible, /qa\\u202E\\u202A\\u2066\\u200E\\u200Fname/);
    assert.match(visible, /agent=qa\\u202E/);
    assert.equal(cliResult(dir, ['report', 'verify', made.htmlPath]).code, 0);
  });

  function copyReceiptPair(src, dest) {
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(src, dest);
    const sig = src.replace(/\.md$/i, '.sig.json');
    if (existsSync(sig)) copyFileSync(sig, dest.replace(/\.md$/i, '.sig.json'));
  }

  function assertCandidateRejected(dir, htmlPath, needle, extraArgs = []) {
    const text = cliResult(dir, ['report', 'verify', htmlPath, ...extraArgs]);
    assert.equal(text.code, 2, `${needle}\n${text.out}\n${text.err}`);
    assert.ok(text.err.includes(needle), text.err);
    assert.match(text.out, /failed: [1-9]/);
    assert.doesNotMatch(text.out, /^VERIFIED/m);
    const json = cliResult(dir, ['report', 'verify', htmlPath, ...extraArgs, '--json']);
    assert.equal(json.code, 2, json.out + json.err);
    const body = parseJson(json.out);
    assert.equal(body.verdict, 'FAILED');
    assert.ok(body.failed >= 1, JSON.stringify(body));
    assert.ok(body.checked + body.skipped + body.failed >= 1);
    assert.ok(body.reason.includes(needle), body.reason);
    return body;
  }

  it('rejects an edited original hidden by an aaa-copy with the same id', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const copy = join(dirname(receipt), 'aaa-copy.md');
    copyReceiptPair(receipt, copy);
    const clean = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(clean.code, 0, clean.out + clean.err);
    assert.equal(parseJson(clean.out).verdict, 'VERIFIED');
    assert.equal(parseJson(clean.out).checked, 1);
    editGrandchild(receipt);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects an edited original hidden by a zzz-copy with the same id', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    copyReceiptPair(receipt, join(dirname(receipt), 'zzz-copy.md'));
    editGrandchild(receipt);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects an edited original hidden by a same-id copy in a subdirectory', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    copyReceiptPair(receipt, join(dirname(receipt), 'sub', 'aaa-copy.md'));
    editGrandchild(receipt);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects --receipts that contains both a genuine file and an edited copy', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const both = join(dir, 'both-receipts');
    const genuine = join(both, 'genuine.md');
    const edited = join(both, 'edited.md');
    copyReceiptPair(receipt, genuine);
    copyReceiptPair(receipt, edited);
    editGrandchild(edited);
    assertCandidateRejected(
      dir,
      made.htmlPath,
      `receipt ${id} at ${edited} fails integrity`,
      ['--receipts', both],
    );
  });

  it('rejects a stray edited same-id copy in a subdirectory', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const stray = join(dirname(receipt), 'nested', 'stray.md');
    copyReceiptPair(receipt, stray);
    editGrandchild(stray);
    assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${stray} fails integrity`);
  });

  it('rejects a same-id receipt from another session', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const other = join(dirname(receipt), 'other-session.md');
    const text = readFileSync(receipt, 'utf8').replace(/^- \*\*Session\*\*: .+$/m, '- **Session**: s-other');
    assert.notEqual(text, readFileSync(receipt, 'utf8'));
    writeFileSync(other, sealReceipt(text));
    assert.equal(cliResult(dir, ['verify', other]).code, 0);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${other} differs from the signed payload`);
  });

  function secretReport(extraReportArgs = []) {
    const dir = initRepo();
    commitFile(dir, 'note.txt', `aws ${AWS}\n`);
    cli(dir, ['keygen']);
    cli(dir, ['wrap', '--sign', '--session', 's-secret', '--agent', 'qa', '--host', 'hostA-secret', '--message', `token ${AWS}`]);
    const made = parseJson(cli(dir, ['report', 'last', ...extraReportArgs, '--json']));
    const receipt = latestReceipt(dir);
    const text = readFileSync(receipt, 'utf8');
    assert.match(text, /^- \*\*Host\*\*: hostA-secret$/m);
    assert.ok(text.includes(AWS), 'expected the AWS key in the receipt');
    const id = payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0].id;
    assert.equal(cliResult(dir, ['report', 'verify', made.htmlPath]).code, 0);
    return { dir, made, receipt, id };
  }

  function replaceOnce(file, from, to) {
    const text = readFileSync(file, 'utf8');
    assert.ok(text.includes(from), `missing ${from} in ${file}`);
    const next = text.replace(from, to);
    assert.notEqual(next, text);
    writeFileSync(file, next);
  }

  it('rejects a host edit that redaction would hide', () => {
    const { dir, made, receipt, id } = secretReport();
    replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
    assert.equal(cliResult(dir, ['verify', receipt]).code, 2);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects an AWS key edit that redaction would hide', () => {
    const { dir, made, receipt, id } = secretReport();
    replaceOnce(receipt, AWS, 'AKIAIOSFODNN7EXAMPLZ');
    assert.equal(cliResult(dir, ['verify', receipt]).code, 2);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects a host edit on an --include-host report', () => {
    const { dir, made, receipt, id } = secretReport(['--include-host', '--out', 'host-kept.report.html']);
    assert.equal(payloadOf(readFileSync(made.htmlPath, 'utf8')).exposure, 'host');
    replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects a host edit on a --no-redact report', () => {
    const { dir, made, receipt, id } = secretReport(['--no-redact', '--out', 'open.report.html']);
    assert.equal(payloadOf(readFileSync(made.htmlPath, 'utf8')).exposure, 'unredacted');
    replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`);
  });

  it('rejects a host edit on a session report', () => {
    const dir = initRepo();
    cli(dir, ['keygen']);
    commitFile(dir, 'parent.txt', 'parent\n');
    const parent = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-sechost', '--agent', 'parent', '--host', 'hostA-secret', '--message', 'parent', '--json']));
    commitFile(dir, 'child.txt', 'child\n');
    cli(dir, ['wrap', '--sign', '--session', 's-sechost', '--parent', parent.path, '--agent', 'child', '--message', 'child']);
    const made = parseJson(cli(dir, ['report', '--session', 's-sechost', '--json']));
    assert.equal(made.verdict, 'VERIFIED');
    const payload = payloadOf(readFileSync(made.htmlPath, 'utf8'));
    assert.equal(payload.manifestSha256, null);
    const hostReceipt = payload.receipts.find((item) => item.id && readFileSync(parent.path, 'utf8').includes(item.id));
    assert.ok(hostReceipt);
    replaceOnce(parent.path, '- **Host**: hostA-secret', '- **Host**: attacker-box');
    assertCandidateRejected(dir, made.htmlPath, `receipt ${hostReceipt.id} at ${parent.path} fails integrity`);
  });

  it('rejects a host edit when --receipts is the local store', () => {
    const { dir, made, receipt, id } = secretReport();
    replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
    const store = join(dir, '.agent-receipt', 'receipts');
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} fails integrity`, ['--receipts', store]);
  });

  it('rejects a host edit in a package checked with --receipts', () => {
    const { dir, id } = secretReport();
    const exported = parseJson(cli(dir, ['session', 'export', 's-secret', '--json']));
    const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
    const files = [];
    const walk = (current) => {
      for (const name of readdirSync(current)) {
        const filePath = join(current, name);
        const st = lstatSync(filePath);
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) walk(filePath);
        else if (name.endsWith('.md')) files.push(filePath);
      }
    };
    walk(exported.packagePath);
    const target = files.find((file) => readFileSync(file, 'utf8').includes('- **Host**: [REDACTED]'));
    assert.ok(target, 'packaged receipt missing the redacted host line');
    replaceOnce(target, '- **Host**: [REDACTED]', '- **Host**: attacker-box');
    assertCandidateRejected(
      dir,
      packaged.htmlPath,
      `receipt ${id} at ${target} fails integrity`,
      ['--receipts', exported.packagePath],
    );
  });

  it('rejects a re-hashed host edit when the sidecar no longer verifies', () => {
    const { dir, made, receipt, id } = secretReport();
    replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
    writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
    assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
    assert.equal(cliResult(dir, ['verify', '--require-sig', receipt]).code, 2);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} signature mismatch`, ['--require-sig']);
  });

  it('prints VERIFIED payload-only when this store never listed the receipt', () => {
    const { made } = signedGrandchild();
    const other = initRepo();
    const html = join(other, 'moved.report.html');
    copyFileSync(made.htmlPath, html);
    assert.ok(made.sigPath);
    copyFileSync(made.sigPath, `${html}.sig.json`);
    const text = cliResult(other, ['report', 'verify', html]);
    assert.equal(text.code, 0, text.out + text.err);
    assert.match(text.out, /^VERIFIED \(payload only; 1 receipts not checked\)  report verify/m);
    assert.doesNotMatch(text.out, /^VERIFIED  report verify/m);
    const json = cliResult(other, ['report', 'verify', html, '--json']);
    assert.equal(json.code, 0, json.out + json.err);
    const body = parseJson(json.out);
    assert.equal(body.verdict, 'VERIFIED_PAYLOAD_ONLY');
    assert.equal(body.notChecked, 1);
    assert.equal(body.skipped, 1);
    assert.equal(body.failed, 0);
    assert.notEqual(body.verdict, 'VERIFIED');
  });

  it('exits 2 when a session report root was deleted but the store still lists it', () => {
    const dir = initRepo();
    commitFile(dir, 'parent.txt', 'parent\n');
    const parent = parseJson(cli(dir, ['wrap', '--session', 's-delroot', '--agent', 'parent', '--message', 'parent', '--json']));
    commitFile(dir, 'child.txt', 'child\n');
    cli(dir, ['wrap', '--session', 's-delroot', '--parent', parent.path, '--agent', 'child', '--message', 'child']);
    cli(dir, ['keygen']);
    const made = parseJson(cli(dir, ['report', '--session', 's-delroot', '--json']));
    assert.equal(made.verdict, 'VERIFIED');
    const payload = payloadOf(readFileSync(made.htmlPath, 'utf8'));
    const root = payload.receipts.find((item) => !item.parent);
    assert.ok(root);
    rmSync(parent.path);
    const checked = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(checked.code, 2, checked.out + checked.err);
    const body = parseJson(checked.out);
    assert.equal(body.verdict, 'FAILED');
    assert.match(body.reason, new RegExp(`receipt ${root.id} is missing but the store index or audit log still lists it`));
    assert.ok(body.failed >= 1);
    const text = cliResult(dir, ['report', 'verify', made.htmlPath]);
    assert.doesNotMatch(text.out, /^VERIFIED/m);
    assert.match(text.out, /failed: [1-9]/);
  });

  it('rejects a symlink swapped in for a receipt', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const target = join(dirname(receipt), 'symlink-target.md');
    copyReceiptPair(receipt, target);
    rmSync(receipt);
    symlinkSync(target, receipt);
    assert.equal(lstatSync(receipt).isSymbolicLink(), true);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${receipt} is a symlink`);
  });

  it('treats a .MD case rename as a candidate', () => {
    const { dir, made, receipt, id } = signedGrandchild();
    const upper = receipt.replace(/\.md$/, '.MD');
    assert.notEqual(upper, receipt);
    renameSync(receipt, upper);
    const clean = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
    assert.equal(clean.code, 0, clean.out + clean.err);
    assert.equal(parseJson(clean.out).verdict, 'VERIFIED');
    assert.equal(parseJson(clean.out).checked, 1);
    assert.equal(parseJson(clean.out).skipped, 0);
    editGrandchild(upper);
    assertCandidateRejected(dir, made.htmlPath, `receipt ${id} at ${upper} fails integrity`);
  });

  it('verifies an imported package report against the imported receipt', () => {
    const src = initRepo();
    commitFile(src, 'note.txt', `host ${HOST}\n`);
    cli(src, ['keygen']);
    cli(src, ['wrap', '--session', 's-import', '--agent', 'exporter', '--host', HOST, '--message', 'importer body']);
    const exported = parseJson(cli(src, ['session', 'export', 's-import', '--json']));
    const packaged = parseJson(cli(src, ['report', exported.packagePath, '--json']));
    assert.equal(packaged.verdict, 'VERIFIED');
    const dest = initRepo();
    const imported = cliResult(dest, ['session', 'import', exported.packagePath]);
    assert.equal(imported.code, 0, imported.out + imported.err);
    const checked = cliResult(dest, ['report', 'verify', packaged.htmlPath, '--json']);
    assert.equal(checked.code, 0, checked.out + checked.err);
    const body = parseJson(checked.out);
    assert.equal(body.verdict, 'VERIFIED');
    assert.equal(body.checked, 1);
    assert.equal(body.skipped, 0);
    assert.equal(body.failed, 0);
  });

  it('verifies a portable package with --receipts and payload-only without it', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', `host ${HOST}\n`);
    cli(dir, ['keygen']);
    cli(dir, ['wrap', '--session', 's-port', '--agent', 'exporter', '--host', HOST, '--message', 'portable body']);
    const exported = parseJson(cli(dir, ['session', 'export', 's-port', '--json']));
    const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
    const away = initRepo();
    const withPkg = cliResult(away, ['report', 'verify', packaged.htmlPath, '--receipts', exported.packagePath, '--json']);
    assert.equal(withPkg.code, 0, withPkg.out + withPkg.err);
    assert.equal(parseJson(withPkg.out).verdict, 'VERIFIED');
    assert.equal(parseJson(withPkg.out).checked, 1);
    const html = join(away, 'portable.report.html');
    copyFileSync(packaged.htmlPath, html);
    assert.ok(packaged.sigPath);
    copyFileSync(packaged.sigPath, `${html}.sig.json`);
    const alone = cliResult(away, ['report', 'verify', html, '--json']);
    assert.equal(alone.code, 0, alone.out + alone.err);
    const body = parseJson(alone.out);
    assert.equal(body.verdict, 'VERIFIED_PAYLOAD_ONLY');
    assert.equal(body.notChecked, 1);
    const text = cliResult(away, ['report', 'verify', html]);
    assert.match(text.out, /^VERIFIED \(payload only; 1 receipts not checked\)  report verify/m);
    assert.doesNotMatch(text.out, /^VERIFIED  report verify/m);
  });

  it('rejects a leading UTF-8 BOM', () => {
    const dir = initRepo();
    commitFile(dir, 'note.txt', 'bom\n');
    cli(dir, ['wrap', '--agent', 'ci', '--message', 'bom page']);
    const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
    const bomPath = join(dir, 'bom.report.html');
    writeFileSync(bomPath, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), readFileSync(htmlPath)]));
    const checked = cliResult(dir, ['report', 'verify', bomPath, '--json']);
    assert.equal(checked.code, 2, checked.out + checked.err);
    assert.match(parseJson(checked.out).reason, /page starts with a UTF-8 BOM/);
    assert.notEqual(parseJson(checked.out).verdict, 'VERIFIED');
    const text = cliResult(dir, ['report', 'verify', bomPath]);
    assert.equal(text.code, 2);
    assert.doesNotMatch(text.out, /^VERIFIED/m);
  });
});
