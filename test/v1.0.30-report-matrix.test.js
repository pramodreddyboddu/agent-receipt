/**
 * Table-driven Release QA matrix for report verify, gates 88dad95, 985e363,
 * 74bca3d, and b9c376a. Tamper rows must exit 2 and must not print a
 * VERIFIED headline. Genuine rows must exit 0, including payload-only.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cpSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { publishRedactedReceipt } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const LINK_ENV = [
  'AGENT_RECEIPT_SESSION',
  'AGENT_RECEIPT_PARENT',
  'AGENT_RECEIPT_AGENT',
  'AGENT_RECEIPT_HOST',
];
const AWS = 'AKIAIOSFODNN7EXAMPLE';
const HOST = 'planted-host.example';
const PAGE_MISMATCH = 'page content does not match signed payload';
const PRUNE_NOTE = 'receipt absent; audit.jsonl (unsigned) records a prune';
const PRUNE_WARN = 'audit.jsonl is unsigned; no retention config and no recorded prune command';
const dirs = [];

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

function initRepo(slug) {
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

function scriptBlock(html, id) {
  const match = html.match(new RegExp(`<script type="application\\/json" id="${id}">[\\s\\S]*?<\\/script>`));
  assert.ok(match, `${id} missing`);
  return match[0];
}

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

function sealReceipt(markdown) {
  const body = canonicalBodyOf(markdown);
  const hash = createHash('sha256').update(body, 'utf8').digest('hex');
  return `${body}\n## Integrity\n\n<!-- agent-receipt-sha256:${hash} -->\n\nSHA-256 of canonical body: \`${hash}\`\n`;
}

function copyReceiptPair(src, dest) {
  mkdirSync(dirname(dest), { recursive: true });
  copyFileSync(src, dest);
  const sig = src.replace(/\.md$/i, '.sig.json');
  if (existsSync(sig)) copyFileSync(sig, dest.replace(/\.md$/i, '.sig.json'));
}

function replaceOnce(file, from, to) {
  const text = readFileSync(file, 'utf8');
  assert.ok(text.includes(from), `missing ${from} in ${file}`);
  const next = text.replace(from, to);
  assert.notEqual(next, text);
  writeFileSync(file, next);
}

function verifyCall(dir, args) {
  const human = cliResult(dir, args);
  const json = cliResult(dir, [...args, '--json']);
  let body = null;
  try {
    body = parseJson(json.out);
  } catch {
    body = null;
  }
  return { human, json, body };
}

function assertCode(got, code, label) {
  assert.equal(got.human.code, code, `${label} human\n${got.human.out}\n${got.human.err}`);
  assert.equal(got.json.code, code, `${label} json\n${got.json.out}\n${got.json.err}`);
}

/** Tamper: exit 2, and the human headline is not VERIFIED. */
function assertTamper(dir, args, label, reason) {
  const got = verifyCall(dir, args);
  assertCode(got, 2, label);
  assert.doesNotMatch(got.human.out, /^VERIFIED/m, `${label}\n${got.human.out}`);
  assert.notEqual(got.body?.verdict, 'VERIFIED');
  assert.notEqual(got.body?.verdict, 'VERIFIED_PAYLOAD_ONLY');
  if (reason) assert.match(got.body?.reason ?? got.human.err, reason, `${label}\n${got.json.out}\n${got.human.err}`);
  return got;
}

function assertPayloadOnly(dir, args, label, note) {
  const got = verifyCall(dir, args);
  assertCode(got, 0, label);
  assert.equal(got.body.verdict, 'VERIFIED_PAYLOAD_ONLY', `${label}\n${got.json.out}`);
  assert.match(got.human.out, /^VERIFIED \(payload only; .+ receipts not checked/m, got.human.out);
  assert.doesNotMatch(got.human.out, /^VERIFIED  report verify/m, got.human.out);
  assert.equal(got.body.failed, 0);
  if (note) {
    const blob = `${got.human.out}\n${got.human.err}\n${got.json.out}`;
    assert.match(blob, note, blob);
  }
  return got;
}

function assertVerified(dir, args, label) {
  const got = verifyCall(dir, args);
  assertCode(got, 0, label);
  assert.equal(got.body.verdict, 'VERIFIED', `${label}\n${got.json.out}`);
  assert.match(got.human.out, /^VERIFIED  report verify/m, got.human.out);
  assert.equal(got.body.failed, 0);
  return got;
}

function writePage(dir, html, label) {
  const file = join(dir, `${label}.report.html`);
  writeFileSync(file, html);
  return file;
}

function expectPageReject(dir, html, label) {
  const file = writePage(dir, html, label);
  for (const extra of [[], ['--require-sig']]) {
    assertTamper(dir, ['report', 'verify', file, ...extra], label, new RegExp(PAGE_MISMATCH));
  }
}

function expectStructureReject(dir, html, label, reason) {
  const file = writePage(dir, html, label);
  for (const extra of [[], ['--require-sig']]) {
    assertTamper(dir, ['report', 'verify', file, ...extra], label, reason);
  }
}

let unsignedPage;
function unsignedFixture() {
  if (unsignedPage) return unsignedPage;
  const dir = initRepo('matrix-unsigned-');
  commitFile(dir, 'note.txt', 'b1\n');
  cli(dir, ['wrap', '--agent', 'ci', '--message', 'unsigned banner']);
  const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
  unsignedPage = { dir, html: readFileSync(htmlPath, 'utf8'), htmlPath };
  return unsignedPage;
}

let narrativePage;
function narrativeFixture() {
  if (narrativePage) return narrativePage;
  const dir = initRepo('matrix-narrative-');
  git(dir, ['checkout', '-b', 'b2-branch']);
  commitFile(dir, 'b2-file.txt', 'b2-diff-token\n', 'b2-commit-token');
  cli(dir, ['wrap', '--base', 'HEAD~1', '--full', '--session', 's-b2page', '--agent', 'b2-agent', '--message', 'b2-message-token']);
  cli(dir, ['keygen']);
  cli(dir, ['trust', 'add', '--self']);
  const made = parseJson(cli(dir, ['report', '--session', 's-b2page', '--json']));
  assert.equal(made.verdict, 'VERIFIED');
  const html = readFileSync(made.htmlPath, 'utf8');
  const fp = html.match(/<p>Fingerprint: <code>([0-9a-f]{64})<\/code><\/p>/);
  assert.ok(fp, 'fingerprint line missing');
  narrativePage = { dir, html, fp: fp[1] };
  return narrativePage;
}

let unredactedPage;
function unredactedFixture() {
  if (unredactedPage) return unredactedPage;
  const dir = initRepo('matrix-unredacted-');
  commitFile(dir, 'note.txt', 'b4\n');
  cli(dir, ['wrap', '--host', HOST, '--agent', 'ci', '--message', 'show host']);
  const made = parseJson(cli(dir, ['report', 'last', '--include-host', '--json']));
  const html = readFileSync(made.htmlPath, 'utf8');
  const marker = html.match(/<div class="banner unredacted" role="status">[\s\S]*?<\/div>/);
  assert.ok(marker, 'expected a visible UNREDACTED banner');
  unredactedPage = { dir, html, marker: marker[0] };
  return unredactedPage;
}

function signedGrandchild() {
  const dir = initRepo('matrix-grand-');
  commitFile(dir, 'note.txt', 'grandchild\n');
  cli(dir, ['wrap', '--session', 's-grand', '--agent', 'qa', '--message', 'A grandchild']);
  cli(dir, ['keygen']);
  const made = parseJson(cli(dir, ['report', 'last', '--json']));
  const receipt = latestReceipt(dir);
  const id = payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0].id;
  return { dir, made, receipt, id };
}

function editGrandchild(receipt) {
  replaceOnce(receipt, 'A grandchild', 'A grandchild (edited)');
}

function secretReport(extraReportArgs = []) {
  const dir = initRepo('matrix-secret-');
  commitFile(dir, 'note.txt', `aws ${AWS}\n`);
  cli(dir, ['keygen']);
  cli(dir, ['wrap', '--sign', '--session', 's-secret', '--agent', 'qa', '--host', 'hostA-secret', '--message', `token ${AWS}`]);
  const made = parseJson(cli(dir, ['report', 'last', ...extraReportArgs, '--json']));
  const receipt = latestReceipt(dir);
  const id = payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0].id;
  return { dir, made, receipt, id };
}

function packageFiles(dir) {
  const files = [];
  const walk = (current) => {
    for (const name of readdirSync(current)) {
      const filePath = join(current, name);
      const st = lstatSync(filePath);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(filePath);
      else if (name.endsWith('.md') || name.endsWith('.MD') || name.endsWith('.Md')) files.push(filePath);
    }
  };
  walk(dir);
  return files;
}

/** Signed session whose export redacts Host, so imported bytes are redactedSha256. */
function exporterSession() {
  const dir = initRepo('matrix-export-');
  cli(dir, ['keygen']);
  commitFile(dir, 'parent.txt', 'parent\n');
  const parent = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-imp', '--agent', 'parent', '--host', HOST, '--message', 'parent body', '--json']));
  commitFile(dir, 'child.txt', 'child\n');
  const child = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-imp', '--parent', parent.path, '--agent', 'child', '--host', HOST, '--message', 'child body', '--json']));
  commitFile(dir, 'grand.txt', 'grand\n');
  cli(dir, ['wrap', '--sign', '--session', 's-imp', '--parent', child.path, '--agent', 'grand', '--host', HOST, '--message', 'grand body']);
  // `report <pkg>.session` writes `<id>.report.html` beside outDir, the same
  // default path as `report --session`. Keep the local page on its own --out.
  const sessionReport = parseJson(cli(dir, ['report', '--session', 's-imp', '--out', join(dir, 'A-session.report.html'), '--json']));
  const single = parseJson(cli(dir, ['report', parent.path, '--out', join(dir, 'A-single.report.html'), '--json']));
  const sessionPayload = payloadOf(readFileSync(sessionReport.htmlPath, 'utf8'));
  assert.equal(sessionPayload.manifestSha256, null);
  assert.equal(sessionPayload.receipts.length, 3);
  assert.ok(sessionPayload.receipts.every((item) => item.redactedSha256), 'local session report must record redactedSha256');
  const exported = parseJson(cli(dir, ['session', 'export', 's-imp', '--json']));
  const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--out', join(dir, 'A-package.report.html'), '--json']));
  const packagePayload = payloadOf(readFileSync(packaged.htmlPath, 'utf8'));
  assert.ok(packagePayload.receipts.every((item) => item.originalFingerprint), 'package report must record originalFingerprint');
  return { dir, parent, sessionReport, single, exported, packaged };
}

function signedPackageAttack() {
  const dir = initRepo('matrix-b3-');
  commitFile(dir, 'note.txt', `aws ${AWS}\n`);
  cli(dir, ['keygen']);
  cli(dir, ['wrap', '--sign', '--session', 's-b3', '--agent', 'qa', '--host', 'hostA-secret', '--message', `token ${AWS}`]);
  const receipt = latestReceipt(dir);
  const exported = parseJson(cli(dir, ['session', 'export', 's-b3', '--json']));
  const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
  const payload = payloadOf(readFileSync(packaged.htmlPath, 'utf8'));
  const receiptPayload = payload.receipts[0];
  assert.ok(receiptPayload.originalFingerprint, 'originalFingerprint must be set for the stripped-sig attack');
  return { dir, receipt, exported, packaged, id: receiptPayload.id, originalFingerprint: receiptPayload.originalFingerprint };
}

function signedOne(slug) {
  const dir = initRepo(`matrix-${slug}-`);
  cli(dir, ['keygen']);
  commitFile(dir, 'note.txt', `${slug}\n`);
  cli(dir, ['wrap', '--sign', '--message', slug]);
  const made = parseJson(cli(dir, ['report', 'last', '--json']));
  const receipt = latestReceipt(dir);
  const payload = payloadOf(readFileSync(made.htmlPath, 'utf8'));
  return { dir, made, receipt, id: payload.receipts[0].id, sha256: payload.receipts[0].sha256, payload };
}

function payloadId(made) {
  return payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0].id;
}

function removeReceipt(file) {
  rmSync(file, { force: true });
  for (const suffix of ['.sig.json', '.json']) {
    const side = file.replace(/\.md$/i, suffix);
    if (existsSync(side)) rmSync(side);
  }
}

function auditLines(dir) {
  const auditPath = join(dir, '.agent-receipt', 'audit.jsonl');
  if (!existsSync(auditPath)) return [];
  return readFileSync(auditPath, 'utf8')
    .split('\n')
    .filter((line) => line.length > 0);
}

function appendAuditLine(dir, fields) {
  const lines = auditLines(dir);
  const prev = lines.length
    ? createHash('sha256').update(`${lines[lines.length - 1]}\n`, 'utf8').digest('hex')
    : null;
  const event = {
    ts: fields.ts,
    event: fields.event,
    version: fields.version || '1.0.30',
    experimental: true,
    path: fields.path,
    sha256: fields.sha256 ?? null,
    agent: null,
    redacted: false,
    verified: true,
    failedOn: false,
    exitCode: 0,
    prev,
  };
  const line = JSON.stringify(event);
  writeFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), `${lines.concat(line).join('\n')}\n`);
  return event;
}

function relFrom(dir, file) {
  return file.slice(dir.length + 1).split('\\').join('/');
}

/** Sign `file` with a key that is not the repo's key. Returns the sidecar path in `dir`. */
function sidecarFromOtherKey(dir, file) {
  const other = initRepo('matrix-other-key-');
  cli(other, ['keygen']);
  const destDir = join(other, '.agent-receipt', 'receipts');
  mkdirSync(destDir, { recursive: true });
  const dest = join(destDir, 'other.md');
  copyFileSync(file, dest);
  const signed = cliResult(other, ['sign', dest]);
  assert.equal(signed.code, 0, signed.out + signed.err);
  const sig = dest.replace(/\.md$/i, '.sig.json');
  assert.ok(existsSync(sig), 'other key sidecar missing');
  const back = file.replace(/\.md$/i, '.sig.json');
  copyFileSync(sig, back);
  return back;
}

function autocrlfClone(attributes) {
  const dir = initRepo('matrix-autocrlf-');
  cli(dir, ['keygen']);
  commitFile(dir, 'note.txt', 'autocrlf\n');
  cli(dir, ['wrap', '--sign', '--session', 's-crlf', '--agent', 'qa', '--message', 'autocrlf session']);
  const made = parseJson(cli(dir, ['report', '--session', 's-crlf', '--out', 'docs-s.report.html', '--json']));
  assert.equal(made.verdict, 'VERIFIED');
  writeFileSync(join(dir, '.gitattributes'), attributes);
  git(dir, ['config', 'core.autocrlf', 'false']);
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-m', 'signed report']);
  const clone = mkdtempSync(join(tmpdir(), 'matrix-autocrlf-clone-'));
  dirs.push(clone);
  execFileSync('git', ['clone', '-c', 'core.autocrlf=true', dir, clone], { encoding: 'utf8' });
  return { dir, clone, html: join(clone, 'docs-s.report.html') };
}

const NARRATIVE = [
  ['agent', '<th scope="row">Agent</th><td>b2-agent</td>', '<th scope="row">Agent</th><td>other-agent</td>'],
  ['verified-pill', '<th scope="row">Verified</th><td><span class="pill ok">yes</span>', '<th scope="row">Verified</th><td><span class="pill ok">no</span>'],
  ['trust-pill', '<th scope="row">Trust</th><td><span class="pill mid">UNSIGNED</span>', '<th scope="row">Trust</th><td><span class="pill ok">TRUSTED</span>'],
  ['status', 'Report signature: present (trusted)', 'Report signature: present (untrusted)'],
  ['banner-class', '<div class="banner verified"', '<div class="banner failed"'],
  ['title', '<title>Agent Receipt report — VERIFIED</title>', '<title>Agent Receipt report — FAILED</title>'],
  ['branch', '<th scope="row">Branch</th><td><code>b2-branch</code>', '<th scope="row">Branch</th><td><code>other-branch</code>'],
  ['message', '<th scope="row">Message</th><td>b2-message-token</td>', '<th scope="row">Message</th><td>other-message</td>'],
  ['files', 'b2-file.txt', 'other-file.txt'],
  ['diff', 'b2-diff-token', 'other-diff-token'],
  ['commits', 'b2-commit-token', 'other-commit-token'],
  ['risk', 'No risk findings.', 'Risk was cleared.'],
  ['tree', 'session s-b2page', 'session s-other'],
];

const CASES = [
  {
    id: 'hidden-verdict-banner-pills-title',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      let attacked = mutateVisible(html, '<body>\n', '<body>\n<span hidden data-covered="verdict">FAILED</span>\n');
      attacked = mutateVisible(attacked, '<div class="banner unsigned"', '<div class="banner verified"');
      attacked = mutateVisible(attacked, '<div class="verdict">UNSIGNED</div>', '<div class="verdict">VERIFIED</div>');
      attacked = mutateVisible(attacked, '<title>Agent Receipt report — UNSIGNED</title>', '<title>Agent Receipt report — VERIFIED</title>');
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
      expectPageReject(dir, attacked, 'hidden-verdict');
    },
  },
  {
    id: 'fingerprint-line',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html, fp } = narrativeFixture();
      const flipped = fp.slice(0, -1) + (fp.endsWith('a') ? 'b' : 'a');
      expectPageReject(
        dir,
        mutateVisible(html, `<p>Fingerprint: <code>${fp}</code></p>`, `<p>Fingerprint: <code>${flipped}</code></p>`),
        'fingerprint',
      );
    },
  },
  {
    id: 'sig-line',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = narrativeFixture();
      expectPageReject(
        dir,
        mutateVisible(html, 'Report signature: present (trusted)', 'Report signature: present (untrusted)'),
        'sig-line',
      );
    },
  },
  ...NARRATIVE.map(([name, from, to]) => ({
    id: `narrative-${name}`,
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = narrativeFixture();
      expectPageReject(dir, mutateVisible(html, from, to), `narrative-${name}`);
    },
  })),
  {
    id: 'payload-in-comment',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      const payload = scriptBlock(html, 'agent-receipt-report');
      const forged = '<script type="application/json" id="agent-receipt-report">{"forged":true}</script>';
      expectStructureReject(dir, html.replace(payload, `<!-- ${payload} -->\n${forged}`), 'comment-payload', /report payload block is inside a comment/);
    },
  },
  {
    id: 'duplicate-payload',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      const payload = scriptBlock(html, 'agent-receipt-report');
      const forged = '<script type="application/json" id="agent-receipt-report">{"forged":true}</script>';
      expectStructureReject(dir, html.replace(payload, `${payload}\n${forged}`), 'duplicate-payload', /report has more than one payload block/);
    },
  },
  {
    id: 'duplicate-sig',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      const signature = scriptBlock(html, 'agent-receipt-report-sig');
      expectStructureReject(dir, html.replace(signature, `${signature}\n${signature}`), 'duplicate-sig', /report has more than one signature block/);
    },
  },
  {
    id: 'unredacted-comment',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html, marker } = unredactedFixture();
      expectPageReject(dir, html.replace(marker, '<!-- UNREDACTED -->'), 'unredacted-comment');
    },
  },
  {
    id: 'unredacted-hidden',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html, marker } = unredactedFixture();
      expectPageReject(dir, html.replace(marker, '<p hidden>UNREDACTED</p>'), 'unredacted-hidden');
    },
  },
  {
    id: 'unredacted-stripped',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html, marker } = unredactedFixture();
      expectPageReject(dir, html.replace(marker, ''), 'unredacted-stripped');
    },
  },
  {
    id: 'tampered-session-root',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-root-');
      commitFile(dir, 'parent.txt', 'parent\n');
      const parent = parseJson(cli(dir, ['wrap', '--session', 's-rootfail', '--agent', 'parent', '--message', 'parent', '--json']));
      commitFile(dir, 'child.txt', 'child\n');
      cli(dir, ['wrap', '--session', 's-rootfail', '--parent', parent.path, '--agent', 'child', '--message', 'child']);
      cli(dir, ['keygen']);
      const good = parseJson(cli(dir, ['report', '--session', 's-rootfail', '--json']));
      const rootId = payloadOf(readFileSync(good.htmlPath, 'utf8')).receipts.find((item) => !item.parent).id;
      const original = readFileSync(parent.path, 'utf8');
      writeFileSync(parent.path, original.replace(/agent-receipt-sha256:[0-9a-f]{64}/, (hex) => hex.replace(/[0-9a-f]$/, (ch) => (ch === 'a' ? 'b' : 'a'))));
      const made = cliResult(dir, ['report', '--session', 's-rootfail', '--json']);
      assert.equal(made.code, 2, made.out + made.err);
      assert.match(parseJson(made.out).reason, new RegExp(`session root ${rootId} failed verification`));
      assertTamper(dir, ['report', 'verify', parseJson(made.out).htmlPath], 'session-root', new RegExp(rootId));
    },
  },
  {
    id: 'failed-verdict',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-failed-');
      commitFile(dir, 'note.txt', 'policy\n');
      cli(dir, ['wrap', '--agent', 'ci', '--message', 'policy']);
      const receipt = latestReceipt(dir);
      const bad = join(dir, 'bad-policy.md');
      writeFileSync(bad, readFileSync(receipt, 'utf8').replace(/agent-receipt-sha256:[0-9a-f]{64}/, (hex) => hex.replace(/[0-9a-f]$/, (ch) => (ch === 'a' ? 'b' : 'a'))));
      const failed = cliResult(dir, ['report', bad, '--out', join(dir, 'failed-policy.report.html'), '--json']);
      assert.equal(failed.code, 2);
      assert.equal(parseJson(failed.out).verdict, 'FAILED');
      const got = assertTamper(dir, ['report', 'verify', parseJson(failed.out).htmlPath], 'failed-verdict');
      assert.match(got.human.out, /^FAILED  report verify/m);
    },
  },
  {
    id: 'untrusted-verdict',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-untrusted-');
      commitFile(dir, 'note.txt', 'policy\n');
      cli(dir, ['wrap', '--agent', 'ci', '--message', 'policy']);
      cli(dir, ['keygen']);
      cli(dir, ['trust', 'add', 'ab'.repeat(32)]);
      const untrusted = cliResult(dir, ['report', 'last', '--json']);
      assert.equal(untrusted.code, 0, untrusted.out + untrusted.err);
      assert.equal(parseJson(untrusted.out).verdict, 'UNTRUSTED');
      const got = assertTamper(dir, ['report', 'verify', parseJson(untrusted.out).htmlPath, '--require-sig'], 'untrusted');
      assert.match(got.human.out, /^UNTRUSTED  report verify/m);
      assert.equal(got.body.verdict, 'UNTRUSTED');
    },
  },
  {
    id: 'receipts-dir-missing',
    gate: '88dad95',
    kind: 'usage',
    run() {
      const { dir, htmlPath } = unsignedFixture();
      const missing = cliResult(dir, ['report', 'verify', htmlPath, '--receipts', join(dir, 'no-such-receipts')]);
      assert.equal(missing.code, 1, missing.out + missing.err);
      assert.match(missing.err, /--receipts directory not found/);
      assert.doesNotMatch(missing.out, /^VERIFIED/m);
    },
  },
  {
    id: 'receipts-dir-not-directory',
    gate: '88dad95',
    kind: 'usage',
    run() {
      const { dir, htmlPath } = unsignedFixture();
      const notDir = join(dir, 'not-a-receipts-dir');
      writeFileSync(notDir, 'x\n');
      const fileDir = cliResult(dir, ['report', 'verify', htmlPath, '--receipts', notDir]);
      assert.equal(fileDir.code, 1, fileDir.out + fileDir.err);
      assert.match(fileDir.err, /--receipts is not a directory/);
      assert.doesNotMatch(fileDir.out, /^VERIFIED/m);
    },
  },
  {
    id: 'schema-invalid-payload',
    gate: '88dad95',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      const match = html.match(/<script type="application\/json" id="agent-receipt-report">([\s\S]*?)<\/script>/);
      const obj = JSON.parse(match[1]);
      delete obj.title;
      const encoded = JSON.stringify(obj).replace(/&/g, '\\u0026').replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
      expectStructureReject(dir, html.replace(match[1], encoded), 'schema-title', /report payload title is missing/);
      expectStructureReject(dir, html.replace(match[1], '{'), 'schema-json', /embedded report payload is malformed JSON/);
    },
  },
  {
    id: 'in-place-edit',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      editGrandchild(receipt);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'in-place', new RegExp(`receipt ${id} at ${receipt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} fails integrity`));
    },
  },
  {
    id: 'rehash-after-tamper',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      editGrandchild(receipt);
      writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'rehash', new RegExp(`receipt ${id} .* differs from the signed payload`));
    },
  },
  {
    id: 'deleted-with-receipts',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const copyDir = join(dir, 'receipts-copy');
      mkdirSync(copyDir);
      const copy = join(copyDir, basename(receipt));
      copyFileSync(receipt, copy);
      rmSync(copy);
      assertTamper(dir, ['report', 'verify', made.htmlPath, '--receipts', copyDir], 'deleted-receipts', new RegExp(`receipt ${id} referenced by report not found in --receipts`));
    },
  },
  {
    id: 'deleted-still-listed',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      rmSync(receipt);
      const got = assertTamper(dir, ['report', 'verify', made.htmlPath], 'still-listed', new RegExp(`receipt ${id} is missing but the store index or audit log still lists it`));
      assert.ok(got.body.failed >= 1);
      assert.match(got.human.out, /failed: [1-9]/);
    },
  },
  {
    id: 'copied-dir-one-edited',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const copyDir = join(dir, 'receipts-copy');
      mkdirSync(copyDir);
      const copy = join(copyDir, basename(receipt));
      copyFileSync(receipt, copy);
      editGrandchild(copy);
      assertTamper(dir, ['report', 'verify', made.htmlPath, '--receipts', copyDir], 'copied-dir', new RegExp(`fails integrity`));
      assert.ok(verifyCall(dir, ['report', 'verify', made.htmlPath, '--receipts', copyDir]).human.err.includes(id));
    },
  },
  {
    id: 'package-one-edited',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, id } = signedGrandchild();
      const exported = parseJson(cli(dir, ['session', 'export', 's-grand', '--json']));
      const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
      const target = packageFiles(exported.packagePath).find((file) => readFileSync(file, 'utf8').includes('A grandchild'));
      assert.ok(target);
      editGrandchild(target);
      assertTamper(dir, ['report', 'verify', packaged.htmlPath, '--receipts', exported.packagePath], 'package-edited', /fails integrity/);
    },
  },
  {
    id: 'crlf',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, html, htmlPath } = unsignedFixture();
      assert.equal(cliResult(dir, ['report', 'verify', htmlPath]).code, 0);
      const file = writePage(dir, html.replace(/\n/g, '\r\n'), 'crlf');
      const got = assertTamper(dir, ['report', 'verify', file], 'crlf', /page has CRLF line endings/);
      assert.match(got.body.reason, /core\.autocrlf/);
      assert.match(got.body.reason, /\*\.report\.html -text/);
    },
  },
  {
    id: 'lone-cr',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      const file = writePage(dir, html.replace('CLI', 'CLI\r'), 'lone-cr');
      const got = assertTamper(dir, ['report', 'verify', file], 'lone-cr', /page has CR line endings/);
      assert.doesNotMatch(got.body.reason, /CRLF/);
    },
  },
  {
    id: 'mixed-cr-crlf',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, html } = unsignedFixture();
      const file = writePage(dir, html.replace('\n', '\r\n').replace('CLI', 'CLI\r'), 'mixed-cr');
      const got = assertTamper(dir, ['report', 'verify', file], 'mixed-cr', /page has CR line endings/);
      assert.match(got.body.reason, /page has CRLF line endings/);
    },
  },
  {
    id: 'invalid-utf8',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-utf8-');
      commitFile(dir, 'note.txt', 'utf8\n');
      cli(dir, ['wrap', '--agent', 'ci', '--message', 'bad\uFFFD byte']);
      const htmlPath = parseJson(cli(dir, ['report', 'last', '--json'])).htmlPath;
      const buf = readFileSync(htmlPath);
      const needle = Buffer.from('\uFFFD', 'utf8');
      const at = buf.indexOf(needle);
      assert.ok(at >= 0);
      const flipped = Buffer.concat([buf.subarray(0, at), Buffer.from([0xff]), buf.subarray(at + needle.length)]);
      const file = join(dir, 'bad-utf8.report.html');
      writeFileSync(file, flipped);
      assertTamper(dir, ['report', 'verify', file], 'utf8', /not valid UTF-8/);
    },
  },
  {
    id: 'bom',
    gate: '985e363',
    kind: 'tamper',
    run() {
      const { dir, htmlPath } = unsignedFixture();
      const bomPath = join(dir, 'bom.report.html');
      writeFileSync(bomPath, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), readFileSync(htmlPath)]));
      assertTamper(dir, ['report', 'verify', bomPath], 'bom', /page starts with a UTF-8 BOM/);
    },
  },
  {
    id: 'aaa-copy',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      copyReceiptPair(receipt, join(dirname(receipt), 'aaa-copy.md'));
      editGrandchild(receipt);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'aaa-copy', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'zzz-copy',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      copyReceiptPair(receipt, join(dirname(receipt), 'zzz-copy.md'));
      editGrandchild(receipt);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'zzz-copy', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'subdir-copy',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      copyReceiptPair(receipt, join(dirname(receipt), 'sub', 'aaa-copy.md'));
      editGrandchild(receipt);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'subdir-copy', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'receipts-genuine-plus-edited',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const both = join(dir, 'both-receipts');
      copyReceiptPair(receipt, join(both, 'genuine.md'));
      copyReceiptPair(receipt, join(both, 'edited.md'));
      editGrandchild(join(both, 'edited.md'));
      assertTamper(dir, ['report', 'verify', made.htmlPath, '--receipts', both], 'both', new RegExp(`receipt ${id} at .*edited\\.md fails integrity`));
    },
  },
  {
    id: 'stray-subdir',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const stray = join(dirname(receipt), 'nested', 'stray.md');
      copyReceiptPair(receipt, stray);
      editGrandchild(stray);
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'stray', new RegExp(`receipt ${id} at .*stray\\.md fails integrity`));
    },
  },
  {
    id: 'other-session-same-id',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const other = join(dirname(receipt), 'other-session.md');
      const text = readFileSync(receipt, 'utf8').replace(/^- \*\*Session\*\*: .+$/m, '- **Session**: s-other');
      writeFileSync(other, sealReceipt(text));
      assert.equal(cliResult(dir, ['verify', other]).code, 0);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'other-session', new RegExp(`receipt ${id} at .* differs from the signed payload`));
    },
  },
  {
    id: 'dot-MD',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const upper = receipt.replace(/\.md$/, '.MD');
      copyReceiptPair(receipt, upper);
      rmSync(receipt);
      const sig = receipt.replace(/\.md$/, '.sig.json');
      if (existsSync(sig)) rmSync(sig);
      editGrandchild(upper);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'dot-MD', new RegExp(`receipt ${id} at .*\\.MD fails integrity`));
    },
  },
  {
    id: 'dot-Md',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const mixed = receipt.replace(/\.md$/, '.Md');
      copyReceiptPair(receipt, mixed);
      rmSync(receipt);
      editGrandchild(mixed);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'dot-Md', new RegExp(`receipt ${id} at .*\\.Md fails integrity`));
    },
  },
  {
    id: 'dotfile',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const hidden = join(dirname(receipt), '.hidden.md');
      copyReceiptPair(receipt, hidden);
      editGrandchild(hidden);
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'dotfile', new RegExp(`receipt ${id} at .*\\.hidden\\.md fails integrity`));
    },
  },
  {
    id: 'symlink',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = signedGrandchild();
      const target = join(dirname(receipt), 'symlink-target.md');
      copyReceiptPair(receipt, target);
      rmSync(receipt);
      symlinkSync(target, receipt);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'symlink', new RegExp(`receipt ${id} at .* is a symlink`));
    },
  },
  {
    id: 'host-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'host-edit', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'aws-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      replaceOnce(receipt, AWS, 'AKIAIOSFODNN7EXAMPLZ');
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'aws-edit', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'include-host-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport(['--include-host', '--out', 'host-kept.report.html']);
      assert.equal(payloadOf(readFileSync(made.htmlPath, 'utf8')).exposure, 'host');
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'include-host', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'no-redact-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport(['--no-redact', '--out', 'open.report.html']);
      assert.equal(payloadOf(readFileSync(made.htmlPath, 'utf8')).exposure, 'unredacted');
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'no-redact', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'session-host-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-sechost-');
      cli(dir, ['keygen']);
      commitFile(dir, 'parent.txt', 'parent\n');
      const parent = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-sechost', '--agent', 'parent', '--host', 'hostA-secret', '--message', 'parent', '--json']));
      commitFile(dir, 'child.txt', 'child\n');
      cli(dir, ['wrap', '--sign', '--session', 's-sechost', '--parent', parent.path, '--agent', 'child', '--message', 'child']);
      const made = parseJson(cli(dir, ['report', '--session', 's-sechost', '--json']));
      const payload = payloadOf(readFileSync(made.htmlPath, 'utf8'));
      assert.equal(payload.manifestSha256, null);
      const hostReceipt = payload.receipts.find((item) => readFileSync(parent.path, 'utf8').includes(item.id));
      replaceOnce(parent.path, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'session-host', new RegExp(`receipt ${hostReceipt.id} at .* fails integrity`));
    },
  },
  {
    id: 'receipts-store-host-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      const store = join(dir, '.agent-receipt', 'receipts');
      assertTamper(dir, ['report', 'verify', made.htmlPath, '--receipts', store], 'receipts-store', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'package-receipts-host-edit',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, id } = secretReport();
      const exported = parseJson(cli(dir, ['session', 'export', 's-secret', '--json']));
      const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
      const target = packageFiles(exported.packagePath).find((file) => readFileSync(file, 'utf8').includes('- **Host**: [REDACTED]'));
      assert.ok(target);
      replaceOnce(target, '- **Host**: [REDACTED]', '- **Host**: attacker-box');
      assertTamper(dir, ['report', 'verify', packaged.htmlPath, '--receipts', exported.packagePath], 'pkg-host', new RegExp(`receipt ${id} at .* fails integrity`));
    },
  },
  {
    id: 'rehash-host-require-sig',
    gate: '74bca3d',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      assert.equal(cliResult(dir, ['verify', '--require-sig', receipt]).code, 2);
      assertTamper(dir, ['report', 'verify', made.htmlPath, '--require-sig'], 'rehash-host', new RegExp(`receipt ${id} at .* signature mismatch`));
    },
  },
  {
    id: 'prune-max-count',
    gate: 'b9c376a',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-prune-');
      cli(dir, ['keygen']);
      const paths = [];
      for (let i = 0; i < 4; i += 1) {
        commitFile(dir, `f${i}.txt`, `n${i}\n`);
        paths.push(parseJson(cli(dir, ['wrap', '--sign', '--message', `m${i}`, '--json'])).path);
      }
      const oldest = paths[0];
      const made = parseJson(cli(dir, ['report', oldest, '--json']));
      assert.equal(made.verdict, 'VERIFIED');
      const before = cliResult(dir, ['report', 'verify', made.htmlPath, '--json']);
      assert.equal(before.code, 0, before.out + before.err);
      const pruned = cliResult(dir, ['prune', '--max-count', '1', '--json']);
      assert.equal(pruned.code, 0, pruned.out + pruned.err);
      assert.equal(existsSync(oldest), false);
      const got = assertPayloadOnly(dir, ['report', 'verify', made.htmlPath], 'prune', new RegExp(PRUNE_NOTE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.equal(got.body.reason, PRUNE_NOTE);
      assert.equal(got.body.warning, null);
      assert.ok(got.body.notChecked >= 1);
    },
  },
  {
    id: 'auto-prune',
    gate: 'b9c376a',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-autoprune-');
      writeFileSync(join(dir, '.agent-receipt.yml'), '\nmaxCount: 2\nautoPrune: true\n', { flag: 'a' });
      cli(dir, ['keygen']);
      commitFile(dir, 'first.txt', 'first\n');
      const first = parseJson(cli(dir, ['capture', '--sign', '--message', 'first', '--json']));
      const made = parseJson(cli(dir, ['report', 'last', '--json']));
      assert.equal(made.verdict, 'VERIFIED');
      for (let i = 0; i < 3; i += 1) {
        commitFile(dir, `more${i}.txt`, `more${i}\n`);
        cli(dir, ['capture', '--sign', '--message', `more${i}`]);
      }
      assert.equal(existsSync(first.path), false, 'auto-prune should have deleted the reported receipt');
      const got = assertPayloadOnly(dir, ['report', 'verify', made.htmlPath], 'auto-prune', new RegExp(PRUNE_NOTE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.equal(got.body.reason, PRUNE_NOTE);
      assert.equal(got.body.warning, null);
    },
  },
  {
    id: 'importer-session-report',
    gate: 'b9c376a',
    kind: 'genuine',
    run() {
      const { sessionReport, exported } = exporterSession();
      const dest = initRepo('matrix-import-session-');
      const imported = cliResult(dest, ['session', 'import', exported.packagePath]);
      assert.equal(imported.code, 0, imported.out + imported.err);
      const got = assertVerified(dest, ['report', 'verify', sessionReport.htmlPath], 'importer-session');
      assert.equal(got.body.checked, 3);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'importer-single-report',
    gate: 'b9c376a',
    kind: 'genuine',
    run() {
      const { single, exported } = exporterSession();
      const dest = initRepo('matrix-import-single-');
      assert.equal(cliResult(dest, ['session', 'import', exported.packagePath]).code, 0);
      const got = assertVerified(dest, ['report', 'verify', single.htmlPath], 'importer-single');
      assert.equal(got.body.checked, 1);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'importer-receipts-package',
    gate: 'b9c376a',
    kind: 'genuine',
    run() {
      const { sessionReport, exported } = exporterSession();
      const dest = initRepo('matrix-import-pkg-');
      assert.equal(cliResult(dest, ['session', 'import', exported.packagePath]).code, 0);
      const got = assertVerified(dest, ['report', 'verify', sessionReport.htmlPath, '--receipts', exported.packagePath], 'importer-pkg');
      assert.equal(got.body.checked, 3);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'stripped-sig-host',
    gate: 'b9c376a',
    kind: 'tamper',
    run() {
      const { dir, receipt, packaged, id } = signedPackageAttack();
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
      const sig = receipt.replace(/\.md$/i, '.sig.json');
      assert.ok(existsSync(sig));
      rmSync(sig);
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      for (const extra of [[], ['--require-sig']]) {
        assertTamper(
          dir,
          ['report', 'verify', packaged.htmlPath, ...extra],
          `stripped-host${extra.join('')}`,
          new RegExp(`receipt ${id} at .* signature mismatch`),
        );
      }
    },
  },
  {
    id: 'stripped-sig-aws',
    gate: 'b9c376a',
    kind: 'tamper',
    run() {
      const { dir, receipt, packaged, id } = signedPackageAttack();
      replaceOnce(receipt, AWS, 'AKIAIOSFODNN7EXAMPLZ');
      writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
      rmSync(receipt.replace(/\.md$/i, '.sig.json'));
      assertTamper(
        dir,
        ['report', 'verify', packaged.htmlPath, '--require-sig'],
        'stripped-aws',
        new RegExp(`receipt ${id} at .* signature mismatch`),
      );
    },
  },
  {
    id: 'planted-unsigned-in-package',
    gate: 'b9c376a',
    kind: 'tamper',
    run() {
      const { dir, receipt, exported, packaged, id } = signedPackageAttack();
      const planted = join(exported.packagePath, 'receipts', 'planted-original.md');
      copyFileSync(receipt, planted);
      replaceOnce(planted, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      writeFileSync(planted, sealReceipt(readFileSync(planted, 'utf8')));
      const plantedSig = planted.replace(/\.md$/i, '.sig.json');
      if (existsSync(plantedSig)) rmSync(plantedSig);
      assert.equal(cliResult(dir, ['verify', planted]).code, 0);
      assertTamper(
        dir,
        ['report', 'verify', packaged.htmlPath, '--receipts', exported.packagePath, '--require-sig'],
        'planted',
        new RegExp(`receipt ${id} at .* signature mismatch`),
      );
    },
  },
  {
    id: 'audit-chain-break',
    gate: 'b9c376a',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-chain-');
      cli(dir, ['keygen']);
      commitFile(dir, 'a.txt', 'a\n');
      const first = parseJson(cli(dir, ['wrap', '--sign', '--message', 'first', '--json']));
      commitFile(dir, 'b.txt', 'b\n');
      cli(dir, ['wrap', '--sign', '--message', 'second']);
      const made = parseJson(cli(dir, ['report', first.path, '--json']));
      rmSync(first.path);
      const sig = first.path.replace(/\.md$/i, '.sig.json');
      if (existsSync(sig)) rmSync(sig);
      const indexPath = join(dir, '.agent-receipt', 'index.json');
      const index = JSON.parse(readFileSync(indexPath, 'utf8'));
      index.receipts = [];
      writeFileSync(indexPath, JSON.stringify(index));
      const auditPath = join(dir, '.agent-receipt', 'audit.jsonl');
      const lines = readFileSync(auditPath, 'utf8').split('\n').filter((line) => line.length > 0);
      assert.ok(lines.length >= 2, `expected an audit chain to break, got ${lines.length}`);
      writeFileSync(auditPath, `${lines.slice(1).join('\n')}\n`);
      const got = assertTamper(dir, ['report', 'verify', made.htmlPath], 'chain', /audit log hash chain is broken/);
      assert.doesNotMatch(got.human.out, /payload only/);
      assert.match(got.human.out, /checked: \d+  skipped: \d+  failed: \d+/);
    },
  },
  {
    id: 'no-audit-file-payload-only',
    gate: 'b9c376a',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-noaudit-src-');
      cli(dir, ['keygen']);
      commitFile(dir, 'note.txt', 'away\n');
      cli(dir, ['wrap', '--sign', '--message', 'away']);
      const made = parseJson(cli(dir, ['report', 'last', '--json']));
      rmSync(latestReceipt(dir));
      const indexPath = join(dir, '.agent-receipt', 'index.json');
      const index = JSON.parse(readFileSync(indexPath, 'utf8'));
      index.receipts = [];
      writeFileSync(indexPath, JSON.stringify(index));
      rmSync(join(dir, '.agent-receipt', 'audit.jsonl'));
      assertPayloadOnly(dir, ['report', 'verify', made.htmlPath], 'no-audit');
    },
  },
  {
    id: 'local-single',
    gate: 'genuine',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-local-single-');
      cli(dir, ['keygen']);
      commitFile(dir, 'note.txt', 'one\n');
      cli(dir, ['wrap', '--sign', '--message', 'one']);
      const made = parseJson(cli(dir, ['report', 'last', '--json']));
      const got = assertVerified(dir, ['report', 'verify', made.htmlPath], 'local-single');
      assert.equal(got.body.checked, 1);
      assert.equal(got.body.skipped, 0);
    },
  },
  {
    id: 'local-session',
    gate: 'genuine',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-local-session-');
      cli(dir, ['keygen']);
      commitFile(dir, 'parent.txt', 'parent\n');
      const parent = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-local', '--agent', 'parent', '--message', 'parent', '--json']));
      commitFile(dir, 'child.txt', 'child\n');
      cli(dir, ['wrap', '--sign', '--session', 's-local', '--parent', parent.path, '--agent', 'child', '--message', 'child']);
      const made = parseJson(cli(dir, ['report', '--session', 's-local', '--json']));
      const got = assertVerified(dir, ['report', 'verify', made.htmlPath], 'local-session');
      assert.equal(got.body.checked, 2);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'exporter-package-report',
    gate: 'genuine',
    kind: 'genuine',
    run() {
      const { dir, packaged } = exporterSession();
      const got = assertVerified(dir, ['report', 'verify', packaged.htmlPath], 'exporter-pkg');
      assert.equal(got.body.checked, 3);
      assert.equal(got.body.skipped, 0);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'importer-package-report',
    gate: 'genuine',
    kind: 'genuine',
    run() {
      const { exported, packaged } = exporterSession();
      const dest = initRepo('matrix-import-packaged-');
      assert.equal(cliResult(dest, ['session', 'import', exported.packagePath]).code, 0);
      const got = assertVerified(dest, ['report', 'verify', packaged.htmlPath], 'importer-packaged');
      assert.equal(got.body.checked, 3);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'portable-payload-only',
    gate: 'genuine',
    kind: 'genuine',
    run() {
      const { packaged } = exporterSession();
      const away = initRepo('matrix-portable-');
      const html = join(away, 'portable.report.html');
      copyFileSync(packaged.htmlPath, html);
      copyFileSync(packaged.sigPath, `${html}.sig.json`);
      const got = assertPayloadOnly(away, ['report', 'verify', html], 'portable');
      assert.equal(got.body.notChecked, 3);
    },
  },
  {
    id: 'receipts-package-genuine',
    gate: 'genuine',
    kind: 'genuine',
    run() {
      const { dir, exported, packaged } = exporterSession();
      const got = assertVerified(dir, ['report', 'verify', packaged.htmlPath, '--receipts', exported.packagePath], 'receipts-pkg');
      assert.equal(got.body.checked, 3);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'count-after-first-failure',
    gate: 'nit',
    kind: 'tamper',
    run() {
      const dir = initRepo('matrix-count-');
      cli(dir, ['keygen']);
      commitFile(dir, 'parent.txt', 'parent\n');
      const parent = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-count', '--agent', 'parent', '--message', 'parent ok', '--json']));
      commitFile(dir, 'child.txt', 'child\n');
      const child = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-count', '--parent', parent.path, '--agent', 'child', '--message', 'child bad', '--json']));
      commitFile(dir, 'grand.txt', 'grand\n');
      const grand = parseJson(cli(dir, ['wrap', '--sign', '--session', 's-count', '--parent', child.path, '--agent', 'grand', '--message', 'grand bad', '--json']));
      const made = parseJson(cli(dir, ['report', '--session', 's-count', '--json']));
      replaceOnce(child.path, 'child bad', 'child tampered');
      replaceOnce(grand.path, 'grand bad', 'grand tampered');
      const ownId = (file) => {
        const match = readFileSync(file, 'utf8').match(/^- \*\*Id\*\*: (r-[0-9a-f]+)/m);
        assert.ok(match, `id missing in ${file}`);
        return match[1];
      };
      const childId = ownId(child.path);
      const grandId = ownId(grand.path);
      const got = assertTamper(dir, ['report', 'verify', made.htmlPath], 'counts');
      assert.equal(got.body.checked, 1, JSON.stringify(got.body));
      assert.equal(got.body.skipped, 0);
      assert.equal(got.body.failed, 2, JSON.stringify(got.body));
      assert.match(got.body.reason, new RegExp(childId));
      assert.match(got.body.reason, new RegExp(grandId));
      assert.match(got.human.out, /checked: 1  skipped: 0  failed: 2/);
    },
  },
  {
    id: 'share-bidi',
    gate: 'nit',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-bidi-');
      commitFile(dir, 'note.txt', 'bidi\n');
      const agent = 'qa\u202E\u202A\u2066\u200E\u200Fname';
      cli(dir, ['capture', '--agent', agent, '--message', 'bidi\u202Etail']);
      const htmlPath = join(dir, 'share.html');
      cli(dir, ['share', '--out', htmlPath]);
      const html = readFileSync(htmlPath, 'utf8');
      for (const token of ['\\u202E', '\\u202A', '\\u2066', '\\u200E', '\\u200F']) {
        assert.ok(html.includes(token), `share HTML missing ${token}`);
      }
      for (const ch of ['\u202E', '\u202A', '\u2066', '\u200E', '\u200F']) {
        assert.equal(html.includes(ch), false, `share HTML kept raw ${ch}`);
      }
    },
  },
  {
    id: 'depth-cap-documented',
    gate: 'nit',
    kind: 'genuine',
    run() {
      const report = readFileSync(join(root, 'src', 'commands', 'report.ts'), 'utf8');
      const help = readFileSync(join(root, 'src', 'lib', 'help.ts'), 'utf8');
      const readme = readFileSync(join(root, 'README.md'), 'utf8');
      assert.match(report, /depth cap of 4/);
      assert.match(report, /last, verify, and session/);
      assert.match(report, /depth 5/);
      assert.match(help, /depth of 4/);
      assert.match(help, /depth 5/);
      assert.match(help, /report last/);
      assert.match(help, /report --session/);
      assert.match(readme, /depth 5/);
    },
  },
  {
    id: 'autocrlf-clone-attributes',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const attrs = readFileSync(join(root, '.gitattributes'), 'utf8');
      assert.match(attrs, /\*\.report\.html -text/);
      assert.match(attrs, /\.agent-receipt\/\*\* -text/);
      const readme = readFileSync(join(root, 'README.md'), 'utf8');
      const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
      assert.match(readme, /\.agent-receipt\/\*\* -text/);
      assert.match(changelog, /\.agent-receipt\/\*\* -text/);
      const { clone, html } = autocrlfClone('*.report.html -text\n.agent-receipt/** -text\n');
      const audit = readFileSync(join(clone, '.agent-receipt', 'audit.jsonl'));
      const page = readFileSync(html);
      assert.equal(audit.includes(0x0d), false, 'both -text rules should keep audit.jsonl as LF');
      assert.equal(page.includes(0x0d), false, 'the report page should stay LF');
      const got = assertVerified(clone, ['report', 'verify', 'docs-s.report.html'], 'autocrlf-both');
      assert.equal(got.body.failed, 0);
      assert.equal(cliResult(clone, ['audit', '--verify']).code, 0);
    },
  },
  {
    id: 'autocrlf-clone-audit-crlf',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const { clone, html } = autocrlfClone('*.report.html -text\n');
      const audit = readFileSync(join(clone, '.agent-receipt', 'audit.jsonl'));
      const page = readFileSync(html);
      assert.ok(audit.includes(0x0d), 'audit.jsonl should be CRLF when only *.report.html is -text');
      assert.equal(page.includes(0x0d), false, 'the report page should stay LF');
      const got = assertVerified(clone, ['report', 'verify', 'docs-s.report.html'], 'autocrlf-audit');
      assert.equal(got.body.failed, 0);
      assert.equal(cliResult(clone, ['audit', '--verify']).code, 0);
      const doctor = cliResult(clone, ['doctor', '--json']);
      assert.equal(doctor.code === 0 || doctor.code === 1, true, doctor.out + doctor.err);
      const checks = parseJson(doctor.out);
      const auditRow = (checks.checks || checks).find?.((row) => row.name === 'audit')
        || (Array.isArray(checks) ? checks.find((row) => row.name === 'audit') : null);
      const blob = doctor.out + doctor.err;
      assert.doesNotMatch(blob, /chain broken/i);
      if (auditRow) assert.notEqual(auditRow.status, 'fail');
    },
  },
  {
    id: 'm6-local-unsigned-rehash',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      const payload = payloadOf(readFileSync(made.htmlPath, 'utf8'));
      assert.equal(payload.manifestSha256, null);
      replaceOnce(receipt, '- **Host**: hostA-secret', '- **Host**: attacker-box');
      writeFileSync(receipt, sealReceipt(readFileSync(receipt, 'utf8')));
      rmSync(receipt.replace(/\.md$/i, '.sig.json'));
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      for (const extra of [[], ['--require-sig']]) {
        assertTamper(
          dir,
          ['report', 'verify', made.htmlPath, ...extra],
          `m6${extra.join('')}`,
          new RegExp(`receipt ${id} at .* differs from the signed payload`),
        );
      }
    },
  },
  {
    id: 'm7-raw-stripped',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      rmSync(receipt.replace(/\.md$/i, '.sig.json'));
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      for (const extra of [[], ['--require-sig']]) {
        assertTamper(
          dir,
          ['report', 'verify', made.htmlPath, ...extra],
          `raw-stripped${extra.join('')}`,
          new RegExp(`receipt ${id} at .* signature mismatch`),
        );
      }
    },
  },
  {
    id: 'm7-raw-other-key',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      sidecarFromOtherKey(dir, receipt);
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      for (const extra of [[], ['--require-sig']]) {
        assertTamper(
          dir,
          ['report', 'verify', made.htmlPath, ...extra],
          `raw-other${extra.join('')}`,
          new RegExp(`receipt ${id} at .* signature mismatch`),
        );
      }
    },
  },
  {
    id: 'm7-redacted-byte-stripped',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      const payload = payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0];
      assert.ok(payload.fingerprint, 'payload must record the receipt as signed');
      assert.ok(payload.redactedSha256);
      const redacted = publishRedactedReceipt(readFileSync(receipt, 'utf8'), { maskHost: true });
      writeFileSync(receipt, redacted);
      rmSync(receipt.replace(/\.md$/i, '.sig.json'));
      assert.equal(cliResult(dir, ['verify', receipt]).code, 0);
      for (const extra of [[], ['--require-sig']]) {
        assertTamper(
          dir,
          ['report', 'verify', made.htmlPath, ...extra],
          `redacted-stripped${extra.join('')}`,
          new RegExp(`receipt ${id} at .* signature mismatch`),
        );
      }
    },
  },
  {
    id: 'm7-redacted-byte-other-key',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, id } = secretReport();
      const payload = payloadOf(readFileSync(made.htmlPath, 'utf8')).receipts[0];
      assert.ok(payload.fingerprint);
      const redacted = publishRedactedReceipt(readFileSync(receipt, 'utf8'), { maskHost: true });
      writeFileSync(receipt, redacted);
      sidecarFromOtherKey(dir, receipt);
      for (const extra of [[], ['--require-sig']]) {
        assertTamper(
          dir,
          ['report', 'verify', made.htmlPath, ...extra],
          `redacted-other${extra.join('')}`,
          new RegExp(`receipt ${id} at .* signature mismatch`),
        );
      }
    },
  },
  {
    id: 'prune-before-capture',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, sha256 } = signedOne('before-capture');
      const capture = auditLines(dir).map((line) => JSON.parse(line)).find((event) => event.sha256 === sha256);
      assert.ok(capture, 'expected a capture event');
      removeReceipt(receipt);
      appendAuditLine(dir, {
        ts: new Date(Date.parse(capture.ts) - 60_000).toISOString(),
        event: 'prune',
        path: relFrom(dir, receipt),
        sha256,
      });
      assertTamper(
        dir,
        ['report', 'verify', made.htmlPath],
        'prune-before',
        new RegExp(`receipt ${payloadId(made)} prune is timestamped before its capture`),
      );
    },
  },
  {
    id: 'prune-no-capture',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made, receipt, sha256 } = signedOne('no-capture');
      removeReceipt(receipt);
      const indexPath = join(dir, '.agent-receipt', 'index.json');
      const index = JSON.parse(readFileSync(indexPath, 'utf8'));
      index.receipts = [];
      writeFileSync(indexPath, JSON.stringify(index));
      writeFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), '');
      appendAuditLine(dir, {
        ts: new Date().toISOString(),
        event: 'prune',
        path: relFrom(dir, receipt),
        sha256,
      });
      assertTamper(
        dir,
        ['report', 'verify', made.htmlPath],
        'prune-no-capture',
        new RegExp(`receipt ${payloadId(made)} is absent; audit\\.jsonl records a prune with no capture event`),
      );
    },
  },
  {
    id: 'forged-prune-wording',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const { dir, made, receipt, sha256 } = signedOne('forged-prune');
      const capture = auditLines(dir).map((line) => JSON.parse(line)).find((event) => event.sha256 === sha256);
      assert.ok(capture);
      removeReceipt(receipt);
      appendAuditLine(dir, {
        ts: new Date(Date.parse(capture.ts) + 60_000).toISOString(),
        event: 'prune',
        path: relFrom(dir, receipt),
        sha256,
      });
      const got = assertPayloadOnly(dir, ['report', 'verify', made.htmlPath], 'forged-prune');
      assert.equal(got.body.reason, PRUNE_NOTE);
      assert.equal(got.body.warning, PRUNE_WARN);
      assert.match(got.human.err, new RegExp(PRUNE_WARN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.doesNotMatch(`${got.body.reason}`, /legitimate|pruned per audit/);
      const readme = readFileSync(join(root, 'README.md'), 'utf8');
      const help = cli(root, ['help', 'report']);
      assert.match(readme, /audit\.jsonl is not signed/);
      assert.match(readme, /write access/);
      assert.match(help, /audit\.jsonl is not signed/);
    },
  },
  {
    id: 'depth-5-plus',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const { dir, made, receipt } = signedOne('depth5');
      const plant = (levels) => {
        let destDir = join(dir, '.agent-receipt', 'receipts');
        for (let i = 0; i < levels; i += 1) destDir = join(destDir, `n${i}`);
        mkdirSync(destDir, { recursive: true });
        const dest = join(destDir, 'planted.md');
        copyReceiptPair(receipt, dest);
        replaceOnce(dest, 'depth5', 'depth5-tampered');
        return dest;
      };
      plant(5);
      assertVerified(dir, ['report', 'verify', made.htmlPath], 'depth-5-ignored');
      const deep = plant(4);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'depth-4-read', new RegExp(basename(deep)));
    },
  },
  {
    id: 'package-original-deleted',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, packaged } = exporterSession();
      const payload = payloadOf(readFileSync(packaged.htmlPath, 'utf8'));
      assert.ok(payload.manifestSha256);
      for (const item of payload.receipts) {
        assert.ok(item.originalSha256, `originalSha256 missing for ${item.id}`);
        assert.notEqual(item.originalSha256, item.sha256);
      }
      for (const file of receiptFiles(dir)) removeReceipt(file);
      assertTamper(
        dir,
        ['report', 'verify', packaged.htmlPath],
        'deleted-original',
        /still lists it/,
      );
    },
  },
  {
    id: 'unsigned-source-package',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const dir = initRepo('matrix-unsigned-src-');
      commitFile(dir, 'note.txt', 'unsigned source\n');
      cli(dir, ['wrap', '--session', 's-usrc', '--agent', 'qa', '--host', HOST, '--message', 'unsigned source']);
      cli(dir, ['keygen']);
      const exportedRun = cliResult(dir, ['session', 'export', 's-usrc', '--json']);
      assert.equal(exportedRun.code, 0, exportedRun.out + exportedRun.err);
      assert.match(exportedRun.err, /originalFingerprint is null|signedBy/);
      const exported = parseJson(exportedRun.out);
      const packaged = parseJson(cli(dir, ['report', exported.packagePath, '--json']));
      const payload = payloadOf(readFileSync(packaged.htmlPath, 'utf8'));
      assert.ok(payload.manifestSha256);
      assert.equal(payload.receipts[0].originalFingerprint, null);
      assert.ok(payload.receipts[0].signedBy);
      const got = assertVerified(dir, ['report', 'verify', packaged.htmlPath], 'unsigned-source');
      assert.equal(got.body.checked, 1);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'trust-removed-require-sig',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made } = signedOne('trust-rm');
      cli(dir, ['trust', 'add', '--self']);
      const shown = parseJson(cli(dir, ['trust', 'show', '--json']));
      assert.equal(shown.localListed, true);
      assertVerified(dir, ['report', 'verify', made.htmlPath, '--require-sig'], 'trusted');
      // An empty file is not an allowlist. Keep one other key so removal stays active.
      cli(dir, ['trust', 'add', 'ab'.repeat(32)]);
      const removed = cliResult(dir, ['trust', 'rm', shown.localFingerprint]);
      assert.equal(removed.code, 0, removed.out + removed.err);
      assertTamper(
        dir,
        ['report', 'verify', made.htmlPath, '--require-sig'],
        'trust-removed',
        /not trusted/,
      );
    },
  },
  {
    id: 'legacy-audit-1.0.16-through-1.0.29',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const { dir, made } = signedOne('legacy-audit');
      const versions = [];
      for (let minor = 16; minor <= 29; minor += 1) versions.push(`1.0.${minor}`);
      let prev = null;
      const lines = [];
      for (const version of versions) {
        const event = {
          ts: '2020-01-01T00:00:00.000Z',
          event: 'capture',
          version,
          experimental: true,
          path: 'legacy/not-a-receipt.md',
          sha256: 'a'.repeat(64),
          agent: null,
          redacted: false,
          verified: true,
          failedOn: false,
          exitCode: 0,
          prev,
        };
        const line = JSON.stringify(event);
        lines.push(line);
        prev = createHash('sha256').update(`${line}\n`, 'utf8').digest('hex');
      }
      writeFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), `${lines.join('\n')}\n`);
      assert.equal(cliResult(dir, ['audit', '--verify']).code, 0);
      const got = assertVerified(dir, ['report', 'verify', made.htmlPath], 'legacy-audit');
      assert.equal(got.body.checked, 1);
      assert.equal(got.body.failed, 0);
    },
  },
  {
    id: 'whole-store-wipe',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const { dir, made, receipt } = signedOne('wipe');
      removeReceipt(receipt);
      rmSync(join(dir, '.agent-receipt', 'receipts'), { recursive: true, force: true });
      rmSync(join(dir, '.agent-receipt', 'index.json'), { force: true });
      rmSync(join(dir, '.agent-receipt', 'audit.jsonl'), { force: true });
      const got = assertPayloadOnly(dir, ['report', 'verify', made.htmlPath], 'wipe');
      assert.equal(got.body.reason, null);
      assert.equal(got.body.notChecked, 1);
      assert.match(got.human.out, /^VERIFIED \(payload only; 1 receipts not checked\)  report verify/m);
      assert.doesNotMatch(`${got.human.out}\n${got.human.err}\n${got.json.out}`, /records a prune|pruned per audit/);
    },
  },
  {
    id: 'chain-only-counts',
    gate: '3131122',
    kind: 'tamper',
    run() {
      const { dir, made } = signedOne('chain-only');
      const lines = auditLines(dir);
      assert.ok(lines.length >= 1);
      const event = JSON.parse(lines[0]);
      event.prev = 'b'.repeat(64);
      lines[0] = JSON.stringify(event);
      writeFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), `${lines.join('\n')}\n`);
      const got = assertTamper(dir, ['report', 'verify', made.htmlPath], 'chain-only', /audit log hash chain is broken/);
      assert.ok(got.body.checked >= 1, JSON.stringify(got.body));
      assert.notEqual(got.body.failed, 0);
      assert.match(got.human.out, /failed: [1-9]/);
      assert.doesNotMatch(got.human.out, /failed: 0/);
    },
  },
  {
    id: 'receipts-elsewhere-ignores-cwd-audit',
    gate: '3131122',
    kind: 'genuine',
    run() {
      const { dir, made } = signedOne('elsewhere');
      const pocket = mkdtempSync(join(tmpdir(), 'matrix-pocket-'));
      dirs.push(pocket);
      cpSync(join(dir, '.agent-receipt', 'receipts'), join(pocket, 'receipts'), { recursive: true });
      const lines = auditLines(dir);
      const event = JSON.parse(lines[0]);
      event.prev = 'c'.repeat(64);
      lines[0] = JSON.stringify(event);
      writeFileSync(join(dir, '.agent-receipt', 'audit.jsonl'), `${lines.join('\n')}\n`);
      const got = assertVerified(
        dir,
        ['report', 'verify', made.htmlPath, '--receipts', join(pocket, 'receipts')],
        'elsewhere',
      );
      assert.equal(got.body.checked, 1);
      assertTamper(dir, ['report', 'verify', made.htmlPath], 'cwd-chain-still-fails', /audit log hash chain is broken/);
    },
  },
];

describe('v1.0.30 report verify regression matrix', { concurrency: 1 }, () => {
  after(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it(`registers ${CASES.length} matrix cases across the four gates`, () => {
    const gates = new Set(CASES.map((item) => item.gate));
    for (const gate of ['88dad95', '985e363', '74bca3d', 'b9c376a', 'genuine', 'nit']) {
      assert.ok(gates.has(gate), gate);
    }
    assert.ok(CASES.length >= 70, `expected a full matrix, got ${CASES.length}`);
    const ids = new Set(CASES.map((item) => item.id));
    assert.equal(ids.size, CASES.length, 'duplicate case id');
  });

  for (const item of CASES) {
    it(`${item.gate} ${item.id} [${item.kind}]`, item.run);
  }
});
