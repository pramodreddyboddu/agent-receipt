/**
 * v1.0.46 — Release QA follow-ups from v1.0.45.
 * Secret-shaped session ids export as a verifiable package, and JWT masking
 * covers alg:none, short segments, standard base64, without swallowing a
 * trailing _x. A hyphenated lowercase tail is consumed (v1.0.47).
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { maskSessionId, redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];

const SAMPLE = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
].join('.');
/** alg:none, empty signature, base64url segments. */
const ALG_NONE = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJxYSJ9.';
/** Short payload (`{}` → e30) and a one-character signature. Header still decodes. */
const SHORT = 'eyJhbGciOiJuIn0.e30.x';
/** Standard base64: `+`, `/`, and `=` in the segments. Header is `{"alg":"none"}`. */
const STD = 'eyJhbGciOiJub25lIn0=.+//v+w==.+y8=';
/** Padded `{"alg":"none"}` header, short payload, empty signature. */
const PADDED_NONE = 'eyJhbGciOiJub25lIn0=.e30.';
const GHP = `ghp_${'m'.repeat(36)}`;
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AKIA_SESSION = `sess-${AWS_KEY}`;

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function keep(dir) {
  dirs.push(dir);
  return dir;
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function cli(cwd, args) {
  const result = spawnSync(process.execPath, [bin, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30000,
  });
  const extra = result.error ? result.error.message : '';
  return {
    code: result.status === null ? 1 : result.status,
    out: result.stdout || '',
    err: `${result.stderr || ''}${extra}`,
  };
}

function gitRepo(prefix) {
  const dir = keep(mkdtempSync(join(tmpdir(), prefix)));
  git(dir, ['init', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  writeFileSync(join(dir, 'README.md'), '# qa\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  assert.equal(cli(dir, ['init']).code, 0);
  return dir;
}

function parseJson(result) {
  assert.equal(result.code, 0, result.err + result.out);
  return JSON.parse(result.out);
}

function walkFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const filePath = join(dir, name);
    const st = lstatSync(filePath);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) out.push(...walkFiles(filePath));
    else out.push(filePath);
  }
  return out;
}

function packageText(dir) {
  return walkFiles(dir).map((filePath) => readFileSync(filePath, 'utf8')).join('\n');
}

function latestReceipt(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  const files = readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .map((name) => join(out, name));
  assert.ok(files.length > 0, 'expected a receipt');
  files.sort((a, b) => lstatSync(b).mtimeMs - lstatSync(a).mtimeMs);
  return files[0];
}

function field(markdown, label) {
  const match = markdown.match(new RegExp(`^- \\*\\*${label}\\*\\*: (.*)$`, 'm'));
  return match ? match[1] : null;
}

function payloadOf(html) {
  const match = html.match(
    /<script type="application\/json" id="agent-receipt-report">([\s\S]*?)<\/script>/,
  );
  assert.ok(match, 'embedded payload missing');
  return JSON.parse(match[1]);
}

function opaqueName(sessionId) {
  const digest = createHash('sha256').update(sessionId, 'utf8').digest('hex').slice(0, 12);
  return `session-${digest}.session`;
}

describe('v1.0.46 JWT mask coverage and boundary', () => {
  it('masks alg:none, short segments, standard base64, and a short _x tail', () => {
    assert.ok(ALG_NONE.endsWith('.'));
    assert.equal(ALG_NONE.split('.').length, 3);
    assert.ok(SHORT.split('.')[1].length < 8);
    assert.ok(SHORT.split('.')[2].length < 8);
    assert.ok(STD.includes('+'));
    assert.ok(STD.includes('/'));
    assert.ok(STD.includes('='));
    assert.ok(PADDED_NONE.includes('='));

    assert.equal(redactSecretsInText(`note ${SAMPLE} please`), 'note [REDACTED] please');
    assert.equal(redactSecretsInText(`${SAMPLE}_x`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}_`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-Def9Xyz`).includes('Def9Xyz'), false);
    assert.equal(redactSecretsInText(`${SAMPLE}-Def9Xyz`).includes(SAMPLE), false);
    assert.equal(redactSecretsInText(ALG_NONE), '[REDACTED]');
    assert.equal(redactSecretsInText(SHORT), '[REDACTED]');
    assert.equal(redactSecretsInText(STD), '[REDACTED]');
    assert.equal(redactSecretsInText(PADDED_NONE), '[REDACTED]');
    assert.equal(redactSecretsInText('eyJsee.the.docs'), 'eyJsee.the.docs');
    assert.equal(redactSecretsInText('v1.0.46'), 'v1.0.46');
    assert.equal(redactSecretsInText('file.name.txt'), 'file.name.txt');
    assert.equal(redactSecretsInText('foo.bar.baz'), 'foo.bar.baz');
    assert.equal(redactSecretsInText(GHP), 'ghp_[REDACTED]');
    assert.match(redactSecretsInText(AKIA_SESSION), /^sess-AKIA\[REDACTED:[0-9a-f]{12}\]$/);
    assert.equal(redactSecretsInText(SAMPLE), '[REDACTED]');
    assert.equal(redactSecretsInText('sess-plain'), 'sess-plain');
  });

  it('redacts the missed JWT shapes on share and report, including a short _x tail', () => {
    const dir = gitRepo('ar1046-jwt-');
    const message = [
      `none ${ALG_NONE} end`,
      `short ${SHORT} end`,
      `std ${STD} end`,
      `pad ${PADDED_NONE} end`,
      `sfx ${SAMPLE}_x end`,
      `dash ${SAMPLE}-suffix end`,
      `mix ${SAMPLE}-Def9Xyz end`,
      'keep eyJsee.the.docs v1.0.46 file.name.txt foo.bar.baz',
    ].join(' | ');
    const wrapped = cli(dir, [
      'wrap',
      '--agent', 'ci',
      '--message', message,
      '--session', 's-jwt-46',
      '--json',
    ]);
    assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
    const receipt = latestReceipt(dir);
    const original = readFileSync(receipt, 'utf8');
    assert.equal(original.includes(ALG_NONE), true);
    assert.equal(original.includes(SHORT), true);
    assert.equal(original.includes(STD), true);
    assert.equal(cli(dir, ['verify', receipt]).code, 0);

    const sharedResult = cli(dir, ['share', receipt, '--package', '--json']);
    const shared = parseJson(sharedResult);
    const md = readFileSync(join(shared.packagePath, 'receipt.md'), 'utf8');
    const shareHtml = readFileSync(join(shared.packagePath, 'receipt.html'), 'utf8');
    const packed = packageText(shared.packagePath);
    for (const token of [ALG_NONE, SHORT, STD, PADDED_NONE, SAMPLE, 'Def9Xyz', '+//v+w==']) {
      assert.equal(packed.includes(token), false, 'share package still has a raw token');
      assert.equal(sharedResult.out.includes(token), false, 'share stdout still has a raw token');
    }
    assert.equal(md.includes('_x'), false);
    assert.equal(md.includes('-suffix'), false);
    assert.equal(shareHtml.includes('_x'), false);
    assert.equal(shareHtml.includes('-suffix'), false);
    assert.equal(md.includes('eyJsee.the.docs'), true);
    assert.equal(md.includes('v1.0.46'), true);
    assert.equal(md.includes('file.name.txt'), true);
    assert.equal(md.includes('foo.bar.baz'), true);
    assert.equal(md.includes('suffix'), false);
    assert.equal(cli(dir, ['verify', '--package', shared.packagePath]).code, 0);

    const made = parseJson(cli(dir, ['report', receipt, '--json']));
    const reportHtml = readFileSync(made.htmlPath, 'utf8');
    const payload = payloadOf(reportHtml);
    const shown = payload.receipts[0].message;
    for (const token of [ALG_NONE, SHORT, STD, PADDED_NONE, SAMPLE, 'Def9Xyz', '+//v+w==']) {
      assert.equal(reportHtml.includes(token), false, 'signed report still has a raw token');
      assert.equal(shown.includes(token), false);
    }
    assert.equal(shown.includes('_x'), false);
    assert.equal(shown.includes('-suffix'), false);
    assert.equal(shown.includes('eyJsee.the.docs'), true);
    assert.equal(shown.includes('file.name.txt'), true);
    assert.equal(shown.includes('suffix'), false);
  });
});

describe('v1.0.46 secret-shaped session export', () => {
  for (const [label, session, masked] of [
    // v1.0.47 stamps a masked session id. A message token stays unstamped.
    ['ghp_', GHP, maskSessionId(GHP)],
    ['jwt', SAMPLE, maskSessionId(SAMPLE)],
    ['akia', AKIA_SESSION, redactSecretsInText(AKIA_SESSION)],
  ]) {
    it(`exports and shares a ${label} session id without a manifest mismatch`, () => {
      const dir = gitRepo(`ar1046-${label}-`);
      const wrapped = cli(dir, [
        'wrap',
        '--agent', 'ci',
        '--message', 'secret session',
        '--session', session,
        '--json',
      ]);
      assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
      const receipt = latestReceipt(dir);
      assert.equal(readFileSync(receipt, 'utf8').includes(session), true);

      const exported = cli(dir, ['session', 'export', session, '--json']);
      assert.equal(exported.code, 0, exported.err + exported.out);
      assert.equal(exported.out.includes(session), false, 'export stdout still has the session id');
      assert.equal(exported.err.includes(session), false, 'export stderr still has the session id');
      const report = JSON.parse(exported.out);
      assert.equal(report.exitCode, 0);
      assert.equal(report.session, masked);
      assert.equal(report.packagePath.includes(session), false);
      assert.equal(basename(report.packagePath), opaqueName(session));
      const manifest = JSON.parse(readFileSync(report.manifestPath, 'utf8'));
      assert.equal(manifest.session, masked);
      assert.equal(manifest.includeHost, false);
      const packed = packageText(report.packagePath);
      assert.equal(packed.includes(session), false, 'export package still has the session id');
      for (const entry of manifest.receipts) {
        const text = readFileSync(join(report.packagePath, entry.path), 'utf8');
        assert.equal(field(text, 'Session'), masked);
        assert.equal(cli(dir, ['verify', join(report.packagePath, entry.path)]).code, 0);
      }

      const dest = gitRepo(`ar1046-${label}-dest-`);
      const dry = cli(dest, ['session', 'import', report.packagePath, '--dry-run', '--json']);
      assert.equal(dry.code, 0, dry.err + dry.out);
      const dryBody = JSON.parse(dry.out);
      assert.equal(dryBody.written, false);
      assert.equal(dryBody.conflicts, 0);
      assert.equal(dry.out.includes(session), false);

      const sharedResult = cli(dir, ['share', receipt, '--package', '--json']);
      const shared = parseJson(sharedResult);
      const shareText = packageText(shared.packagePath);
      assert.equal(shareText.includes(session), false, 'share package still has the session id');
      assert.equal(sharedResult.out.includes(session), false, 'share stdout still has the session id');
      assert.equal(cli(dir, ['verify', '--package', shared.packagePath]).code, 0);

      const raw = readFileSync(report.manifestPath, 'utf8');
      const tampered = JSON.parse(raw);
      tampered.session = session;
      writeFileSync(report.manifestPath, `${JSON.stringify(tampered, null, 2)}\n`);
      const bad = cli(dest, ['session', 'import', report.packagePath, '--dry-run', '--json']);
      assert.equal(bad.code, 2, bad.out + bad.err);
      assert.match(bad.out, /manifest session does not match/);

      const again = cli(dir, ['session', 'export', session, '--out', `tamper-${label}`, '--json']);
      assert.equal(again.code, 0, again.err + again.out);
      const second = JSON.parse(again.out);
      const receiptPath = join(second.packagePath, second.receipts[0].path);
      const bytes = readFileSync(receiptPath);
      bytes[10] = bytes[10] === 0x41 ? 0x42 : 0x41;
      writeFileSync(receiptPath, bytes);
      const flipped = cli(dest, ['session', 'import', second.packagePath, '--dry-run', '--json']);
      assert.equal(flipped.code, 2, flipped.out + flipped.err);
    });
  }

  it('keeps the original id on both sides with --include-host', () => {
    const dir = gitRepo('ar1046-host-');
    const session = GHP;
    assert.equal(cli(dir, [
      'wrap', '--agent', 'ci', '--message', 'keep', '--session', session, '--json',
    ]).code, 0);
    const exported = cli(dir, [
      'session', 'export', session, '--include-host', '--out', 'with-host', '--json',
    ]);
    assert.equal(exported.code, 0, exported.err + exported.out);
    const report = JSON.parse(exported.out);
    assert.equal(report.session, session);
    assert.equal(report.includeHost, true);
    const manifest = JSON.parse(readFileSync(report.manifestPath, 'utf8'));
    assert.equal(manifest.session, session);
    const text = readFileSync(join(report.packagePath, manifest.receipts[0].path), 'utf8');
    assert.equal(field(text, 'Session'), session);
    const dest = gitRepo('ar1046-host-dest-');
    const dry = cli(dest, ['session', 'import', report.packagePath, '--dry-run', '--json']);
    assert.equal(dry.code, 0, dry.err + dry.out);
    assert.equal(existsSync(report.packagePath), true);
  });
});
