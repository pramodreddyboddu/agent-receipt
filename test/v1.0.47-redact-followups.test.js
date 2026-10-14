/**
 * v1.0.47 — Release QA follow-ups from v1.0.46.
 * Linear JWT scan, distinct masked AWS ids, opaque include-host folders,
 * segments over 8 KiB, and hyphenated lowercase tails consumed with the token.
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
import {
  JWT_SEGMENT_MAX,
  maskJwtTokens,
  redactSecretsInText,
  secretMaskStamp,
} from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];

const SAMPLE = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
].join('.');
/** alg:none, no underscore, so the id is one safe path segment. */
const JWT_DIR = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJxYSJ9.';
const STD = 'eyJhbGciOiJub25lIn0=.+//v+w==.+y8=';
const KEY_A = 'AKIAIOSFODNN7EXAMPLE';
const KEY_B = 'AKIAIOSFODNN7EXAMPLZ';

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
    maxBuffer: 32 * 1024 * 1024,
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

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

describe('v1.0.47 linear JWT scan', () => {
  it('redacts a 1MB eyJ. run in well under five seconds and still masks a real JWT', () => {
    const filler = 'eyJ.'.repeat(250000);
    assert.equal(filler.length, 1000000);
    const input = `${filler} ${SAMPLE}`;
    const started = Date.now();
    const out = redactSecretsInText(input);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 5000, `redaction took ${elapsed}ms`);
    assert.equal(out.includes(SAMPLE), false);
    assert.equal(out.includes('eyJ.'), true);
    assert.equal(out.includes('[REDACTED]'), true);
  });
});

describe('v1.0.47 distinct masked secret ids', () => {
  it('stamps two AKIA keys differently and does not merge them on import', () => {
    const maskedA = redactSecretsInText(KEY_A);
    const maskedB = redactSecretsInText(KEY_B);
    assert.notEqual(maskedA, maskedB);
    assert.equal(maskedA, `AKIA[REDACTED:${secretMaskStamp(KEY_A)}]`);
    assert.equal(maskedB, `AKIA[REDACTED:${secretMaskStamp(KEY_B)}]`);
    assert.equal(redactSecretsInText(KEY_A), maskedA);
    assert.match(maskedA, /^AKIA\[REDACTED:[0-9a-f]{12}\]$/);
    assert.equal(maskedA.includes(KEY_A.slice(4)), false);
    assert.equal(maskedB.includes(KEY_B.slice(4)), false);

    const sessionA = `s-${KEY_A}`;
    const sessionB = `s-${KEY_B}`;
    const maskedSessionA = redactSecretsInText(sessionA);
    const maskedSessionB = redactSecretsInText(sessionB);
    assert.notEqual(maskedSessionA, maskedSessionB);
    assert.equal(maskedSessionA.includes(KEY_A), false);
    assert.equal(maskedSessionB.includes(KEY_B), false);

    const alpha = gitRepo('ar1047-a-');
    const beta = gitRepo('ar1047-b-');
    assert.equal(cli(alpha, [
      'wrap', '--agent', 'alpha', '--message', 'alpha', '--session', sessionA, '--json',
    ]).code, 0);
    assert.equal(cli(beta, [
      'wrap', '--agent', 'beta', '--message', 'beta', '--session', sessionB, '--json',
    ]).code, 0);

    const expA = parseJson(cli(alpha, ['session', 'export', sessionA, '--json']));
    const expB = parseJson(cli(beta, ['session', 'export', sessionB, '--json']));
    assert.equal(expA.session, maskedSessionA);
    assert.equal(expB.session, maskedSessionB);
    assert.equal(packageText(expA.packagePath).includes(KEY_A), false);
    assert.equal(packageText(expB.packagePath).includes(KEY_B), false);

    const dest = gitRepo('ar1047-merge-');
    assert.equal(cli(dest, ['session', 'import', expA.packagePath, '--json']).code, 0);
    assert.equal(cli(dest, ['session', 'import', expB.packagePath, '--json']).code, 0);

    const listedA = parseJson(cli(dest, ['session', maskedSessionA, '--json']));
    const listedB = parseJson(cli(dest, ['session', maskedSessionB, '--json']));
    assert.equal(listedA.receipts.length, 1);
    assert.equal(listedB.receipts.length, 1);
    assert.equal(listedA.receipts[0].agent, 'alpha');
    assert.equal(listedB.receipts[0].agent, 'beta');
    assert.equal(JSON.stringify(listedA).includes('beta'), false);
    assert.equal(JSON.stringify(listedB).includes('alpha'), false);
  });
});

describe('v1.0.47 include-host default directory', () => {
  for (const [label, session] of [
    ['akia', `s-${KEY_A}`],
    ['jwt', JWT_DIR],
  ]) {
    it(`names a ${label} package with a hash when --include-host has no --out`, () => {
      assert.match(session, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,200}$/);
      const dir = gitRepo(`ar1047-host-${label}-`);
      assert.equal(cli(dir, [
        'wrap',
        '--agent', 'ci',
        '--message', 'keep host',
        '--session', session,
        '--host', KEY_B,
        '--json',
      ]).code, 0);
      const exported = parseJson(cli(dir, [
        'session', 'export', session, '--include-host', '--json',
      ]));
      assert.equal(exported.includeHost, true);
      assert.equal(exported.session, session);
      assert.equal(basename(exported.packagePath), opaqueName(session));
      assert.equal(exported.packagePath.includes(session), false);
      assert.equal(exported.packagePath.includes(KEY_A), false);
      assert.equal(exported.packagePath.includes(KEY_B), false);
      const manifest = JSON.parse(readFileSync(exported.manifestPath, 'utf8'));
      assert.equal(manifest.session, session);
      assert.equal(manifest.includeHost, true);
      const text = readFileSync(join(exported.packagePath, manifest.receipts[0].path), 'utf8');
      assert.equal(field(text, 'Session'), session);
      assert.equal(field(text, 'Host'), KEY_B);
      assert.equal(existsSync(join(dirname(exported.packagePath), `${session}.session`)), false);
    });
  }

  it('keeps a non-secret id as the directory name', () => {
    const dir = gitRepo('ar1047-plain-');
    const session = 'ci-plain';
    assert.equal(cli(dir, [
      'wrap', '--agent', 'ci', '--message', 'plain', '--session', session, '--json',
    ]).code, 0);
    const exported = parseJson(cli(dir, [
      'session', 'export', session, '--include-host', '--json',
    ]));
    assert.equal(basename(exported.packagePath), `${session}.session`);
    assert.equal(exported.session, session);
  });
});

describe('v1.0.47 oversized JWT segments and hyphen tails', () => {
  it('masks a segment just over 8KB and stops at the documented cap', () => {
    const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ x: 'a'.repeat(9000) }));
    assert.ok(payload.length > 8192);
    assert.ok(payload.length <= JWT_SEGMENT_MAX);
    const token = `${header}.${payload}.sig`;
    assert.equal(redactSecretsInText(`see ${token} end`), 'see [REDACTED] end');

    const atCap = `${header}.${'A'.repeat(JWT_SEGMENT_MAX)}.sig`;
    assert.equal(redactSecretsInText(atCap).includes('A'.repeat(64)), false);
    const overCap = `${header}.${'A'.repeat(JWT_SEGMENT_MAX + 1)}.sig`;
    assert.equal(redactSecretsInText(overCap).includes(overCap), true);

    const dir = gitRepo('ar1047-big-');
    const wrapped = cli(dir, [
      'wrap', '--agent', 'ci', '--message', token, '--session', 's-big-jwt', '--json',
    ]);
    assert.equal(wrapped.code, 0, wrapped.err + wrapped.out);
    const receipt = latestReceipt(dir);
    assert.equal(readFileSync(receipt, 'utf8').includes(token), true);

    const sharedResult = cli(dir, ['share', receipt, '--package', '--json']);
    const shared = parseJson(sharedResult);
    const packed = packageText(shared.packagePath);
    assert.equal(packed.includes(token), false, 'share package still has the raw token');
    assert.equal(packed.includes(payload), false);
    assert.equal(sharedResult.out.includes(token), false);

    const made = parseJson(cli(dir, ['report', receipt, '--json']));
    const reportHtml = readFileSync(made.htmlPath, 'utf8');
    const shown = payloadOf(reportHtml).receipts[0].message;
    assert.equal(reportHtml.includes(token), false, 'signed report still has the raw token');
    assert.equal(shown.includes(token), false);
    assert.equal(shown.includes(payload), false);
  });

  it('consumes a hyphenated lowercase tail and keeps a non-token suffix', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`).includes('suffix'), false);
    assert.equal(redactSecretsInText(`${STD}-suffix`).includes('suffix'), false);
    assert.equal(redactSecretsInText(`${STD}-suffix`).includes(STD), false);
    assert.equal(redactSecretsInText(`${SAMPLE}_x`), '[REDACTED]_x');
    assert.equal(redactSecretsInText(`${SAMPLE}-`), '[REDACTED]-');
    assert.equal(redactSecretsInText(`${SAMPLE}_`), '[REDACTED]_');
    assert.equal(redactSecretsInText('eyJsee.the.docs'), 'eyJsee.the.docs');

    const typ = `${b64url(JSON.stringify({ typ: 'JWT' }))}.${b64url('{}')}.x`;
    assert.equal(maskJwtTokens(typ, 'general'), '[REDACTED]');
    assert.equal(maskJwtTokens(typ, 'strict'), typ);
    assert.equal(redactSecretsInText(typ), '[REDACTED]');
    assert.equal(maskJwtTokens(`${SAMPLE}-low`, 'strict').includes('low'), false);

    const dir = gitRepo('ar1047-tail-');
    const message = `dash ${SAMPLE}-suffix keep ${SAMPLE}_x`;
    assert.equal(cli(dir, [
      'wrap', '--agent', 'ci', '--message', message, '--session', 's-tail', '--json',
    ]).code, 0);
    const receipt = latestReceipt(dir);
    const shared = parseJson(cli(dir, ['share', receipt, '--package', '--json']));
    const md = readFileSync(join(shared.packagePath, 'receipt.md'), 'utf8');
    assert.equal(md.includes(SAMPLE), false);
    assert.equal(md.includes('suffix'), false);
    assert.equal(md.includes('[REDACTED]_x'), true);
    const shown = payloadOf(readFileSync(
      parseJson(cli(dir, ['report', receipt, '--json'])).htmlPath,
      'utf8',
    )).receipts[0].message;
    assert.equal(shown.includes('suffix'), false);
    assert.equal(shown.includes('[REDACTED]_x'), true);
  });
});
