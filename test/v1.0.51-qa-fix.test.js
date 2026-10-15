/**
 * v1.0.51 Release QA blockers.
 * The padding "=" search stays inside the current token, an unpadded
 * standard-base64 signature that contains + or / is fully masked, last
 * redacts commit-message secrets, and a JWT glued to "=text" is masked.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  maskJwtTokens,
  redactSecretsInText,
} from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];

const SAMPLE = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
].join('.');
const JWT_DIR = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJxYSJ9.';
const STD = 'eyJhbGciOiJub25lIn0=.+//v+w==.+y8=';
const HEADER = 'eyJhbGciOiJub25lIn0';
const PAYLOAD = 'eyJzdWIiOiJxYSJ9';
const GHP = `ghp_${'a'.repeat(36)}`;
const AKIA = 'AKIAIOSFODNN7EXAMPLE';
const FOUR_MB = 4 * 1024 * 1024;
/**
 * Linear 4MB scans are well under these. The unbounded "=" search was about
 * 1.5s for space-separated tokens and about 7s for a header plus `-eyJ-eyJ.`
 * on a quiet host, so a quadratic scan still fails. The slack is for a slow
 * loaded host. The header run does more candidate work, so its bound is wider.
 */
const BOUND_MS = 1000;
const HEADER_BOUND_MS = 3000;

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
    timeout: 120000,
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
  const init = cli(dir, ['init']);
  assert.equal(init.code, 0, init.err + init.out);
  return dir;
}

function latestReceipt(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  const files = readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .map((name) => join(out, name));
  assert.ok(files.length > 0, 'expected a receipt');
  return files.sort()[files.length - 1];
}

function assertJwtGone(text, token, label) {
  const [header, payload, signature] = token.split('.');
  assert.equal(text.includes(header), false, `${label} header`);
  assert.equal(text.includes(payload), false, `${label} payload`);
  if (signature) assert.equal(text.includes(signature), false, `${label} signature`);
}

function assertSecretGone(text, label) {
  assert.equal(text.includes(GHP), false, `${label} ghp`);
  assert.equal(text.includes(AKIA), false, `${label} akia`);
  assert.equal(text.includes('a'.repeat(36)), false, `${label} token body`);
}

function fill(unit, size) {
  const whole = Math.max(1, Math.floor(size / unit.length));
  return unit.repeat(whole);
}

function assertFast(label, input, bound = BOUND_MS) {
  assert.equal(input.includes('='), false, `${label} must not contain =`);
  assert.ok(input.length >= FOUR_MB - 256, `${label} length ${input.length}`);
  const started = Date.now();
  const out = redactSecretsInText(input);
  const elapsed = Date.now() - started;
  assert.ok(elapsed < bound, `${label} took ${elapsed}ms`);
  return out;
}

describe('v1.0.51 QA bounded JWT padding scan', () => {
  it('redacts 4MB of space-separated JWTs with no "=" after them', () => {
    const input = fill(`${SAMPLE} `, FOUR_MB);
    const out = assertFast('space-separated', input);
    assertJwtGone(out, SAMPLE, 'space-separated');
    assert.equal(out.includes('[REDACTED]'), true);
  });

  it('redacts 4MB of 9xeyJ- plus a JWT with no "=" after them', () => {
    const input = fill(`9xeyJ-${SAMPLE} `, FOUR_MB);
    const out = assertFast('9xeyJ-', input);
    assertJwtGone(out, SAMPLE, '9xeyJ-');
    assert.equal(out.includes('[REDACTED]'), true);
  });

  it('scans 4MB of repeated J/x/y.ts with no "="', () => {
    const input = fill('J/x/y.ts', FOUR_MB);
    const out = assertFast('J/x/y.ts', input);
    assert.equal(out.includes('[REDACTED]'), false);
    assert.equal(out.includes('J/x/y.ts'), true);
  });

  it('scans 4MB of a header plus -eyJ-eyJ with no "=" after the run', () => {
    const unit = `${HEADER}-eyJ-eyJ.`;
    const filler = fill(unit, FOUR_MB - SAMPLE.length - 1);
    const input = `${filler} ${SAMPLE}`;
    const out = assertFast('header -eyJ-eyJ', input, HEADER_BOUND_MS);
    assertJwtGone(out, SAMPLE, 'header -eyJ-eyJ');
    assert.equal(out.includes(unit.slice(0, HEADER.length)), true);
  });
});

describe('v1.0.51 QA std-base64 signature is not split as a path', () => {
  const leaked = `${HEADER}.${PAYLOAD}.ab+c/def`;

  it('masks an unpadded signature that contains + and /', () => {
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(leaked, mode);
      assert.equal(out, '[REDACTED]', `${mode} ${out}`);
      assert.equal(out.includes('+'), false, mode);
      assert.equal(out.includes('/'), false, mode);
      assertJwtGone(out, leaked, mode);
    }
    const text = redactSecretsInText(`see ${leaked} later`);
    assert.equal(text, 'see [REDACTED] later', text);
    assertJwtGone(text, leaked, 'sentence');
    assert.equal(text.includes('+c/def'), false);
    assert.equal(text.includes('ab+c'), false);

    const slashFirst = redactSecretsInText(`${HEADER}.${PAYLOAD}.abc/de/fghi`);
    assert.equal(slashFirst, '[REDACTED]', slashFirst);
    assert.equal(slashFirst.includes('/de/'), false);
  });

  it('still keeps a clear path glued after a standard base64url signature', () => {
    const kept = [
      [`${SAMPLE}/src/app.ts`, '[REDACTED]/src/app.ts'],
      [`${SAMPLE}/file.ts`, '[REDACTED]/file.ts'],
      [`${SAMPLE}+src/app.ts`, '[REDACTED]+src/app.ts'],
      [`${SAMPLE}+/src/app.ts`, '[REDACTED]+/src/app.ts'],
      [`${SAMPLE}+lib/index.js`, '[REDACTED]+lib/index.js'],
      [`${STD}/src/app.ts`, '[REDACTED]/src/app.ts'],
      [`${STD}+src/app.ts`, '[REDACTED]+src/app.ts'],
      [`see ${SAMPLE}/docs/readme.md later`, 'see [REDACTED]/docs/readme.md later'],
    ];
    for (const [raw, expect] of kept) {
      for (const mode of ['general', 'strict']) {
        assert.equal(maskJwtTokens(raw, mode), expect, `${mode} ${raw}`);
      }
      const text = redactSecretsInText(raw);
      assert.equal(text, expect, text);
      assertJwtGone(text, raw.includes(STD) ? STD : SAMPLE, expect);
    }
    assert.equal(redactSecretsInText(`${SAMPLE}+hello`), '[REDACTED]');
    const empty = redactSecretsInText(`${JWT_DIR}/src/app.ts`);
    assert.equal(empty, '[REDACTED].ts', empty);
    assert.equal(empty.includes('/src/app'), false);
  });
});

describe('v1.0.51 QA JWT followed by =text', () => {
  it('masks the token and leaves the plain trailer', () => {
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(`${SAMPLE}=text`, mode);
      assert.equal(out, '[REDACTED]text', `${mode} ${out}`);
      assertJwtGone(out, SAMPLE, mode);
    }
    const text = redactSecretsInText(`see ${SAMPLE}=text later`);
    assert.equal(text, 'see [REDACTED]text later', text);
    assertJwtGone(text, SAMPLE, 'sentence');
    assert.equal(text.includes('text'), true);

    assert.equal(redactSecretsInText(`${STD}text`), '[REDACTED]text');
    assert.equal(redactSecretsInText(`${STD}=text`), '[REDACTED]=text');
    assert.equal(redactSecretsInText(`${SAMPLE}=${SAMPLE}`), '[REDACTED]=[REDACTED]');
    assert.equal(redactSecretsInText(`${STD}=+hello`), '[REDACTED]=+hello');
    assert.equal(redactSecretsInText(`${SAMPLE}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${STD}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${STD}-Then`), '[REDACTED]-Then');
  });
});

describe('v1.0.51 QA last redacts commit-message secrets', () => {
  it('masks a ghp_ and AKIA in last and last --json', () => {
    const dir = gitRepo('ar1051qa-last-');
    const subject = `ship ${GHP} and ${AKIA}`;
    writeFileSync(join(dir, 'notes.txt'), 'plain\n');
    git(dir, ['add', 'notes.txt']);
    git(dir, ['commit', '-m', subject]);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', subject]).code, 0);

    const stored = readFileSync(latestReceipt(dir), 'utf8');
    assert.equal(stored.includes(GHP), true);
    assert.equal(stored.includes(AKIA), true);
    const index = readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8');
    assert.equal(index.includes(GHP), true);
    assert.equal(index.includes(AKIA), true);

    const human = cli(dir, ['last']);
    assert.equal(human.code, 0, human.err);
    assert.match(human.out, /latest:/);
    assertSecretGone(human.out, 'last');
    assert.equal(human.out.includes('ghp_[REDACTED]'), true, human.out);
    assert.equal(human.out.includes('AKIA[REDACTED:'), true, human.out);

    const listed = cli(dir, ['last', '--json']);
    assert.equal(listed.code, 0, listed.err);
    assertSecretGone(listed.out, 'last --json');
    const body = JSON.parse(listed.out);
    assert.equal(body.command, 'last');
    assert.equal(body.ok, true);
    assert.equal(body.message.includes('ghp_[REDACTED]'), true, body.message);
    assert.equal(body.message.includes('AKIA[REDACTED:'), true, body.message);
    assert.equal(body.message.includes(GHP), false);
    assert.equal(body.message.includes(AKIA), false);
  });
});
