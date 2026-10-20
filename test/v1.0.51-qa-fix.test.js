/**
 * v1.0.51 Release QA blockers.
 * The padding "=" search stays inside the current token, an unpadded
 * standard-base64 signature that contains + or / is fully masked, last
 * redacts commit-message secrets, and a JWT glued to "=text" is masked.
 * The re-gate splits a glued path only at the signature length for the
 * token's own alg, and treats "=" as a boundary after every valid JWT.
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

const MARK = 'Qxsigrest';

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function jwtFor(alg, signature) {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'qa' }));
  return `${header}.${payload}.${signature}`;
}

/** `marker` at `at` inside a signature of `length`, with a path-shaped tail. */
function sigMarked(length, at, marker) {
  const glued = `${marker}src/${MARK}`;
  assert.ok(at + glued.length <= length, `marker does not fit in ${length}`);
  return `${'A'.repeat(at)}${glued}${'B'.repeat(length - at - glued.length)}`;
}

function assertFullyMasked(raw, label) {
  for (const mode of ['general', 'strict']) {
    const out = maskJwtTokens(raw, mode);
    assert.equal(out, '[REDACTED]', `${label} ${mode} ${out}`);
    assert.equal(out.includes(MARK), false, `${label} ${mode} marker`);
    assert.equal(out.includes('/src/'), false, `${label} ${mode} path`);
  }
  const text = redactSecretsInText(`see ${raw} later`);
  assert.equal(text, 'see [REDACTED] later', `${label} ${text}`);
  assert.equal(text.includes(MARK), false, label);
  assertJwtGone(text, raw, label);
}

function assertPathKept(raw, expect, label) {
  for (const mode of ['general', 'strict']) {
    assert.equal(maskJwtTokens(raw, mode), expect, `${label} ${mode}`);
  }
  const text = redactSecretsInText(raw);
  assert.equal(text, expect, `${label} ${text}`);
  assert.equal(text.includes(MARK), false, label);
}

describe('v1.0.51 QA signature split matches the token alg', () => {
  it('masks a + or / at 43, 64, or 86 inside a longer signature', () => {
    const cases = [
      ['HS512', 86, 43, '/'],
      ['HS512', 86, 64, '+'],
      ['HS384', 64, 43, '/'],
      ['ES512', 176, 86, '/'],
      ['ES512', 176, 43, '+'],
      ['ES512', 176, 64, '/'],
      ['RS256', 342, 64, '+'],
      ['RS256', 342, 86, '+'],
      ['RS256', 342, 43, '/'],
      ['PS256', 342, 64, '+'],
      ['PS512', 683, 86, '/'],
    ];
    for (const [alg, length, at, marker] of cases) {
      const raw = jwtFor(alg, sigMarked(length, at, marker));
      assertFullyMasked(raw, `${alg} ${marker} at ${at}`);
    }
  });

  it('keeps a clear path when the signature length matches that alg', () => {
    const cases = [
      ['HS256', 43],
      ['HS384', 64],
      ['HS512', 86],
      ['ES256', 86],
      ['EdDSA', 86],
      ['ES384', 128],
      ['ES512', 176],
      ['RS256', 342],
      ['PS256', 342],
      ['RS384', 512],
      ['PS384', 512],
      ['RS512', 683],
      ['PS512', 683],
    ];
    for (const [alg, length] of cases) {
      const token = jwtFor(alg, 'A'.repeat(length));
      assertPathKept(`${token}/src/app.ts`, '[REDACTED]/src/app.ts', `${alg} slash`);
      if (alg === 'ES384' || alg === 'ES512' || alg === 'HS256' || alg === 'RS256') {
        assertPathKept(`${token}+src/app.ts`, '[REDACTED]+src/app.ts', `${alg} plus`);
        assertPathKept(`${token}+/src/app.ts`, '[REDACTED]+/src/app.ts', `${alg} plus-slash`);
      }
    }
  });

  it('masks the whole run when the alg does not allow that length', () => {
    const mismatched = [
      ['HS256', 64],
      ['HS256', 86],
      ['HS256', 128],
      ['HS384', 43],
      ['HS384', 86],
      ['HS512', 43],
      ['ES384', 86],
      ['ES512', 128],
      ['RS256', 86],
      ['none', 43],
      ['none', 86],
      ['HS999', 43],
    ];
    for (const [alg, length] of mismatched) {
      const raw = `${jwtFor(alg, 'A'.repeat(length))}/src/app.ts`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        assert.equal(out, '[REDACTED].ts', `${alg} ${length} ${mode} ${out}`);
        assert.equal(out.includes('/src/app'), false, `${alg} ${mode}`);
        assert.equal(out.includes('A'.repeat(20)), false, `${alg} ${mode} sig`);
      }
    }

    const header = b64url(JSON.stringify({ typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ sub: 'qa' }));
    const typOnly = `${header}.${payload}.${'A'.repeat(43)}/src/app.ts`;
    assert.equal(maskJwtTokens(typOnly, 'general'), '[REDACTED].ts');
    assert.equal(maskJwtTokens(typOnly, 'strict'), typOnly);
  });
});

describe('v1.0.51 QA = boundary after every JWT length', () => {
  const cases = [
    ['HS384', 64, '=text', '=text'],
    ['HS384', 64, '==text', '==text'],
    ['ES384', 128, '=text', '=text'],
    ['ES384', 128, '==text', '==text'],
    ['ES512', 176, '=text', '=text'],
    ['ES512', 176, '==text', '==text'],
    ['RS384', 512, '=text', '=text'],
    ['RS384', 512, '==text', '==text'],
    ['HS512', 86, '=text', '=text'],
    ['HS512', 86, '==text', 'text'],
    ['ES256', 86, '=text', '=text'],
    ['EdDSA', 86, '==text', 'text'],
    ['RS256', 342, '=text', '=text'],
    ['RS256', 342, '==text', 'text'],
    ['PS256', 342, '=text', '=text'],
    ['RS512', 683, '=text', 'text'],
    ['RS512', 683, '==text', '=text'],
    ['PS512', 683, '=text', 'text'],
  ];

  for (const [alg, length, trailer, suffix] of cases) {
    it(`masks ${alg} (${length}) before ${trailer}`, () => {
      const token = jwtFor(alg, 'A'.repeat(length));
      const raw = `${token}${trailer}`;
      const expect = `[REDACTED]${suffix}`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        assert.equal(out, expect, `${mode} ${out}`);
        assertJwtGone(out, token, `${alg} ${mode}`);
      }
      const text = redactSecretsInText(`see ${raw} later`);
      assert.equal(text, `see ${expect} later`, text);
      assert.equal(text.includes('text'), true);
      assertJwtGone(text, token, alg);
    });
  }

  it('keeps =text after an empty signature and after a signature that contains /', () => {
    assert.equal(redactSecretsInText(`${JWT_DIR}=text`), '[REDACTED]=text');
    assert.equal(redactSecretsInText(`${JWT_DIR}==text`), '[REDACTED]==text');
    assertJwtGone(redactSecretsInText(`${JWT_DIR}=text`), JWT_DIR, 'empty =text');

    const hs = jwtFor('HS512', sigMarked(86, 43, '/'));
    assert.equal(redactSecretsInText(`${hs}=text`), '[REDACTED]=text');
    assert.equal(redactSecretsInText(`${hs}=text`).includes(MARK), false);
    assert.equal(redactSecretsInText(`${hs}==text`), '[REDACTED]text');
    assert.equal(redactSecretsInText(`${hs}==text`).includes(MARK), false);

    const rs = jwtFor('RS256', sigMarked(342, 64, '+'));
    assert.equal(redactSecretsInText(`${rs}=text`), '[REDACTED]=text');
    assert.equal(redactSecretsInText(`${rs}=text`).includes(MARK), false);
    assert.equal(redactSecretsInText(`${rs}==text`), '[REDACTED]text');
    assert.equal(redactSecretsInText(`${rs}==text`).includes(MARK), false);
    assert.equal(redactSecretsInText(`see ${jwtFor('ES384', 'A'.repeat(128))}=text later`), 'see [REDACTED]=text later');
    assert.equal(redactSecretsInText(`see ${jwtFor('RS384', 'B'.repeat(512))}==text later`), 'see [REDACTED]==text later');
  });
});
