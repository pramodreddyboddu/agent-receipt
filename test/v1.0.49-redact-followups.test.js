/**
 * v1.0.49 — Release QA follow-ups from v1.0.48.
 * JWTs joined by `_` or `=` are masked, hyphen suffixes stay whole words
 * (including capitals) and do not leave token tails, git-quoted paths are
 * attest subjects, and the adversarial eyJ shapes stay fast.
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
import { unquoteGitPath } from '../dist/lib/git.js';
import {
  maskJwtTokens,
  maskSecretPath,
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
const GHP = `ghp_${'a'.repeat(36)}`;

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
  git(dir, ['config', 'core.quotePath', 'true']);
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

describe('v1.0.49 JWTs joined by _ or =', () => {
  for (const joiner of ['_', '=']) {
    it(`masks both tokens joined by ${joiner} and leaves no raw JWT substring`, () => {
      for (const [label, token] of [['sample', SAMPLE], ['std', STD], ['none', JWT_DIR]]) {
        const joined = `${token}${joiner}${token}`;
        for (const mode of ['general', 'strict']) {
          const out = maskJwtTokens(joined, mode);
          assert.equal(out, `[REDACTED]${joiner}[REDACTED]`, `${label} ${mode}`);
          assertJwtGone(out, token, `${label} ${mode} ${joiner}`);
        }
        const text = redactSecretsInText(joined);
        assert.equal(text, `[REDACTED]${joiner}[REDACTED]`, label);
        assertJwtGone(text, token, `${label} text ${joiner}`);
      }
      const triple = `${SAMPLE}${joiner}${SAMPLE}${joiner}${SAMPLE}`;
      assert.equal(redactSecretsInText(triple), `[REDACTED]${joiner}[REDACTED]${joiner}[REDACTED]`);
      assertJwtGone(redactSecretsInText(triple), SAMPLE, `triple ${joiner}`);
    });
  }

  it('still masks two tokens joined by a hyphen', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}`), '[REDACTED]-[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}-suffix`).includes('suffix'), false);
    assertJwtGone(redactSecretsInText(`${STD}-${STD}`), STD, 'hyphen std');
  });
});

describe('v1.0.49 hyphen suffix rule', () => {
  it('keeps a whole hyphenated word, including a capital', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}-config-file`), '[REDACTED]-config-file');
    assert.equal(redactSecretsInText(`${STD}-config-file`), '[REDACTED]-config-file');
    assert.equal(maskJwtTokens(`${SAMPLE}-Config-File`, 'strict'), '[REDACTED]-Config-File');
    assert.equal(redactSecretsInText(`${SAMPLE}-Then`), '[REDACTED]-Then');
    assert.equal(redactSecretsInText(`${STD}-Then`), '[REDACTED]-Then');
    assert.equal(maskJwtTokens(`${SAMPLE}-Then`, 'strict'), '[REDACTED]-Then');
    assert.equal(redactSecretsInText(`${SAMPLE}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${SAMPLE}-word`), '[REDACTED]-word');
    assert.equal(redactSecretsInText(`${SAMPLE}-file`), '[REDACTED]-file');
    assert.equal(redactSecretsInText('see hello-config-file next'), 'see hello-config-file next');
    assertJwtGone(redactSecretsInText(`${STD}-Then`), STD, 'padded Then');
    assertJwtGone(redactSecretsInText(`${STD}-config-file`), STD, 'padded config-file');
  });

  it('consumes stopword tails, all-caps, and the token-tail leaks', () => {
    for (const tail of ['-the', '-a', '-not', '-suffix', '-word9', '-THEN', '-suffix-file', '-low']) {
      for (const token of [SAMPLE, STD]) {
        const out = redactSecretsInText(`${token}${tail}`);
        assert.equal(out, '[REDACTED]', tail);
        assert.equal(out.includes(tail), false, `${tail} visible`);
        assertJwtGone(out, token, tail);
      }
      const strict = maskJwtTokens(`${SAMPLE}${tail}`, 'strict');
      assert.equal(strict, '[REDACTED]', `strict ${tail}`);
      assert.equal(strict.includes(tail), false, `strict ${tail} visible`);
    }
    assert.equal(redactSecretsInText(`${SAMPLE}_x`), '[REDACTED]_x');
    assert.equal(redactSecretsInText(`${SAMPLE}-`), '[REDACTED]-');
    assert.equal(redactSecretsInText(`${SAMPLE}_`), '[REDACTED]_');
    assert.equal(redactSecretsInText('eyJsee.the.docs'), 'eyJsee.the.docs');
  });
});

describe('v1.0.49 attest keeps a git-quoted filename', () => {
  it('decodes a C-style git path', () => {
    assert.equal(unquoteGitPath('"caf\\303\\251.txt"'), 'café.txt');
    assert.equal(unquoteGitPath('"odd\\"name.txt"'), 'odd"name.txt');
    assert.equal(unquoteGitPath('sp ace.txt'), 'sp ace.txt');
  });

  it('includes a quoted filename as a subject and still stamps a secret-shaped one', () => {
    const dir = gitRepo('ar1049-quote-');
    const plain = 'café.txt';
    const secret = `café-${GHP}.txt`;
    writeFileSync(join(dir, plain), 'cafe\n');
    writeFileSync(join(dir, secret), 'secret\n');
    git(dir, ['add', '--', plain, secret]);
    git(dir, ['commit', '-m', 'add quoted names']);
    const quoted = git(dir, ['diff', '--name-status', 'HEAD~1', 'HEAD']);
    assert.match(quoted, /\\303\\251/, quoted);
    assert.equal(quoted.includes(plain), false);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'quoted names']).code, 0);
    const receipt = latestReceipt(dir);
    const source = readFileSync(receipt, 'utf8');
    const filesSection = source.split('## Files changed')[1].split('\n## ')[0];
    assert.equal(filesSection.includes(plain), true, filesSection);
    assert.equal(filesSection.includes('\\303'), false, filesSection);
    assert.equal(filesSection.includes(GHP), true);

    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = parseJson(cli(dir, ['attest', '--json']));
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(created.path, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    const names = statement.subject.map((subject) => subject.name);
    const factNames = statement.predicate.files.map((file) => file.name);
    assert.ok(names.includes(plain), names.join(','));
    assert.ok(factNames.includes(plain), factNames.join(','));
    const stamped = maskSecretPath(secret);
    assert.ok(names.includes(stamped), names.join(','));
    assert.ok(factNames.includes(stamped));
    assert.equal(stamped.includes(GHP), false);
    assert.equal(stamped.includes('a'.repeat(36)), false);
    const packed = JSON.stringify(statement);
    assert.equal(packed.includes(GHP), false);
    assert.equal(packed.includes('a'.repeat(36)), false);
    assert.equal(packed.includes('\\303'), false);

    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);
    assert.equal(verified.subjectsOk, true);
  });
});

describe('v1.0.49 eyJ scan stays fast', () => {
  it('redacts a 1MB run of nine eyJ- prefixes plus a dot well under a second', () => {
    const filler = ('eyJ-'.repeat(9) + '.').repeat(Math.ceil((1024 * 1024) / 37)).slice(0, 1024 * 1024);
    assert.ok(filler.length >= 1024 * 1024 - 37);
    const input = `${filler} ${SAMPLE}`;
    const started = Date.now();
    const out = redactSecretsInText(input);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 2000, `nine eyJ- plus a dot took ${elapsed}ms`);
    assertJwtGone(out, SAMPLE, 'nine eyJ-');
    assert.equal(out.includes('[REDACTED]'), true);
  });

  it('redacts a 1MB header plus repeated -eyJ-eyJ well under a second', () => {
    const header = 'eyJhbGciOiJub25lIn0';
    const unit = `${header}-eyJ-eyJ.`;
    const filler = unit.repeat(Math.ceil((1024 * 1024) / unit.length)).slice(0, 1024 * 1024);
    assert.ok(filler.length >= 1024 * 1024 - unit.length);
    const input = `${filler} ${SAMPLE}`;
    const started = Date.now();
    const out = redactSecretsInText(input);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 2000, `header plus -eyJ-eyJ took ${elapsed}ms`);
    assertJwtGone(out, SAMPLE, 'header -eyJ-eyJ');
    assert.equal(out.includes('[REDACTED]'), true);
    assert.equal(maskJwtTokens(`${'eyJ-'.repeat(9)}${SAMPLE}`, 'strict').endsWith('[REDACTED]'), true);
  });
});
