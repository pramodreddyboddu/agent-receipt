/**
 * v1.0.48 — Release QA follow-ups from v1.0.47.
 * A real JWT after a long glued eyJ prefix is masked, ghp_ filenames are
 * stamped in share and attest, two JWTs joined by one hyphen are both
 * masked, and an ordinary hyphenated word stays visible.
 * The 64KB and 1MB timing bounds stay in test/v1.0.47-redact-followups.test.js.
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
  maskSecretPath,
  redactMarkdownBody,
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
const JWT_DIR = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJxYSJ9.';
const STD = 'eyJhbGciOiJub25lIn0=.+//v+w==.+y8=';
const KEY = 'AKIAIOSFODNN7EXAMPLE';
const GHP_A = `ghp_${'a'.repeat(36)}`;
const GHP_B = `ghp_${'b'.repeat(36)}`;

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

function latestReceipt(dir) {
  const out = join(dir, '.agent-receipt', 'receipts');
  const files = readdirSync(out)
    .filter((name) => name.endsWith('.md') && !name.endsWith('.prove.md'))
    .map((name) => join(out, name));
  assert.ok(files.length > 0, 'expected a receipt');
  return files.sort()[files.length - 1];
}

function mixedPrefixes(count) {
  const units = ['eyJ-', 'eyJ_', 'eyJ='];
  let out = '';
  for (let i = 0; i < count; i += 1) out += units[i % units.length];
  return out;
}

function assertJwtGone(text, token, label) {
  const [header, payload, signature] = token.split('.');
  assert.equal(text.includes(header), false, `${label} header`);
  assert.equal(text.includes(payload), false, `${label} payload`);
  if (signature) assert.equal(text.includes(signature), false, `${label} signature`);
}

describe('v1.0.48 JWT after a long glued prefix', () => {
  for (const unit of ['eyJ-', 'eyJ_', 'eyJ=']) {
    it(`masks a real JWT after nine glued ${unit} prefixes`, () => {
      const input = `${unit.repeat(9)}${SAMPLE}`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(input, mode);
        assert.equal(out, `${unit.repeat(9)}[REDACTED]`, mode);
        assertJwtGone(out, SAMPLE, `${unit} ${mode}`);
      }
      assert.equal(redactSecretsInText(input), `${unit.repeat(9)}[REDACTED]`);
    });
  }

  it('masks a real JWT after twelve and forty mixed prefixes', () => {
    for (const count of [12, 40]) {
      const prefix = mixedPrefixes(count);
      const input = `${prefix}${SAMPLE}`;
      const out = redactSecretsInText(input);
      assert.equal(out, `${prefix}[REDACTED]`, String(count));
      assertJwtGone(out, SAMPLE, String(count));
      assert.equal(maskJwtTokens(input, 'strict'), `${prefix}[REDACTED]`);
    }
  });

  it('still masks a real JWT that fits inside the restart cap', () => {
    const prefix = 'eyJ-'.repeat(8);
    assert.equal(redactSecretsInText(`${prefix}${SAMPLE}`), `${prefix}[REDACTED]`);
  });
});

describe('v1.0.48 ghp_ filename in share', () => {
  it('stamps a ghp_ path segment and leaves an AKIA filename on its key stamp', () => {
    const fileA = `${GHP_A}.txt`;
    const fileB = `${GHP_B}.txt`;
    assert.equal(maskSecretPath(fileA), `ghp_[REDACTED:${secretMaskStamp(fileA)}].txt`);
    assert.equal(maskSecretPath(fileB), `ghp_[REDACTED:${secretMaskStamp(fileB)}].txt`);
    assert.notEqual(maskSecretPath(fileA), maskSecretPath(fileB));
    assert.equal(maskSecretPath(`dir/${fileA}`), `dir/ghp_[REDACTED:${secretMaskStamp(fileA)}].txt`);
    assert.equal(redactSecretsInText(GHP_A), 'ghp_[REDACTED]');
    const akiaName = `notes-${KEY}.txt`;
    assert.equal(maskSecretPath(akiaName), redactSecretsInText(akiaName));
    assert.equal(maskSecretPath(akiaName).includes(KEY), false);

    const heading = redactMarkdownBody(`## Diff summaries\n\n### \`${fileA}\`\n\n| A | \`${fileA}\` |\n`);
    assert.equal(heading.includes(GHP_A), false);
    assert.equal(heading.includes('a'.repeat(36)), false);
    assert.match(heading, new RegExp(`### \`ghp_\\[REDACTED:${secretMaskStamp(fileA)}\\]\\.txt\``));
  });

  it('omits a raw ghp_ filename from share markdown and receipt.html', () => {
    const dir = gitRepo('ar1048-ghp-');
    const fileName = `${GHP_A}.txt`;
    writeFileSync(join(dir, fileName), 'notes\n');
    git(dir, ['add', fileName]);
    git(dir, ['commit', '-m', 'add named file']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'named file']).code, 0);
    const receipt = latestReceipt(dir);
    const source = readFileSync(receipt, 'utf8');
    assert.equal(source.includes(GHP_A), true, 'source receipt should still name the file');

    const sharedResult = cli(dir, ['share', receipt, '--package', '--json']);
    const shared = parseJson(sharedResult);
    const md = readFileSync(shared.markdownPath, 'utf8');
    const html = readFileSync(shared.htmlPath, 'utf8');
    for (const [label, text] of [['markdown', md], ['html', html], ['stdout', sharedResult.out]]) {
      assert.equal(text.includes(GHP_A), false, `${label} still has the raw token`);
      assert.equal(text.includes('a'.repeat(36)), false, `${label} still has the token body`);
    }
    assert.match(md, /### `ghp_\[REDACTED:[0-9a-f]{12}\]\.txt`/);
    assert.match(html, /ghp_\[REDACTED:[0-9a-f]{12}\]\.txt/);
    assert.equal(cli(dir, ['verify', '--package', shared.packagePath]).code, 0);
  });
});

describe('v1.0.48 attest stamps a ghp_ filename', () => {
  it('stamps two ghp_ filenames differently and still verifies', () => {
    const dir = gitRepo('ar1048-attest-');
    const fileA = `${GHP_A}.txt`;
    const fileB = `${GHP_B}.txt`;
    writeFileSync(join(dir, fileA), 'a\n');
    writeFileSync(join(dir, fileB), 'b\n');
    git(dir, ['add', fileA, fileB]);
    git(dir, ['commit', '-m', 'add named files']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'named files']).code, 0);
    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = parseJson(cli(dir, ['attest', '--json']));
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(created.path, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    const names = statement.subject.map((subject) => subject.name);
    const factNames = statement.predicate.files.map((file) => file.name);
    assert.ok(names.includes(maskSecretPath(fileA)), names.join(','));
    assert.ok(names.includes(maskSecretPath(fileB)));
    assert.ok(factNames.includes(maskSecretPath(fileA)));
    assert.ok(factNames.includes(maskSecretPath(fileB)));
    assert.notEqual(maskSecretPath(fileA), maskSecretPath(fileB));
    const packed = JSON.stringify(statement);
    assert.equal(packed.includes(GHP_A), false);
    assert.equal(packed.includes(GHP_B), false);
    assert.equal(packed.includes('a'.repeat(36)), false);
    assert.equal(packed.includes('b'.repeat(36)), false);

    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);
    assert.equal(verified.subjectsOk, true);
  });
});

describe('v1.0.48 two JWTs joined by a hyphen', () => {
  it('masks both tokens and leaves no raw JWT material', () => {
    for (const [label, token] of [['sample', SAMPLE], ['std', STD], ['none', JWT_DIR]]) {
      const joined = `${token}-${token}`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(joined, mode);
        assert.equal(out, '[REDACTED]-[REDACTED]', `${label} ${mode}`);
        assertJwtGone(out, token, `${label} ${mode}`);
      }
    }
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}-${SAMPLE}`), '[REDACTED]-[REDACTED]-[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}-word`), '[REDACTED]-[REDACTED]-word');
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}-suffix`).includes('suffix'), false);
    assertJwtGone(redactSecretsInText(`${STD}-${STD}`), STD, 'std text');
  });
});

describe('v1.0.48 hyphenated word suffixes', () => {
  it('keeps an ordinary word and still consumes a token tail', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}-word`), '[REDACTED]-word');
    assert.equal(redactSecretsInText(`${STD}-word`), '[REDACTED]-word');
    assert.equal(maskJwtTokens(`${SAMPLE}-hello`, 'strict'), '[REDACTED]-hello');
    assert.equal(redactSecretsInText(`${SAMPLE}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${STD}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText('see hello-word next'), 'see hello-word next');

    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`).includes('suffix'), false);
    assert.equal(redactSecretsInText(`${STD}-suffix`).includes('suffix'), false);
    assert.equal(redactSecretsInText(`${SAMPLE}-word9`).includes('word9'), false);
    assert.equal(maskJwtTokens(`${SAMPLE}-low`, 'strict').includes('low'), false);
    assert.equal(maskJwtTokens(`${STD}-low`, 'general').includes('low'), false);
  });
});
