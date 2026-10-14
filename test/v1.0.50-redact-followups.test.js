/**
 * v1.0.50 — Release QA follow-ups from v1.0.49.
 * Quoted non-ASCII paths stay intact, JWTs joined by + or / are masked,
 * backslash and newline filenames stay in the receipt and attest, and
 * history --json masks a ghp_ that arrived as a commit message.
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
  decodeReceiptTablePath,
  quoteReceiptTablePath,
  unquoteGitPath,
} from '../dist/lib/git.js';
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
const AKIA = 'AKIAIOSFODNN7EXAMPLE';

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
  git(dir, ['config', 'core.quotePath', 'true']);
  writeFileSync(join(dir, 'README.md'), '# qa\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial']);
  const init = cli(dir, ['init']);
  assert.equal(init.code, 0, init.err + init.out);
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

function tablePaths(markdown) {
  const section = markdown.split('## Files changed')[1].split('\n## ')[0];
  const paths = [];
  for (const line of section.split('\n')) {
    const match = line.match(/^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|/);
    if (!match) continue;
    const status = match[1].trim();
    if (!status || status === 'Status' || /^-+$/.test(status)) continue;
    paths.push(decodeReceiptTablePath(match[2]));
  }
  return paths;
}

function statementOf(dir) {
  assert.equal(cli(dir, ['keygen']).code, 0);
  const created = parseJson(cli(dir, ['attest', '--json']));
  const statement = JSON.parse(Buffer.from(
    JSON.parse(readFileSync(created.path, 'utf8').trim()).payload,
    'base64',
  ).toString('utf8'));
  return { created, statement };
}

describe('v1.0.50 unquoteGitPath keeps non-ASCII', () => {
  it('does not truncate raw non-ASCII or turn \\400 into NUL', () => {
    assert.equal(unquoteGitPath('"caf\u00e9\\\\notes.txt"'), 'caf\u00e9\\notes.txt');
    assert.equal(unquoteGitPath('"\u4f60\\\\x.txt"'), '\u4f60\\x.txt');
    assert.equal(unquoteGitPath('"\u0100\\\\x.txt"'), '\u0100\\x.txt');
    assert.equal(unquoteGitPath('"\u0100\\\\x.txt"').includes('\0'), false);
    assert.equal(unquoteGitPath('"\\400"'), '\u0100');
    assert.equal(unquoteGitPath('"pre\\400post"'), 'pre\u0100post');
    assert.equal(unquoteGitPath('"pre\\400post"').includes('\0'), false);
    assert.equal(unquoteGitPath('"\\304\\200.txt"'), '\u0100.txt');
    assert.equal(unquoteGitPath('"\\344\\275\\240.txt"'), '\u4f60.txt');
    assert.equal(unquoteGitPath('"caf\\303\\251.txt"'), 'caf\u00e9.txt');
    assert.equal(unquoteGitPath('caf\u00e9.txt'), 'caf\u00e9.txt');

    const mixed = 'has\n\u4f60.txt';
    const quoted = quoteReceiptTablePath(mixed);
    assert.equal(quoted.includes('\n'), false, quoted);
    assert.equal(decodeReceiptTablePath(quoted), mixed);
    assert.equal(quoteReceiptTablePath('foo\\bar.txt'), 'foo\\bar.txt');
  });

  it('keeps quotePath=false non-ASCII names in the files table and attest subjects', () => {
    const dir = gitRepo('ar1050-utf8-');
    git(dir, ['config', 'core.quotePath', 'false']);
    const plain = 'caf\u00e9.txt';
    const han = '\u4f60\u597d.txt';
    const wide = '\u0100\\x.txt';
    writeFileSync(join(dir, plain), 'cafe\n');
    writeFileSync(join(dir, han), 'han\n');
    writeFileSync(join(dir, wide), 'wide\n');
    git(dir, ['add', '--', plain, han, wide]);
    git(dir, ['commit', '-m', 'add non-ascii names']);
    const listed = git(dir, ['diff', '--name-status', 'HEAD~1', 'HEAD']);
    assert.equal(listed.includes(plain), true, listed);
    assert.equal(listed.includes(han), true, listed);
    assert.equal(listed.includes('\0'), false, listed);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'utf8 names']).code, 0);
    const source = readFileSync(latestReceipt(dir), 'utf8');
    const paths = tablePaths(source);
    for (const name of [plain, han, wide]) {
      assert.ok(paths.includes(name), `${name} missing from ${paths.join(' | ')}`);
    }
    assert.equal(source.includes('\0'), false);

    const { created, statement } = statementOf(dir);
    const names = statement.subject.map((subject) => subject.name);
    const factNames = statement.predicate.files.map((file) => file.name);
    for (const name of [plain, han, wide]) {
      assert.ok(names.includes(name), `${name} missing from ${names.join(' | ')}`);
      assert.ok(factNames.includes(name), `${name} missing from ${factNames.join(' | ')}`);
    }
    assert.equal(JSON.stringify(statement).includes('\0'), false);
    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);
    assert.equal(verified.subjectsOk, true);
  });
});

describe('v1.0.50 JWTs joined by + or /', () => {
  for (const joiner of ['+', '/']) {
    it(`masks both tokens joined by ${joiner} and leaves no raw JWT substring`, () => {
      for (const [label, token] of [['sample', SAMPLE], ['std', STD], ['none', JWT_DIR]]) {
        const joined = `${token}${joiner}${token}`;
        for (const mode of ['general', 'strict']) {
          const out = maskJwtTokens(joined, mode);
          assert.equal(out, `[REDACTED]${joiner}[REDACTED]`, `${label} ${mode} ${out}`);
          assertJwtGone(out, token, `${label} ${mode} ${joiner}`);
        }
        const text = redactSecretsInText(joined);
        assert.equal(text, `[REDACTED]${joiner}[REDACTED]`, `${label} ${text}`);
        assertJwtGone(text, token, `${label} text ${joiner}`);
      }
      const triple = `${SAMPLE}${joiner}${SAMPLE}${joiner}${SAMPLE}`;
      const masked = redactSecretsInText(triple);
      assert.equal(masked, `[REDACTED]${joiner}[REDACTED]${joiner}[REDACTED]`);
      assertJwtGone(masked, SAMPLE, `triple ${joiner}`);
    });
  }

  it('still masks _ = and hyphen joins and keeps whole-word suffixes', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}_${SAMPLE}`), '[REDACTED]_[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}=${SAMPLE}`), '[REDACTED]=[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}`), '[REDACTED]-[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${SAMPLE}-Then`), '[REDACTED]-Then');
    assert.equal(redactSecretsInText(`${SAMPLE}-config-file`), '[REDACTED]-config-file');
    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-low`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${STD}+${STD}`).includes('+//v+w=='), false);
    const url = `https://example.com/${SAMPLE}`;
    const masked = redactSecretsInText(url);
    assert.equal(masked, 'https://example.com/[REDACTED]');
    assertJwtGone(masked, SAMPLE, 'url');
  });

  it('masks a JWT after an eyJ+ or eyJ/ prefix run', () => {
    for (const sep of ['+', '/']) {
      const filler = (`eyJ${sep}`.repeat(9) + '.').repeat(40);
      const out = redactSecretsInText(`${filler} ${SAMPLE}`);
      assertJwtGone(out, SAMPLE, `prefix ${sep}`);
      assert.equal(out.includes('[REDACTED]'), true);
    }
  });
});

describe('v1.0.50 backslash and newline filenames', () => {
  it('includes both in the files table and as attest subjects', () => {
    const dir = gitRepo('ar1050-nl-');
    const back = 'foo\\bar.txt';
    const nl = 'has\nnewline.txt';
    const secretBack = `foo\\${GHP}.txt`;
    const secretNl = `has\n${GHP}.txt`;
    for (const name of [back, nl, secretBack, secretNl]) {
      writeFileSync(join(dir, name), 'plain\n');
    }
    git(dir, ['add', '--', back, nl, secretBack, secretNl]);
    git(dir, ['commit', '-m', 'add awkward names']);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'awkward names']).code, 0);
    const source = readFileSync(latestReceipt(dir), 'utf8');
    const paths = tablePaths(source);
    for (const name of [back, nl, secretBack, secretNl]) {
      assert.ok(paths.includes(name), `${JSON.stringify(name)} missing from ${paths.map((p) => JSON.stringify(p)).join(' | ')}`);
    }
    const quotedNl = quoteReceiptTablePath(nl);
    assert.equal(source.split('\n').some((line) => line.includes(`\`${quotedNl}\``)), true, source);
    assert.equal(source.includes(`\`${back}\``), true);

    const { created, statement } = statementOf(dir);
    const names = statement.subject.map((subject) => subject.name);
    const factNames = statement.predicate.files.map((file) => file.name);
    for (const name of [back, nl]) {
      assert.ok(names.includes(name), `${JSON.stringify(name)} missing from subjects`);
      assert.ok(factNames.includes(name), `${JSON.stringify(name)} missing from facts`);
    }
    for (const name of [secretBack, secretNl]) {
      const stamped = maskSecretPath(name);
      assert.equal(stamped.includes(GHP), false);
      assert.equal(stamped.includes('a'.repeat(36)), false);
      assert.ok(names.includes(stamped), `${JSON.stringify(stamped)} missing from ${names.map((n) => JSON.stringify(n)).join(' | ')}`);
      assert.ok(factNames.includes(stamped));
    }
    const packed = JSON.stringify(statement);
    assert.equal(packed.includes(GHP), false);
    assert.equal(packed.includes('a'.repeat(36)), false);

    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);
    assert.equal(verified.subjectsOk, true);
  });
});

describe('v1.0.50 history --json redacts commit-message secrets', () => {
  it('does not print a ghp_ or AKIA that was only in the commit message', () => {
    const dir = gitRepo('ar1050-hist-');
    writeFileSync(join(dir, 'notes.txt'), 'plain\n');
    git(dir, ['add', 'notes.txt']);
    git(dir, ['commit', '-m', `ship ${GHP} and ${AKIA}`]);
    const subject = git(dir, ['log', '-1', '--format=%s']);
    assert.equal(subject.includes(GHP), true);
    assert.equal(subject.includes(AKIA), true);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor']).code, 0);
    const bare = cli(dir, ['history', '--json']);
    assert.equal(bare.code, 0, bare.err + bare.out);
    assert.equal(bare.out.includes(GHP), false, bare.out);
    assert.equal(bare.out.includes(AKIA), false, bare.out);
    assert.equal(bare.out.includes('a'.repeat(36)), false, bare.out);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', subject]).code, 0);
    const listed = cli(dir, ['history', '--json']);
    assert.equal(listed.code, 0, listed.err + listed.out);
    assert.equal(listed.out.includes(GHP), false, listed.out);
    assert.equal(listed.out.includes(AKIA), false, listed.out);
    assert.equal(listed.out.includes('a'.repeat(36)), false, listed.out);
    const rows = JSON.parse(listed.out);
    const messages = rows.map((row) => row.message).filter(Boolean);
    assert.ok(messages.some((message) => message.includes('ghp_[REDACTED]')));
    assert.ok(messages.some((message) => message.includes('AKIA[REDACTED:')));
  });
});
