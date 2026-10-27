/**
 * v1.0.51 — Release QA follow-ups from v1.0.50.
 * A padded standard-base64 JWT glued with + / _ = is masked, a clear
 * path glued with / or + stays, backtick filenames stay in the receipt
 * and attest, plain history/show/compare mask commit-message secrets,
 * and an old git-quoted path decodes once.
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
import { appendHashFooter } from '../dist/lib/hash.js';
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

function assertSecretGone(text, label) {
  assert.equal(text.includes(GHP), false, `${label} ghp`);
  assert.equal(text.includes(AKIA), false, `${label} akia`);
  assert.equal(text.includes('a'.repeat(36)), false, `${label} token body`);
}

function tablePaths(markdown) {
  const section = markdown.split('## Files changed')[1].split('\n## ')[0];
  const paths = [];
  for (const line of section.split('\n')) {
    const match = line.match(/^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|/);
    if (!match) continue;
    const status = match[1].trim();
    if (!status || status === 'Status' || /^-+$/.test(status)) continue;
    paths.push({ cell: match[2], path: decodeReceiptTablePath(match[2]) });
  }
  return paths;
}

function statementOf(dir, receiptPath) {
  assert.equal(cli(dir, ['keygen']).code, 0);
  const args = receiptPath ? ['attest', receiptPath, '--json'] : ['attest', '--json'];
  const created = parseJson(cli(dir, args));
  const statement = JSON.parse(Buffer.from(
    JSON.parse(readFileSync(created.path, 'utf8').trim()).payload,
    'base64',
  ).toString('utf8'));
  return { created, statement };
}

describe('v1.0.51 padded JWT joined by + / _ =', () => {
  for (const joiner of ['+', '/', '_', '=']) {
    it(`masks a padded token before ${JSON.stringify(joiner)} and leaves no raw JWT substring`, () => {
      const glued = `${STD}${joiner}hello`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(glued, mode);
        assert.equal(out, `[REDACTED]${joiner}hello`, `${mode} ${out}`);
        assertJwtGone(out, STD, `${mode} ${joiner}`);
      }
      const text = redactSecretsInText(glued);
      assert.equal(text, `[REDACTED]${joiner}hello`, text);
      assertJwtGone(text, STD, `text ${joiner}`);
      assert.equal(text.includes('hello'), true);
    });
  }

  it('masks the reported =+hello trailer on every redaction helper', () => {
    const raw = `${STD}=+hello`;
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(raw, mode);
      assert.equal(out, '[REDACTED]=+hello', `${mode} ${out}`);
      assertJwtGone(out, STD, mode);
    }
    const text = redactSecretsInText(`see ${raw} later`);
    assert.equal(text, 'see [REDACTED]=+hello later');
    assertJwtGone(text, STD, 'sentence');
  });

  it('takes two pads only when one pad is not a valid segment', () => {
    const two = 'eyJhbGciOiJub25lIn0=.+//v+w==.ab==+hello';
    const out = redactSecretsInText(two);
    assert.equal(out, '[REDACTED]+hello', out);
    assert.equal(out.includes('eyJhbGciOiJub25lIn0='), false);
    assert.equal(out.includes('+//v+w=='), false);
    assert.equal(out.includes('ab=='), false);
  });

  it('still splits two tokens and keeps whole-word hyphen suffixes', () => {
    for (const joiner of ['+', '/', '_', '=', '-']) {
      assert.equal(
        redactSecretsInText(`${SAMPLE}${joiner}${SAMPLE}`),
        `[REDACTED]${joiner}[REDACTED]`,
        joiner,
      );
      assert.equal(
        redactSecretsInText(`${STD}${joiner}${STD}`),
        `[REDACTED]${joiner}[REDACTED]`,
        `std ${joiner}`,
      );
    }
    assert.equal(redactSecretsInText(`${SAMPLE}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${SAMPLE}-Then`), '[REDACTED]-Then');
    assert.equal(redactSecretsInText(`${SAMPLE}-config-file`), '[REDACTED]-config-file');
    assert.equal(redactSecretsInText(`${STD}-Then`), '[REDACTED]-Then');
    assert.equal(redactSecretsInText(`${STD}-config-file`), '[REDACTED]-config-file');
    assert.equal(redactSecretsInText(`${SAMPLE}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-low`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${STD}-suffix`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${STD}-low`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}_x`), '[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-`), '[REDACTED]');
    const url = redactSecretsInText(`https://example.com/${SAMPLE}`);
    assert.equal(url, 'https://example.com/[REDACTED]');
    assertJwtGone(url, SAMPLE, 'url');
  });

  it('stays linear on a long padded-joiner run', () => {
    const blob = `${STD}=+hello\n`.repeat(20000);
    const started = Date.now();
    const out = redactSecretsInText(blob);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 8000, `elapsed ${elapsed}ms`);
    assertJwtGone(out, STD, 'timing');
    assert.equal(out.includes('=+hello'), true);
  });
});

describe('v1.0.51 path glued after a JWT', () => {
  const kept = [
    [`${SAMPLE}/src/app.ts`, '[REDACTED]/src/app.ts'],
    [`${SAMPLE}/file.ts`, '[REDACTED]/file.ts'],
    [`${SAMPLE}+src/app.ts`, '[REDACTED]+src/app.ts'],
    [`${SAMPLE}+/src/app.ts`, '[REDACTED]+/src/app.ts'],
    [`${SAMPLE}+lib/index.js`, '[REDACTED]+lib/index.js'],
    [`${STD}/src/app.ts`, '[REDACTED]/src/app.ts'],
    [`${STD}+src/app.ts`, '[REDACTED]+src/app.ts'],
    [`see ${SAMPLE}/docs/readme.md later`, 'see [REDACTED]/docs/readme.md later'],
    [`https://example.com/${STD}/file.ts`, 'https://example.com/[REDACTED]/file.ts'],
  ];

  for (const [raw, expect] of kept) {
    it(`keeps the path in ${expect}`, () => {
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        assert.equal(out, expect, `${mode} ${out}`);
      }
      const text = redactSecretsInText(raw);
      assert.equal(text, expect, text);
      assertJwtGone(text, raw.includes(STD) ? STD : SAMPLE, expect);
    });
  }

  it('still consumes a + tail that is not a path', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}+hello`), '[REDACTED]');
    assertJwtGone(redactSecretsInText(`${SAMPLE}+hello`), SAMPLE, 'plus hello');
  });

  it('prefers no leak when an empty signature is glued to a path', () => {
    const out = redactSecretsInText(`${JWT_DIR}/src/app.ts`);
    assert.equal(out, '[REDACTED].ts', out);
    assertJwtGone(out, JWT_DIR, 'empty signature');
    assert.equal(out.includes('/src/app'), false);
  });
});

describe('v1.0.51 backtick filenames', () => {
  it('round-trips a backtick through the receipt table quoting', () => {
    for (const name of ['has`tick.txt', 'a"b`c.txt', 'has\n`tick.txt']) {
      const quoted = quoteReceiptTablePath(name);
      assert.equal(quoted.includes('`'), false, quoted);
      assert.equal(quoted.includes('\\140'), true, quoted);
      assert.equal(decodeReceiptTablePath(quoted), name);
      assert.equal(decodeReceiptTablePath(decodeReceiptTablePath(quoted)), name);
    }
  });

  it('includes a backtick name in the files table and as an attest subject', () => {
    const dir = gitRepo('ar1051-tick-');
    const plain = 'has`tick.txt';
    const secret = `has\`${GHP}.txt`;
    writeFileSync(join(dir, plain), 'tick\n');
    writeFileSync(join(dir, secret), 'secret-name\n');
    git(dir, ['add', '--', plain, secret]);
    git(dir, ['commit', '-m', 'add backtick names']);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'backtick names']).code, 0);
    const source = readFileSync(latestReceipt(dir), 'utf8');
    const paths = tablePaths(source).map((row) => row.path);
    assert.ok(paths.includes(plain), paths.map((p) => JSON.stringify(p)).join(' | '));
    assert.ok(paths.includes(secret), paths.map((p) => JSON.stringify(p)).join(' | '));
    assert.equal(source.includes('\\140'), true, source);

    const { created, statement } = statementOf(dir);
    const names = statement.subject.map((subject) => subject.name);
    const factNames = statement.predicate.files.map((file) => file.name);
    assert.ok(names.includes(plain), names.map((n) => JSON.stringify(n)).join(' | '));
    assert.ok(factNames.includes(plain));
    const stamped = maskSecretPath(secret);
    assert.equal(stamped.includes(GHP), false);
    assert.ok(names.includes(stamped), names.map((n) => JSON.stringify(n)).join(' | '));
    assert.ok(factNames.includes(stamped));
    assertSecretGone(JSON.stringify(statement), 'statement');

    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);
    assert.equal(verified.subjectsOk, true);
  });
});

describe('v1.0.51 plain history, show, and compare redact commit messages', () => {
  it('masks a ghp_ and AKIA that were only in the commit message', () => {
    const dir = gitRepo('ar1051-msg-');
    const subject = `ship ${GHP} and ${AKIA}`;
    writeFileSync(join(dir, 'notes.txt'), 'plain\n');
    git(dir, ['add', 'notes.txt']);
    git(dir, ['commit', '-m', subject]);

    assert.equal(cli(dir, ['capture', '--agent', 'cursor']).code, 0);
    const storedBare = readFileSync(latestReceipt(dir), 'utf8');
    assert.equal(storedBare.includes(GHP), true);
    const shownBare = cli(dir, ['show']);
    assert.equal(shownBare.code, 0, shownBare.err);
    assertSecretGone(shownBare.out, 'show without --message');
    assert.equal(shownBare.out.includes('ghp_[REDACTED]'), true, shownBare.out);
    const histBare = cli(dir, ['history']);
    assert.equal(histBare.code, 0, histBare.err);
    assertSecretGone(histBare.out, 'history without --message');

    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', subject]).code, 0);
    const stored = readFileSync(latestReceipt(dir), 'utf8');
    assert.equal(stored.includes(GHP), true);
    assert.equal(stored.includes(AKIA), true);
    const index = readFileSync(join(dir, '.agent-receipt', 'index.json'), 'utf8');
    assert.equal(index.includes(GHP), true);
    assert.equal(index.includes(AKIA), true);

    const hist = cli(dir, ['history']);
    assert.equal(hist.code, 0, hist.err);
    assertSecretGone(hist.out, 'history');
    assert.equal(hist.out.includes('ghp_[REDACTED]'), true, hist.out);
    assert.equal(hist.out.includes('AKIA[REDACTED:'), true, hist.out);

    const listed = cli(dir, ['history', '--json']);
    assert.equal(listed.code, 0, listed.err);
    assertSecretGone(listed.out, 'history --json');
    const messages = JSON.parse(listed.out).map((row) => row.message).filter(Boolean);
    assert.ok(messages.some((message) => message.includes('ghp_[REDACTED]')));
    assert.ok(messages.some((message) => message.includes('AKIA[REDACTED:')));

    const shown = cli(dir, ['show']);
    assert.equal(shown.code, 0, shown.err);
    assertSecretGone(shown.out, 'show');
    assert.equal(shown.out.includes('ghp_[REDACTED]'), true, shown.out);

    const compared = cli(dir, ['compare']);
    assert.equal(compared.code, 0, compared.err + compared.out);
    assertSecretGone(compared.out, 'compare');
    assert.equal(compared.out.includes('ghp_[REDACTED]'), true, compared.out);
    assert.equal(compared.out.includes('AKIA[REDACTED:'), true, compared.out);
  });
});

describe('v1.0.51 padded JWT on receipt, attest, history, show, and compare', () => {
  it('leaves no raw JWT substring on the redaction surfaces', () => {
    const dir = gitRepo('ar1051-jwt-');
    const note = `note ${STD}=+hello`;
    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);

    const stored = readFileSync(latestReceipt(dir), 'utf8');
    assert.equal(stored.includes(STD), true);

    for (const [label, args] of [
      ['history', ['history']],
      ['history --json', ['history', '--json']],
      ['show', ['show']],
      ['compare', ['compare']],
    ]) {
      const result = cli(dir, args);
      assert.equal(result.code, 0, `${label} ${result.err}`);
      assertJwtGone(result.out, STD, label);
      assert.equal(result.out.includes('=+hello'), true, `${label} dropped the trailer`);
    }

    const { created, statement } = statementOf(dir, latestReceipt(dir));
    const packed = JSON.stringify(statement);
    assertJwtGone(packed, STD, 'attest');
    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);

    writeFileSync(join(dir, 'token.txt'), `${note}\nagain\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'edit token']);
    assert.equal(cli(dir, ['capture', '--redact', '--agent', 'cursor', '--message', note]).code, 0);
    const redacted = readFileSync(latestReceipt(dir), 'utf8');
    assertJwtGone(redacted, STD, 'redacted receipt');
    assert.equal(redacted.includes('=+hello'), true, redacted);
  });
});

describe('v1.0.51 old git-quoted receipt names', () => {
  it('decodes a pre-1.0.49 quoted cell once', () => {
    const fixture = readFileSync(join(root, 'test/fixtures/v1.0.51/old-git-quoted.md'), 'utf8');
    const rows = tablePaths(fixture);
    const byPath = new Map(rows.map((row) => [row.path, row]));

    const cafe = 'caf\u00e9.txt';
    const han = 'dir/sub/\u4f60.txt';
    const wide = `pre${String.fromCodePoint(0x100)}post`;
    assert.equal(byPath.get(cafe).cell, '"caf\\303\\251.txt"');
    assert.equal(unquoteGitPath(byPath.get(cafe).cell), cafe);
    assert.equal(unquoteGitPath(cafe), cafe);
    assert.equal(decodeReceiptTablePath(cafe), cafe);
    assert.equal(byPath.get(han).path, han);
    assert.equal(han.endsWith('\u4f60.txt'), true);
    assert.equal(byPath.get(wide).path, wide);
    assert.equal(wide.includes('\0'), false, '\\\\400 must not become NUL');
    assert.equal(byPath.get('foo\\bar.txt').path, 'foo\\bar.txt');
    assert.equal(byPath.get('foo\\bar.txt').path.includes('\b'), false);
    assert.equal(byPath.get('plain.txt').path, 'plain.txt');

    for (const row of rows) {
      assert.equal(decodeReceiptTablePath(row.path), row.path);
      assert.equal(row.path.includes('\0'), false);
    }
  });

  it('re-parses an old quoted cell from a rewritten receipt', () => {
    const dir = gitRepo('ar1051-old-');
    const cafe = 'caf\u00e9.txt';
    writeFileSync(join(dir, cafe), 'cafe\n');
    git(dir, ['add', '--', cafe]);
    git(dir, ['commit', '-m', 'add cafe']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'old quote']).code, 0);

    const path = latestReceipt(dir);
    const fixture = readFileSync(join(root, 'test/fixtures/v1.0.51/old-git-quoted.md'), 'utf8');
    const oldCell = tablePaths(fixture).find((row) => row.path === cafe).cell;
    const source = readFileSync(path, 'utf8');
    assert.equal(source.includes(`\`${cafe}\``), true, source);
    const rewritten = appendHashFooter(source.replaceAll(`\`${cafe}\``, `\`${oldCell}\``));
    assert.equal(rewritten.includes(oldCell), true);
    writeFileSync(path, rewritten);

    const names = tablePaths(rewritten).map((row) => row.path);
    assert.ok(names.includes(cafe), names.map((n) => JSON.stringify(n)).join(' | '));
    assert.equal(names.some((name) => name.includes('\0')), false);

    const { created, statement } = statementOf(dir, path);
    const subjects = statement.subject.map((subject) => subject.name);
    const facts = statement.predicate.files.map((file) => file.name);
    assert.ok(subjects.includes(cafe), subjects.map((n) => JSON.stringify(n)).join(' | '));
    assert.ok(facts.includes(cafe));
    assert.equal(JSON.stringify(statement).includes('\\303\\251'), false);
    const verified = parseJson(cli(dir, ['attest', '--verify', created.path, '--json']));
    assert.equal(verified.ok, true);
    assert.equal(verified.subjectsOk, true);
  });
});
