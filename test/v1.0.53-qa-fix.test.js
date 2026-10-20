/**
 * v1.0.53 Release QA re-gate.
 * Exact integrity-footer shapes, one ASCII whitespace definition,
 * repo-root relativePath, and a masked failed session-import path.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendHashFooter } from '../dist/lib/hash.js';
import { maskJwtTokens } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];

after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function keep(dir) {
  dirs.push(dir);
  return dir;
}

function b64url(text) {
  return Buffer.from(text).toString('base64url');
}

function jwtFor(alg, signature) {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'qa' }));
  return `${header}.${payload}.${signature}`;
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

describe('v1.0.53 RSA_GLUED_PATH_MAX is 48 in-segment characters', () => {
  it('keeps a clear path of 48 and masks a clear path of 49', () => {
    for (const [alg, length] of [['RS256', 342], ['PS512', 683]]) {
      const token = jwtFor(alg, 'A'.repeat(length));
      const keep = `/${'a'.repeat(46)}/`;
      assert.equal(keep.length, 48);
      assert.equal(maskJwtTokens(`${token}${keep}`), `[REDACTED]${keep}`, alg);
      const eat = `/${'b'.repeat(47)}/`;
      assert.equal(eat.length, 49);
      const eaten = maskJwtTokens(`${token}${eat}`);
      assert.equal(eaten.includes(eat), false, alg);
      assert.equal(eaten.includes('b'.repeat(20)), false, alg);
      assert.equal(maskJwtTokens(`${token}/src/app.ts`), '[REDACTED]/src/app.ts', alg);
    }
  });
});

describe('v1.0.53 exact footer and ASCII trailing whitespace', { concurrency: 1 }, () => {
  const other = 'ab'.repeat(32);
  const dir = keep(mkdtempSync(join(tmpdir(), 'ar1053qa-footer-')));
  const receipt = join(dir, 'receipt.md');
  const sealed = appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n');

  function write(text) {
    writeFileSync(receipt, text);
  }

  function verify(args) {
    return cli(dir, ['verify', receipt, ...args]);
  }

  function assertClean(args) {
    const result = verify(args);
    assert.equal(result.code, 0, `${args.join(' ')} ${result.err}${result.out}`);
    if (args.includes('--json')) {
      const body = JSON.parse(result.out);
      assert.equal(body.ok, true);
      assert.equal(body.verified, true);
      assert.equal(body.trailingIgnored, false);
    } else {
      assert.match(result.out, /OK/);
    }
  }

  function assertTrailing(args, text) {
    write(text);
    const result = verify(args);
    const label = args.join(' ');
    assert.equal(result.code, 2, `${label}\n${result.out}${result.err}`);
    if (args.includes('--json')) {
      const body = JSON.parse(result.out);
      assert.equal(body.ok, false, label);
      assert.equal(body.verified, false, label);
      assert.equal(body.exitCode, 2, label);
      assert.equal(body.trailingIgnored, true, label);
      assert.match(body.reason, /trailing content after the last chained record/);
      assert.equal(body.reason.includes('Hash mismatch'), false, label);
      assert.equal(body.reason.includes('signature'), false, label);
    } else {
      assert.match(result.err, /trailing content after the last chained record/);
      assert.doesNotMatch(result.out, /OK/);
    }
  }

  const appended = [
    ['heading line', `${sealed}\n## Integrity forged\n`],
    ['marker line', `${sealed}\n<!-- agent-receipt-sha256:${other} -->\n`],
    ['short marker line', `${sealed}\n<!-- agent-receipt-sha256:abcd -->\n`],
    ['prose line', `${sealed}\nSHA-256 of canonical body: \`${other}\`\n`],
    [
      'second footer',
      `${sealed}\n## Integrity\n\n<!-- agent-receipt-sha256:${other} -->\n\nSHA-256 of canonical body: \`${other}\`\n`,
    ],
    ['duplicated footer', sealed + sealed.slice(sealed.indexOf('\n## Integrity\n'))],
    [
      'prose hash differs',
      sealed.replace(
        /SHA-256 of canonical body: `[0-9a-f]{64}`/,
        `SHA-256 of canonical body: \`${other}\``,
      ),
    ],
    ['NBSP', `${sealed}\n\u00A0\n`],
    ['BOM', `${sealed}\n\uFEFF\n`],
    ['U+3000', `${sealed}\n\u3000\n`],
    ['U+2028', `${sealed}\n\u2028\n`],
  ];

  it('accepts a clean receipt and ASCII trailing whitespace', () => {
    write(sealed);
    assert.equal(cli(dir, ['keygen']).code, 0);
    assert.equal(cli(dir, ['sign', receipt]).code, 0);
    assertClean([]);
    assertClean(['--json']);
    assertClean(['--require-sig']);
    assertClean(['--json', '--require-sig']);
    for (const text of [`${sealed}\n`, `${sealed}\n\n`, `${sealed}\n   \n`, `${sealed}\n\t\n`]) {
      write(text);
      assertClean(['--json', '--require-sig']);
    }
  });

  for (const [name, text] of appended) {
    it(`fails verify on ${name}`, () => {
      assertTrailing(['--json'], text);
      assertTrailing([], text);
    });

    it(`fails verify --require-sig on ${name}`, () => {
      assertTrailing(['--json', '--require-sig'], text);
      assertTrailing(['--require-sig'], text);
    });
  }

  it('fails a short marker and a marker hash that is not the prose hash', () => {
    const short = sealed.replace(
      /<!-- agent-receipt-sha256:[0-9a-f]{64} -->/,
      '<!-- agent-receipt-sha256:abcd -->',
    );
    write(short);
    const shortJson = verify(['--json', '--require-sig']);
    assert.equal(shortJson.code, 2, shortJson.err + shortJson.out);
    const shortBody = JSON.parse(shortJson.out);
    assert.equal(shortBody.verified, false);
    assert.equal(shortBody.ok, false);
    assert.equal(shortBody.trailingIgnored, true);

    const different = sealed.replace(
      /<!-- agent-receipt-sha256:[0-9a-f]{64} -->/,
      `<!-- agent-receipt-sha256:${other} -->`,
    );
    write(different);
    const differentJson = verify(['--json', '--require-sig']);
    assert.equal(differentJson.code, 2, differentJson.err + differentJson.out);
    const differentBody = JSON.parse(differentJson.out);
    assert.equal(differentBody.verified, false);
    assert.equal(differentBody.ok, false);
    assert.equal(differentBody.trailingIgnored, true);
  });

  it('prove follows a trailing-content failure', () => {
    write(`${sealed}\n## Integrity forged\n`);
    const proved = cli(dir, ['prove', receipt, '--json']);
    assert.equal(proved.code, 2, proved.err + proved.out);
    const body = JSON.parse(proved.out);
    assert.equal(body.verified, false);
    assert.equal(body.trailingIgnored, true);
    assert.match(body.reason, /trailing content after the last chained record/);
  });
});

describe('v1.0.53 share relativePath from a subdirectory', () => {
  it('names the receipt from the repo root', () => {
    const dir = gitRepo('ar1053qa-rel-');
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'subdir']).code, 0);
    const receipt = latestReceipt(dir);
    const sub = join(dir, 'nested', 'deeper');
    mkdirSync(sub, { recursive: true });
    const shared = cli(sub, ['share', receipt, '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    const body = JSON.parse(shared.out);
    assert.equal(typeof body.relativePath, 'string');
    assert.equal(body.relativePath.includes('..'), false);
    assert.equal(existsSync(join(dir, body.relativePath)), true);
    assert.equal(existsSync(join(sub, body.relativePath)), false);
  });
});

describe('v1.0.53 failed session import masks a secret-shaped path', () => {
  it('does not print the raw directory in the error', () => {
    const secret = `ghp_${'c'.repeat(36)}`;
    const parent = keep(mkdtempSync(join(tmpdir(), 'ar1053qa-imp-')));
    const repo = join(parent, secret, 'repo');
    mkdirSync(repo, { recursive: true });
    const missing = join(repo, 'missing.session');
    const plain = cli(repo, ['session', 'import', missing]);
    assert.notEqual(plain.code, 0);
    const plainText = plain.out + plain.err;
    assert.equal(plainText.includes(secret), false, plainText);
    assert.equal(plainText.includes('c'.repeat(36)), false, plainText);
    assert.equal(plainText.includes('ghp_[REDACTED]'), true, plainText);
    assert.match(plainText, /session package not found/);

    const json = cli(repo, ['session', 'import', missing, '--json']);
    assert.notEqual(json.code, 0);
    const jsonText = json.out + json.err;
    assert.equal(jsonText.includes(secret), false, jsonText);
    assert.equal(jsonText.includes('c'.repeat(36)), false, jsonText);
    const body = JSON.parse(json.out);
    assert.match(body.reason, /session package not found/);
    assert.match(body.reason, /ghp_\[REDACTED\]/);
    assert.match(body.packagePath, /ghp_\[REDACTED\]/);
    assert.equal(body.packagePath.includes(secret), false);
  });
});
