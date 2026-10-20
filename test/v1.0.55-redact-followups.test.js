/**
 * v1.0.55 — Release QA follow-ups from v1.0.54.
 * RSA short-tail redaction, glued filename paths, non-git relativePath,
 * and not-found path masking.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
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
import { maskJwtTokens, redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const RSA_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
const SPOTS = [342, 512, 683];
const TRAILER = '\u0001';

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

/** No 3+ character slice of `tail` outside `[REDACTED]`. */
function assertNoRawTail(text, tail, label) {
  const residue = text.split('[REDACTED]').join('');
  assert.equal(residue.includes(tail), false, `${label} kept ${tail}`);
  for (let n = 3; n <= tail.length; n += 1) {
    for (let i = 0; i + n <= tail.length; i += 1) {
      const window = tail.slice(i, i + n);
      assert.equal(residue.includes(window), false, `${label} kept ${window}`);
    }
  }
}

/**
 * Receipt chrome shares short slices with some tails (`/dev/null`,
 * `older/second`, a temp directory that happens to end in the same
 * letters). Drop those fixed strings, then apply the same 3+ check.
 */
function assertNoRawTailOnSurface(text, tail, label, extra) {
  let residue = text.split('[REDACTED]').join('');
  for (const chrome of ['/dev/null', 'b/token.txt', 'b/README.md', extra]) {
    if (chrome) residue = residue.split(chrome).join('');
  }
  assertNoRawTail(residue, tail, label);
}

function assertTailMasked(alg, at, tail) {
  const signature = `${'A'.repeat(at)}${tail}`;
  const token = jwtFor(alg, signature);
  for (const mode of ['general', 'strict']) {
    const out = maskJwtTokens(`${token}${TRAILER}`, mode);
    assertNoRawTail(out, tail, `${alg} ${at} ${mode}`);
    assert.equal(out.includes('A'.repeat(8)), false, `${mode} leaked the prefix`);
    assert.equal(out.includes(TRAILER), true, `${mode} ate the trailer`);
  }
  const text = redactSecretsInText(`${token}${TRAILER}`);
  assertNoRawTail(text, tail, `${alg} ${at} text`);
  assert.equal(text.includes('A'.repeat(8)), false, 'text leaked the prefix');
}

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state;
  };
}

describe('v1.0.55 short RSA tails are redacted', () => {
  const fixed = ['/qb/m', '/abc/de', '+/kv', '//nps', '/x7/k', '+a/bcd', '/aaa/aa', '/a/b/c', '/Ab/c'];

  it('masks fixed 3–7 character tails on every RSA length', () => {
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        for (const tail of fixed) {
          assert.ok(tail.length >= 3 && tail.length <= 7, tail);
          assertTailMasked(alg, at, tail);
        }
      }
    }
  });

  it('masks randomized 3–7 character tails', () => {
    const next = lcg(0x1055);
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789/+';
    for (let n = 0; n < 64; n += 1) {
      const alg = RSA_ALGS[next() % RSA_ALGS.length];
      const at = SPOTS[next() % SPOTS.length];
      const len = 3 + (next() % 5);
      let tail = next() % 2 === 0 ? '/' : '+';
      for (let i = 1; i < len; i += 1) {
        tail += alphabet[next() % alphabet.length];
      }
      // Half the draws plant a slash so they match the old clear-path leak.
      if (next() % 2 === 0 && len > 1) {
        const pos = 1 + (next() % (len - 1));
        tail = `${tail.slice(0, pos)}/${tail.slice(pos + 1)}`;
      }
      assert.equal(tail.length, len);
      assertTailMasked(alg, at, tail);
    }
  });
});

describe('v1.0.55 glued filename paths stay after an exact RSA signature', () => {
  const kept = [
    '/src/App.tsx',
    '/docs/README.md',
    '/README.md',
    '/src/App.js',
    '/src/App.json',
    '/src/App.test.tsx',
    '/Src/lib/App.tsx',
    '/App.md',
    '/ab.ts',
    '/a/b.js',
    '/src/app.ts',
    '+src/app.ts',
    '+/src/app.ts',
    '/src/index.js',
    '/docs/guide.json',
  ];

  it('keeps filename shapes and masks the signature', () => {
    for (const alg of RSA_ALGS) {
      for (const length of SPOTS) {
        const token = jwtFor(alg, 'A'.repeat(length));
        for (const path of kept) {
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(`${token}${path}`, mode);
            assert.equal(out, `[REDACTED]${path}`, `${alg} ${length} ${mode} ${path}`);
          }
          const text = redactSecretsInText(`${token}${path}`);
          assert.equal(text, `[REDACTED]${path}`, `${alg} ${length} text ${path}`);
          assert.equal(text.includes('A'.repeat(8)), false, `${path} leaked signature`);
        }
        const repeated = `/${'a'.repeat(46)}/`;
        assert.equal(repeated.length, 48);
        assert.equal(maskJwtTokens(`${token}${repeated}`), `[REDACTED]${repeated}`, alg);
      }
    }
  });

  it('still masks signature-like tails and odd RSA runs', () => {
    for (const [alg, length] of [['RS256', 342], ['PS384', 512], ['RS512', 683]]) {
      const token = jwtFor(alg, 'A'.repeat(length));
      for (const eaten of ['/Ab/cdef', '/bcdefghi/src', '/bcdefghi/src.ts', '/a/b', '+/mn']) {
        const out = maskJwtTokens(`${token}${eaten}`);
        const tail = eaten.endsWith('.ts') ? eaten.slice(0, -3) : eaten;
        assert.equal(out.includes(tail), false, `${alg} kept ${tail}`);
        assert.equal(out.includes('A'.repeat(8)), false, `${alg} leaked signature before ${eaten}`);
      }
    }
    const odd = [
      ['RS256', 511, 342],
      ['PS256', 600, 512],
      ['RS512', 682, 342],
    ];
    for (const [alg, length, at] of odd) {
      for (const joiner of ['/', '+']) {
        const marker = `M${length}${joiner === '/' ? 's' : 'p'}`;
        const tail = `${joiner}${marker}`;
        const signature = `${'B'.repeat(at)}${tail}${'C'.repeat(length - at - tail.length)}`;
        assert.equal(signature.length, length);
        const out = maskJwtTokens(`${jwtFor(alg, signature)}${TRAILER}`);
        assertNoRawTail(out, marker, `${alg} ${length} ${joiner}`);
        assert.equal(out.includes('B'.repeat(8)), false, `${alg} ${length} prefix`);
        assert.equal(out.includes('C'.repeat(8)), false, `${alg} ${length} remainder`);
      }
    }
  });
});

describe('v1.0.55 short RSA tails on every redaction surface', { timeout: 180000 }, () => {
  it('leaves no raw tail substring of 3 or more characters', () => {
    const dir = gitRepo('ar1055-jwt-');
    const leaks = [
      ['RS256', 342, '/qzx/m'],
      ['PS256', 342, '+/kvw'],
      ['RS384', 512, '/mnp/qr'],
      ['PS384', 512, '//wxy'],
      ['RS512', 683, '+k/mnp'],
      ['PS512', 683, '/zz/qq'],
    ];
    const paths = ['/src/App.tsx', '/docs/README.md', '/README.md', '/src/app.ts'];
    const signatures = [];
    const parts = [];
    for (const [alg, at, tail] of leaks) {
      const signature = `${'A'.repeat(at)}${tail}`;
      signatures.push({ signature, tail });
      parts.push(jwtFor(alg, signature));
    }
    for (const [alg, length, path] of [
      ['RS256', 342, paths[0]],
      ['PS384', 512, paths[1]],
      ['RS512', 683, paths[2]],
      ['PS256', 342, paths[3]],
    ]) {
      parts.push(`${jwtFor(alg, 'D'.repeat(length))}${path}`);
    }
    const note = parts.join(' ');
    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(signatures[0].tail), true, 'stored receipt stays raw');
    assert.equal(stored.includes('/src/App.tsx'), true, 'stored path stays raw');

    function gone(text, label) {
      for (const { tail } of signatures) {
        assertNoRawTailOnSurface(text, tail, label, dir);
      }
      assert.equal(text.includes('A'.repeat(8)), false, `${label} leaked a prefix`);
      assert.equal(text.includes('D'.repeat(8)), false, `${label} leaked a path signature`);
    }

    function keptPaths(text, label) {
      for (const path of paths) {
        assert.equal(text.includes(path), true, `${label} dropped ${path}`);
      }
    }

    const surfaces = [
      ['show', ['show', storedPath], true],
      ['last', ['last'], true],
      ['last --json', ['last', '--json'], true],
      ['compare', ['compare'], true],
      ['share', ['share', storedPath], false],
      ['share --json', ['share', storedPath, '--json'], false],
      ['prove', ['prove', storedPath], false],
      ['prove --json', ['prove', storedPath, '--json'], false],
      ['verify', ['verify', storedPath], false],
      ['verify --json', ['verify', storedPath, '--json'], false],
    ];
    for (const [label, args, showPath] of surfaces) {
      const result = cli(dir, args);
      assert.equal(result.code, 0, `${label} ${result.err}${result.out}`);
      const text = result.out + result.err;
      gone(text, label);
      if (showPath) keptPaths(text, label);
    }

    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = cli(dir, ['attest', storedPath, '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    gone(created.out + created.err, 'attest --json');
    const attestPath = JSON.parse(created.out).path;
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(attestPath, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    gone(JSON.stringify(statement), 'attest statement');
    const plainAttest = cli(dir, ['attest', storedPath]);
    assert.equal(plainAttest.code, 0, plainAttest.err + plainAttest.out);
    gone(plainAttest.out + plainAttest.err, 'attest');

    const shareHtml = readFileSync(storedPath.replace(/\.md$/i, '.html'), 'utf8');
    gone(shareHtml, 'share html');
    keptPaths(shareHtml, 'share html');
  });
});

describe('v1.0.55 non-git relativePath under a secret-shaped parent', { timeout: 180000 }, () => {
  it('bases relativePath on the receipts root', () => {
    const secret = `ghp_${'f'.repeat(36)}`;
    const parent = keep(mkdtempSync(join(tmpdir(), 'ar1055-nogit-')));
    const project = join(parent, secret, 'notes');
    const receipts = join(project, '.agent-receipt', 'receipts');
    mkdirSync(receipts, { recursive: true });
    const receipt = join(receipts, 'plain.md');
    writeFileSync(
      receipt,
      appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n\nhello\n'),
    );
    const nested = join(project, 'nested', 'deeper');
    mkdirSync(nested, { recursive: true });

    function assertShare(cwd, label) {
      const shared = cli(cwd, ['share', receipt, '--json']);
      assert.equal(shared.code, 0, `${label} ${shared.err}${shared.out}`);
      const body = JSON.parse(shared.out);
      assert.equal(typeof body.relativePath, 'string', `${label} relativePath`);
      assert.equal(body.relativePath.includes('..'), false, body.relativePath);
      assert.equal(body.relativePath.includes(secret), false, body.relativePath);
      assert.equal(body.relativePath.includes('[REDACTED]'), false, body.relativePath);
      assert.equal(existsSync(join(project, body.relativePath)), true, body.relativePath);
      assert.equal(existsSync(join(nested, body.relativePath)), false, body.relativePath);
      assert.equal(body.path.includes(secret), false, body.path);
      assert.match(body.path, /ghp_\[REDACTED\]/);
      assert.equal(JSON.stringify(body).includes(secret), false, label);
    }

    assertShare(parent, 'parent');
    assertShare(project, 'project');
    assertShare(nested, 'nested');
  });
});

describe('v1.0.55 verify and show mask a missing path', { timeout: 120000 }, () => {
  it('masks a secret-shaped directory in the not-found error', () => {
    const secret = `ghp_${'e'.repeat(36)}`;
    const parent = keep(mkdtempSync(join(tmpdir(), 'ar1055-miss-')));
    const dir = join(parent, secret, 'repo');
    mkdirSync(dir, { recursive: true });
    git(dir, ['init', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.com']);
    git(dir, ['config', 'user.name', 'Test']);
    git(dir, ['config', 'commit.gpgsign', 'false']);
    writeFileSync(join(dir, 'README.md'), '# qa\n');
    git(dir, ['add', 'README.md']);
    git(dir, ['commit', '-m', 'initial']);
    assert.equal(cli(dir, ['init']).code, 0);

    function assertMasked(text, label) {
      assert.match(text, /Receipt not found/, label);
      assert.equal(text.includes(secret), false, `${label} printed the secret`);
      assert.equal(text.includes('e'.repeat(36)), false, `${label} printed the token body`);
      assert.match(text, /ghp_\[REDACTED\]/, label);
    }

    const plain = cli(dir, ['verify', 'missing.md']);
    assert.equal(plain.code, 1, plain.out + plain.err);
    assertMasked(plain.out + plain.err, 'verify');

    const json = cli(dir, ['verify', 'missing.md', '--json']);
    assert.equal(json.code, 1, json.out + json.err);
    const body = JSON.parse(json.out);
    assert.equal(body.command, 'verify');
    assert.equal(body.ok, false);
    assert.equal(body.exitCode, 1);
    assert.equal(body.path, null);
    assertMasked(body.reason, 'verify --json reason');
    assert.equal(JSON.stringify(body).includes(secret), false);
    assert.equal((json.err || '').includes(secret), false);

    const shown = cli(dir, ['show', 'missing.md']);
    assert.equal(shown.code, 1, shown.out + shown.err);
    assertMasked(shown.out + shown.err, 'show');

    const abs = cli(dir, ['verify', join(dir, 'nope.md'), '--json']);
    assert.equal(abs.code, 1, abs.out + abs.err);
    const absBody = JSON.parse(abs.out);
    assertMasked(absBody.reason, 'verify absolute');
    assert.equal(JSON.stringify(absBody).includes(secret), false);
  });
});
