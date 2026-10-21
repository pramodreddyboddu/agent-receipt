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

describe('v1.0.55 extension tails do not reopen the RSA leak', () => {
  const mustMask = ['/Qx7.ts', '/aB3k9.md', '/XYZ12.md', '/K.ts'];
  const stillMasked = ['/src/components/Button.tsx', '/Makefile', '/abcdefgh/x.ts', '/AbCdEfGh/x'];

  function glued(path) {
    const dot = path.lastIndexOf('.');
    const slash = path.lastIndexOf('/');
    const tail = dot > slash ? path.slice(0, dot) : path;
    const ext = dot > slash ? path.slice(dot) : '';
    return { tail, ext };
  }

  it('masks the reported extension tails and the paths the changelog still masks', () => {
    for (const alg of RSA_ALGS) {
      for (const length of SPOTS) {
        const token = jwtFor(alg, 'A'.repeat(length));
        for (const path of [...mustMask, ...stillMasked]) {
          const { tail } = glued(path);
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(`${token}${path}${TRAILER}`, mode);
            assertNoRawTail(out, tail, `${alg} ${length} ${mode} ${path}`);
            assert.equal(out.includes('A'.repeat(8)), false, `${path} leaked signature`);
            assert.equal(out.includes(TRAILER), true, `${path} ate the trailer`);
          }
        }
      }
    }
  });

  /**
   * v1.0.54 kept a glued tail only when it was a clear path with no
   * uppercase letter and no mixed run of 8 or more. The count below uses
   * that rule on the same draws the masker sees.
   */
  function v54WouldKeep(tail, ext) {
    if (tail.length < 1 || tail.length > 48) return false;
    const next = tail.charCodeAt(0);
    if (next !== 47 && next !== 43) return false;
    let slashes = 0;
    let sawUpper = false;
    for (let k = 0; k < tail.length; k += 1) {
      const code = tail.charCodeAt(k);
      if (code >= 65 && code <= 90) sawUpper = true;
      if (code === 47) {
        slashes += 1;
        continue;
      }
      if (code === 43) {
        if (k !== 0) return false;
        continue;
      }
      const alnum = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
      if (!(alnum || code === 95 || code === 45)) return false;
    }
    let hasExt = false;
    if (ext.charCodeAt(0) === 46) {
      let n = 0;
      let i = 1;
      for (; i < ext.length && n < 8; i += 1) {
        const code = ext.charCodeAt(i);
        const alnum = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
        if (!alnum) break;
        n += 1;
      }
      const after = i < ext.length ? ext.charCodeAt(i) : 0;
      const afterUrl = (after >= 48 && after <= 57) || (after >= 65 && after <= 90) ||
        (after >= 97 && after <= 122) || after === 95 || after === 45;
      hasExt = n >= 1 && (i >= ext.length || !afterUrl);
    }
    const clear = next === 43 ? slashes >= 1 || hasExt : slashes >= 2 || (slashes >= 1 && hasExt);
    if (!clear || sawUpper) return false;
    let runStart = -1;
    let runs = 0;
    let longRun = false;
    const finish = (end) => {
      const len = end - runStart;
      if (len >= 8) {
        const first = tail.charCodeAt(runStart);
        for (let i = runStart + 1; i < end; i += 1) {
          if (tail.charCodeAt(i) !== first) return false;
        }
        longRun = true;
      }
      runs += 1;
      return true;
    };
    for (let k = 0; k < tail.length; k += 1) {
      const code = tail.charCodeAt(k);
      const alnum = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
      if (alnum) {
        if (runStart < 0) runStart = k;
        continue;
      }
      if (runStart >= 0) {
        if (!finish(k)) return false;
        runStart = -1;
      }
    }
    if (runStart >= 0 && !finish(tail.length)) return false;
    if (longRun && runs !== 1) return false;
    return true;
  }

  function tailLeaked(out, tail, ext) {
    let residue = out.split('[REDACTED]').join('');
    if (ext) residue = residue.split(ext).join('');
    residue = residue.split(TRAILER).join('');
    if (tail.length < 3) return false;
    for (let n = 3; n <= tail.length; n += 1) {
      for (let i = 0; i + n <= tail.length; i += 1) {
        if (residue.includes(tail.slice(i, i + n))) return true;
      }
    }
    return false;
  }

  function measure(gen, samples) {
    const next = lcg(0x1055e);
    let leaked = 0;
    let v54 = 0;
    let maxLeaked = 0;
    let maxV54 = 0;
    const exts = ['.ts', '.md', '.json', '.tsx'];
    for (let n = 0; n < samples; n += 1) {
      const draw = gen(next, exts);
      const alg = RSA_ALGS[next() % RSA_ALGS.length];
      const at = SPOTS[next() % SPOTS.length];
      const token = jwtFor(alg, `${'A'.repeat(at)}${draw.tail}`);
      const text = `${token}${draw.ext}${TRAILER}`;
      const out = maskJwtTokens(text, n % 2 === 0 ? 'general' : 'strict');
      const did = tailLeaked(out, draw.tail, draw.ext);
      const old = v54WouldKeep(draw.tail, draw.ext) && draw.tail.length >= 3;
      if (did) {
        leaked += 1;
        if (draw.tail.length > maxLeaked) maxLeaked = draw.tail.length;
      }
      if (old) {
        v54 += 1;
        if (draw.tail.length > maxV54) maxV54 = draw.tail.length;
      }
      assert.equal(out.includes('A'.repeat(8)), false, `signature leaked before ${draw.tail}`);
    }
    return { leaked, v54, maxLeaked, maxV54 };
  }

  it('keeps a mixed-case extension tail no more often than v1.0.54', () => {
    const std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const mixed = measure((next, exts) => {
      const len = 3 + (next() % 20);
      let tail = next() % 2 === 0 ? '/' : '+';
      for (let i = 1; i < len; i += 1) tail += std[next() % std.length];
      if (next() % 2 === 0 && len > 2) {
        const pos = 1 + (next() % (len - 1));
        tail = `${tail.slice(0, pos)}/${tail.slice(pos + 1)}`;
      }
      return { tail, ext: exts[next() % exts.length] };
    }, 256);
    assert.ok(mixed.leaked <= mixed.v54, `mixed leak ${mixed.leaked} > v1.0.54 ${mixed.v54}`);
    assert.ok(mixed.leaked < mixed.v54, `mixed leak ${mixed.leaked} was not lower than v1.0.54 ${mixed.v54}`);
    assert.ok(mixed.maxLeaked <= mixed.maxV54, `mixed max ${mixed.maxLeaked} > v1.0.54 ${mixed.maxV54}`);

    const stdTs = measure((next) => {
      const len = 1 + (next() % 22);
      let tail = '/';
      for (let i = 1; i < len; i += 1) {
        tail += next() % 5 === 0 ? '/' : std[next() % std.length];
      }
      return { tail, ext: '.ts' };
    }, 256);
    assert.ok(stdTs.leaked <= stdTs.v54, `std-base64+.ts leak ${stdTs.leaked} > v1.0.54 ${stdTs.v54}`);
    assert.ok(stdTs.maxLeaked <= 22, `std-base64+.ts leaked ${stdTs.maxLeaked} chars`);
    assert.ok(stdTs.maxLeaked <= stdTs.maxV54, `std-base64+.ts max ${stdTs.maxLeaked} > v1.0.54 ${stdTs.maxV54}`);
  });
});

describe('v1.0.55 share then verify from a fresh non-git subdirectory', () => {
  it('picks the receipt and verifies from a plain parent and a secret-shaped parent', () => {
    const action = readFileSync(join(root, 'examples/github/action.yml'), 'utf8');
    const picker = action.match(/node -e '([^']*relativePath[^']*)'/)[1];
    assert.ok(picker, 'action receipt picker');

    const shapes = [
      { label: 'plain', secret: null },
      { label: 'secret', secret: `ghp_${'a'.repeat(36)}` },
    ];
    for (const shape of shapes) {
      const parent = keep(mkdtempSync(join(tmpdir(), `ar1055-${shape.label}-`)));
      const project = shape.secret ? join(parent, shape.secret, 'notes') : join(parent, 'notes');
      const receipts = join(project, '.agent-receipt', 'receipts');
      mkdirSync(receipts, { recursive: true });
      const receipt = join(receipts, 'plain.md');
      writeFileSync(
        receipt,
        appendHashFooter('# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n\nhello\n'),
      );
      const sub = join(project, 'nested', 'deeper');
      mkdirSync(sub, { recursive: true });
      mkdirSync(join(sub, '.agent-receipt'), { recursive: true });
      writeFileSync(join(sub, '.agent-receipt', 'audit.jsonl'), '{"event":"share"}\n');

      const shared = cli(sub, ['share', receipt, '--json']);
      assert.equal(shared.code, 0, `${shape.label} ${shared.err}${shared.out}`);
      const body = JSON.parse(shared.out);
      assert.equal(typeof body.relativePath, 'string', shape.label);
      assert.equal(existsSync(join(project, body.relativePath)), true, body.relativePath);
      assert.equal(existsSync(join(sub, body.relativePath)), false, body.relativePath);
      const audit = readFileSync(join(project, '.agent-receipt', 'audit.jsonl'), 'utf8');
      assert.match(audit, /"event":"share"/, shape.label);
      if (shape.secret) {
        assert.equal(body.relativePath.includes(shape.secret), false, body.relativePath);
        assert.equal(body.path.includes(shape.secret), false, body.path);
        assert.equal(JSON.stringify(body).includes(shape.secret), false, shape.label);
      }

      const gateFile = join(project, 'share-gate.json');
      writeFileSync(gateFile, shared.out);
      const picked = execFileSync(process.execPath, ['-e', picker, gateFile], {
        cwd: sub,
        encoding: 'utf8',
      }).trim();
      assert.equal(existsSync(join(sub, picked)), true, `${shape.label} picked ${picked}`);
      if (shape.secret) assert.equal(picked.includes(shape.secret), false, picked);

      const verified = cli(sub, ['verify', picked]);
      assert.equal(verified.code, 0, `${shape.label} ${verified.err}${verified.out}`);
      assert.match(verified.out, /OK/);
      const direct = cli(sub, ['verify', body.relativePath]);
      assert.equal(direct.code, 0, `${shape.label} relative ${direct.err}${direct.out}`);
      if (shape.secret) {
        const shown = `${verified.out}${verified.err}${direct.out}${direct.err}${picked}`;
        assert.equal(shown.includes(shape.secret), false, shown);
        assert.equal(shown.includes('a'.repeat(36)), false, shown);
      }
    }
  });
});

describe('v1.0.55 missing attest and package paths are masked', () => {
  it('masks attest --verify and verify --package not-found errors', () => {
    const secret = `ghp_${'b'.repeat(36)}`;
    const parent = keep(mkdtempSync(join(tmpdir(), 'ar1055-misspath-')));
    const dir = join(parent, secret, 'repo');
    mkdirSync(dir, { recursive: true });

    function assertMasked(text, label) {
      assert.equal(text.includes(secret), false, `${label} printed the secret\n${text}`);
      assert.equal(text.includes('b'.repeat(36)), false, `${label} printed the token body\n${text}`);
      assert.match(text, /ghp_\[REDACTED\]/, label);
    }

    const missingFile = 'missing.intoto.jsonl';
    const plainAttest = cli(dir, ['attest', '--verify', missingFile]);
    assert.equal(plainAttest.code, 1, plainAttest.out + plainAttest.err);
    assert.match(plainAttest.err, /attestation not found/);
    assertMasked(plainAttest.out + plainAttest.err, 'attest --verify');

    const jsonAttest = cli(dir, ['attest', '--verify', missingFile, '--json']);
    assert.equal(jsonAttest.code, 1, jsonAttest.out + jsonAttest.err);
    const attestBody = JSON.parse(jsonAttest.out);
    assert.equal(attestBody.command, 'attest-verify');
    assert.equal(attestBody.ok, false);
    assert.equal(attestBody.exitCode, 1);
    assert.match(attestBody.reason, /attestation not found/);
    assertMasked(attestBody.reason, 'attest --verify --json');
    assert.equal(JSON.stringify(attestBody).includes(secret), false);
    assert.equal((jsonAttest.err || '').includes(secret), false);

    const missingDir = 'missing.share';
    const plainPack = cli(dir, ['verify', '--package', missingDir]);
    assert.equal(plainPack.code, 1, plainPack.out + plainPack.err);
    assert.match(plainPack.err, /share package not found/);
    assertMasked(plainPack.out + plainPack.err, 'verify --package');

    const jsonPack = cli(dir, ['verify', '--package', missingDir, '--json']);
    assert.equal(jsonPack.code, 1, jsonPack.out + jsonPack.err);
    const packBody = JSON.parse(jsonPack.out);
    assert.equal(packBody.command, 'verify');
    assert.equal(packBody.ok, false);
    assert.equal(packBody.exitCode, 1);
    assert.match(packBody.reason, /share package not found/);
    assertMasked(packBody.reason, 'verify --package --json');
    assert.equal(JSON.stringify(packBody).includes(secret), false);
    assert.equal((jsonPack.err || '').includes(secret), false);
  });
});
