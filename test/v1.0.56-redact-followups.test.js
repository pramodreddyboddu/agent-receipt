/**
 * v1.0.56 — Release QA follow-ups from v1.0.55.
 * Lowercase RSA tail residual, shadow roots, nested non-git roots,
 * subdirectory readers, and ordinary long path segments.
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

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
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

function assertNoRawTailOnSurface(text, tail, label, extra) {
  let residue = text.split('[REDACTED]').join('');
  for (const chrome of ['/dev/null', 'a/token.txt', 'b/token.txt', 'b/README.md', 'a/README.md', extra]) {
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
}

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state;
  };
}

function writeReceipt(dir, name) {
  const receipts = join(dir, '.agent-receipt', 'receipts');
  mkdirSync(receipts, { recursive: true });
  const file = join(receipts, name);
  writeFileSync(
    file,
    appendHashFooter(`# Agent Receipt\n\n## Session\n\n- **Agent**: qa\n\n${name}\n`),
  );
  return file;
}

describe('v1.0.56 lowercase RSA tails leave no 3+ residual', () => {
  const fixed = ['/tonaxc/u1', '+kj6/0xsty3', '/ab/cd/ef', '/abc/defg', '+/zzq/w9k', '/abcdefgh/x'];

  it('masks the fixed lowercase residuals', () => {
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        for (const tail of fixed) assertTailMasked(alg, at, tail);
      }
    }
  });

  it('masks randomized lowercase tails that contain a digit', () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789/+';
    const next = lcg(0x1056);
    for (let n = 0; n < 200; n += 1) {
      const len = 8 + (next() % 15);
      let tail = next() % 2 === 0 ? '/' : '+';
      let digit = false;
      for (let i = 1; i < len; i += 1) {
        const ch = alphabet[next() % alphabet.length];
        if (ch >= '0' && ch <= '9') digit = true;
        tail += ch;
      }
      if (!digit) tail = `${tail.slice(0, -1)}7`;
      if (next() % 2 === 0 && len > 3) {
        const pos = 1 + (next() % (len - 1));
        if (tail[pos] !== '/' && tail[pos] !== '+') {
          tail = `${tail.slice(0, pos)}/${tail.slice(pos + 1)}`;
        }
      }
      const alg = RSA_ALGS[next() % RSA_ALGS.length];
      const at = SPOTS[next() % SPOTS.length];
      assertTailMasked(alg, at, tail);
    }
  });
});

describe('v1.0.56 ordinary long path segments stay visible', () => {
  const kept = [
    '/src/components/Button.tsx',
    '/src/utilities/format.ts',
    '/packages/utilities/index.js',
    '/src/app.ts',
    '/docs/guide.json',
    '/src/my-component/format.ts',
  ];
  const masked = ['/abcdefgh/x.ts', '/Makefile', '/AbCdEfGh/x', '/src/aB3k9xQ2/App.ts', '/Qx7.ts'];

  it('keeps ordinary segments and masks secret-shaped ones', () => {
    assert.equal(redactSecretsInText('src/components/utilities'), 'src/components/utilities');
    const secret = `ghp_${'c'.repeat(36)}`;
    assert.equal(redactSecretsInText(secret).includes(secret), false);
    assert.match(redactSecretsInText(secret), /ghp_\[REDACTED\]/);
    for (const alg of RSA_ALGS) {
      for (const length of SPOTS) {
        const token = jwtFor(alg, 'A'.repeat(length));
        for (const path of kept) {
          const out = maskJwtTokens(`${token}${path}${TRAILER}`);
          assert.equal(out, `[REDACTED]${path}${TRAILER}`, `${alg} ${length} ${path}`);
          assert.equal(out.includes('A'.repeat(8)), false, path);
        }
        const repeated = `/${'a'.repeat(46)}/`;
        assert.equal(maskJwtTokens(`${token}${repeated}`), `[REDACTED]${repeated}`, alg);
        for (const path of masked) {
          const dot = path.lastIndexOf('.');
          const slash = path.lastIndexOf('/');
          const tail = dot > slash ? path.slice(0, dot) : path;
          const out = maskJwtTokens(`${token}${path}${TRAILER}`);
          assertNoRawTail(out, tail, `${alg} ${path}`);
          assert.equal(out.includes('A'.repeat(8)), false, path);
          assert.equal(out.includes(TRAILER), true, path);
        }
      }
    }
  });
});

describe('v1.0.56 lowercase RSA tails on every redaction surface', { timeout: 180000 }, () => {
  it('leaves no raw tail substring of 3 or more characters', () => {
    const dir = gitRepo('ar1056-jwt-');
    const leaks = [
      ['RS256', 342, '/qxv9/k3m'],
      ['PS256', 342, '+zj4/8nwp'],
      ['RS384', 512, '/wkv/qpz'],
      ['PS512', 683, '/m9c/r4d'],
    ];
    const paths = ['/src/components/Button.tsx', '/src/utilities/format.ts', '/src/app.ts'];
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
    assert.equal(stored.includes(paths[0]), true, 'stored path stays raw');

    function gone(text, label) {
      for (const { tail } of signatures) assertNoRawTailOnSurface(text, tail, label, dir);
      assert.equal(text.includes('A'.repeat(8)), false, `${label} leaked a prefix`);
      assert.equal(text.includes('D'.repeat(8)), false, `${label} leaked a path signature`);
    }

    function keptPaths(text, label) {
      for (const path of paths) assert.equal(text.includes(path), true, `${label} dropped ${path}`);
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

describe('v1.0.56 an audit directory with an extra file is not a receipts root', { timeout: 120000 }, () => {
  it('does not let audit.jsonl plus another file shadow the real root', () => {
    const project = keep(mkdtempSync(join(tmpdir(), 'ar1056-shadow-')));
    const receipt = writeReceipt(project, 'real.md');
    const shadow = join(project, 'nested');
    mkdirSync(join(shadow, '.agent-receipt'), { recursive: true });
    writeFileSync(join(shadow, '.agent-receipt', 'audit.jsonl'), '{"event":"note"}\n');
    writeFileSync(join(shadow, '.agent-receipt', 'notes.txt'), 'extra\n');
    writeFileSync(join(shadow, '.agent-receipt.yml'), 'outDir: .agent-receipt/receipts\n');
    mkdirSync(join(shadow, '.agent-receipt', 'receipts'), { recursive: true });
    mkdirSync(join(shadow, '.agent-receipt', 'keys'), { recursive: true });

    const shared = cli(shadow, ['share', receipt, '--json']);
    assert.equal(shared.code, 0, shared.err + shared.out);
    const body = JSON.parse(shared.out);
    assert.equal(existsSync(join(project, body.relativePath)), true, body.relativePath);
    assert.equal(existsSync(join(shadow, body.relativePath)), false, body.relativePath);
    const audit = readFileSync(join(project, '.agent-receipt', 'audit.jsonl'), 'utf8');
    assert.match(audit, /"event":"share"/);
    assert.equal(existsSync(join(shadow, '.agent-receipt', 'audit.jsonl')), true);
    const shadowAudit = readFileSync(join(shadow, '.agent-receipt', 'audit.jsonl'), 'utf8');
    assert.equal(shadowAudit.includes('"event":"share"'), false);
    assert.equal(shadowAudit.trim(), '{"event":"note"}');

    const verified = cli(shadow, ['verify', body.relativePath]);
    assert.equal(verified.code, 0, verified.err + verified.out);
    const last = cli(shadow, ['last']);
    assert.equal(last.code, 0, last.err + last.out);
    assert.match(last.out, /real\.md/);
  });
});

describe('v1.0.56 nested non-git roots agree', { timeout: 180000 }, () => {
  it('share, the example picker, and verify use the same root', () => {
    const action = readFileSync(join(root, 'examples/github/action.yml'), 'utf8');
    const picker = action.match(/node -e '([^']*relativePath[^']*)'/)[1];
    assert.ok(picker, 'action receipt picker');
    const gate = readFileSync(join(root, 'examples/github/pr-gate.yml'), 'utf8');
    assert.match(gate, /hasReceiptData/);

    const outer = keep(mkdtempSync(join(tmpdir(), 'ar1056-nest-')));
    const outerReceipt = writeReceipt(outer, 'outer.md');
    const inner = join(outer, 'inner');
    const innerReceipt = writeReceipt(inner, 'inner.md');
    const sub = join(inner, 'sub');
    mkdirSync(sub, { recursive: true });

    function check(cwd, file, base, label) {
      const shared = cli(cwd, ['share', file, '--json']);
      assert.equal(shared.code, 0, `${label} ${shared.err}${shared.out}`);
      const body = JSON.parse(shared.out);
      assert.equal(typeof body.relativePath, 'string', label);
      assert.equal(existsSync(join(base, body.relativePath)), true, `${label} ${body.relativePath}`);
      const gateFile = join(outer, `gate-${label}.json`);
      writeFileSync(gateFile, shared.out);
      const picked = execFileSync(process.execPath, ['-e', picker, gateFile], {
        cwd,
        encoding: 'utf8',
      }).trim();
      assert.equal(existsSync(join(cwd, picked)), true, `${label} picked ${picked}`);
      const verified = cli(cwd, ['verify', body.relativePath]);
      assert.equal(verified.code, 0, `${label} relative ${verified.err}${verified.out}`);
      const pickedVerify = cli(cwd, ['verify', picked]);
      assert.equal(pickedVerify.code, 0, `${label} picked verify ${pickedVerify.err}${pickedVerify.out}`);
      return body.relativePath;
    }

    const fromSubInner = check(sub, innerReceipt, inner, 'sub-inner');
    assert.equal(fromSubInner.includes('inner/'), false, fromSubInner);
    const fromSubOuter = check(sub, outerReceipt, outer, 'sub-outer');
    assert.equal(fromSubOuter.startsWith('inner/'), false, fromSubOuter);
    const fromOuter = check(outer, innerReceipt, outer, 'outer-inner');
    assert.match(fromOuter, /^inner\//, fromOuter);
  });
});

describe('v1.0.56 readers find a non-git receipts root from a subdirectory', { timeout: 180000 }, () => {
  it('last, prove, report, attest, sign, export, and history exit 0', () => {
    const project = keep(mkdtempSync(join(tmpdir(), 'ar1056-sub-')));
    writeReceipt(project, 'one.md');
    assert.equal(cli(project, ['keygen']).code, 0);
    const sub = join(project, 'src', 'components');
    mkdirSync(sub, { recursive: true });
    const commands = [
      ['last', ['last']],
      ['prove', ['prove']],
      ['report', ['report', 'last']],
      ['attest', ['attest']],
      ['sign', ['sign']],
      ['export', ['export']],
      ['history', ['history']],
    ];
    for (const [label, args] of commands) {
      const result = cli(sub, args);
      assert.equal(result.code, 0, `${label} ${result.err}${result.out}`);
    }
    assert.equal(existsSync(join(sub, '.agent-receipt')), false, 'subdir became a shadow root');
    assert.equal(existsSync(join(project, '.agent-receipt', 'audit.jsonl')), true);
  });
});
