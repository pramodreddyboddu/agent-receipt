/**
 * v1.0.57 — v1.0.56 Release QA follow-ups.
 * Ordinary paths after an exact RSA signature stay visible.
 * PascalCase and camelCase filenames stay visible.
 * Secret-shaped stems stay masked.
 * PEM header scans stay linear, and a truncated private key is redacted.
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { maskJwtTokens, redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'bin', 'agent-receipt.js');
const dirs = [];
const RSA_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
const SPOTS = [342, 512, 683];
const TRAILER = '\u0001';
const PEM_REPLACEMENT = '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----';

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

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state;
  };
}

function inSegment(path) {
  const dot = path.lastIndexOf('.');
  const slash = path.lastIndexOf('/');
  if (dot > slash) return path.slice(0, dot);
  return path;
}

function assertNoSignatureWindows(text, signature, label) {
  const residue = text.split('[REDACTED]').join('').split(TRAILER).join('');
  for (let i = 0; i + 3 <= signature.length; i += 1) {
    const window = signature.slice(i, i + 3);
    assert.equal(residue.includes(window), false, `${label} leaked signature ${window}`);
  }
}

const KEPT = [
  '/Users/x/repo/a.ts',
  '/Users/pramod/repo/x.ts',
  '+/Users/x/repo/a.ts',
  'UserProfile.tsx',
  'HomeView.swift',
  'MyClass.java',
  'formatDate.ts',
  'Dockerfile',
  'dockerfile',
  'package.json',
  '/Dockerfile',
  '/package.json',
  '/UserProfile.tsx',
  '/src/app.ts',
  '/src/components/Button.tsx',
];

const MASKED = [
  '/Ahsqowx.ts',
  '/OHALMQO.ts',
  '/QZXWVKT.md',
  'Ahsqowx.ts',
  'OHALMQO.ts',
  'QZXWVKT.md',
  '/Ahs.ts',
  '/hnw/x.ts',
  '/Jrq/kl/x.ts',
  '/Makefile',
  'Makefile',
  'DOCKERFILE',
  '/abcdefgh/x.ts',
  '/AbCdEfGh/x',
  '/Qx7.ts',
  '/src/aB3k9xQ2/App.ts',
  '/ab/cd/ef',
  '/abc/defg',
  '/My.ts',
];

describe('v1.0.57 ordinary paths after an exact RSA signature stay visible', () => {
  it('keeps the path and redacts the signature on every alg and length', () => {
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        const signature = 'A'.repeat(at);
        const token = jwtFor(alg, signature);
        for (const path of KEPT) {
          const raw = `${token}${path}${TRAILER}`;
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(raw, mode);
            assert.equal(out, `[REDACTED]${path}${TRAILER}`, `${alg} ${at} ${mode} ${path}`);
            assertNoSignatureWindows(out, signature, `${alg} ${mode} ${path}`);
          }
          const text = redactSecretsInText(raw);
          assert.equal(text, `[REDACTED]${path}${TRAILER}`, `${alg} ${at} text ${path}`);
          assertNoSignatureWindows(text, signature, `${alg} text ${path}`);
        }
      }
    }
  });

  it('does not split an odd RSA run or an unknown alg', () => {
    const path = '/Users/x/repo/a.ts';
    for (const odd of [511, 600, 682]) {
      const signature = 'B'.repeat(odd);
      const raw = `${jwtFor('RS256', signature)}${path}${TRAILER}`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        assertNoRawTail(out, inSegment(path), `odd ${odd} ${mode}`);
        assertNoSignatureWindows(out, signature.slice(0, 24), `odd ${odd} ${mode}`);
        assert.equal(out.includes(TRAILER), true, `odd ${odd} ate the trailer`);
      }
    }
    const unknown = `${jwtFor('none', 'C'.repeat(342))}${path}${TRAILER}`;
    const masked = maskJwtTokens(unknown);
    assertNoRawTail(masked, inSegment(path), 'unknown alg');
    assert.equal(masked.includes('CCCC'), false, 'unknown alg split the signature');
  });
});

describe('v1.0.57 PascalCase filenames stay visible and secret-shaped stems stay masked', () => {
  it('masks secret-shaped filenames and short uppercase tails', () => {
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        for (const path of MASKED) {
          const stem = inSegment(path);
          const ext = path.slice(stem.length);
          const signature = `${'D'.repeat(at)}${stem}`;
          const raw = `${jwtFor(alg, signature)}${ext}${TRAILER}`;
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(raw, mode);
            assertNoRawTail(out, stem, `${alg} ${at} ${mode} ${path}`);
            assert.equal(out.includes('D'.repeat(8)), false, `${path} leaked the prefix`);
            assert.equal(out.includes(TRAILER), true, `${path} ate the trailer`);
          }
          const text = redactSecretsInText(raw);
          assertNoRawTail(text, stem, `${alg} ${at} text ${path}`);
          assert.equal(text.includes('D'.repeat(8)), false, path);
        }
      }
    }
  });

  it('seeded sweep leaks no 3+ raw signature characters', () => {
    const std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const bare = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const exts = ['.ts', '.tsx', '.md', '.swift', '.java', '.json'];
    const next = lcg(0x1057);
    let probes = 0;
    let leaks = 0;
    for (let n = 0; n < 2048; n += 1) {
      const alg = RSA_ALGS[next() % RSA_ALGS.length];
      const at = SPOTS[next() % SPOTS.length];
      let signature = '';
      for (let i = 0; i < at; i += 1) signature += bare[next() % bare.length];
      const ext = exts[next() % exts.length];
      let stem = '';
      const stemLen = 6 + (next() % 12);
      if (n % 2 === 0) {
        stem = next() % 2 === 0 ? '/' : '+';
        for (let i = 1; i < stemLen; i += 1) stem += std[next() % std.length];
      } else {
        for (let i = 0; i < stemLen; i += 1) stem += bare[next() % bare.length];
      }
      if (!/[A-Z]/.test(stem)) {
        const pos = stem.startsWith('/') || stem.startsWith('+') ? 1 : 0;
        stem = `${stem.slice(0, pos)}${upper[next() % upper.length]}${stem.slice(pos)}`;
      }
      const raw = `${jwtFor(alg, signature + stem)}${ext}${TRAILER}`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        const residue = out.split('[REDACTED]').join('').split(TRAILER).join('').split(ext).join('');
        assert.equal(residue.includes(stem), false, `${mode} kept ${stem}`);
        for (let i = 0; i + 3 <= signature.length; i += 1) {
          if (residue.includes(signature.slice(i, i + 3))) leaks += 1;
        }
        assert.equal(out.includes(TRAILER), true, stem);
      }
      const text = redactSecretsInText(raw);
      const textResidue = text.split('[REDACTED]').join('').split(TRAILER).join('').split(ext).join('');
      assert.equal(textResidue.includes(stem), false, `text kept ${stem}`);
      for (let i = 0; i + 3 <= signature.length; i += 1) {
        if (textResidue.includes(signature.slice(i, i + 3))) leaks += 1;
      }
      probes += 1;
    }
    assert.equal(probes, 2048);
    assert.equal(leaks, 0);
  });
});

describe('v1.0.57 truncated PEM private keys are redacted in one linear scan', () => {
  const body = 'MIIEowIBAAKCAQEAsecretkeymaterial';
  const kinds = ['RSA ', 'OPENSSH ', 'EC ', 'DSA ', 'ENCRYPTED ', ''];

  it('redacts a private-key body when the END line is missing', () => {
    for (const kind of kinds) {
      const block = `-----BEGIN ${kind}PRIVATE KEY-----\n${body}\nQUJDREVGR0g=\n`;
      const out = redactSecretsInText(`before\n${block}after stays`);
      assert.equal(out.includes(body), false, kind);
      assert.equal(out.includes('QUJDREVGR0g='), false, kind);
      assert.equal(out.includes('before'), true, kind);
      assert.equal(out.includes('after stays'), true, kind);
      assert.match(out, /-----BEGIN PRIVATE KEY-----\n\[REDACTED\]\n-----END PRIVATE KEY-----/);
    }
    const only = `-----BEGIN PRIVATE KEY-----\n${body}\n`;
    const onlyOut = redactSecretsInText(only);
    assert.equal(onlyOut.includes(body), false);
    assert.equal(onlyOut, PEM_REPLACEMENT);

    const stopped = `-----BEGIN EC PRIVATE KEY-----\n${body}\nnot base64, keep this!\n`;
    const stoppedOut = redactSecretsInText(stopped);
    assert.equal(stoppedOut.includes(body), false);
    assert.equal(stoppedOut.includes('not base64, keep this!'), true);
    assert.equal(stoppedOut.endsWith('not base64, keep this!\n'), true);

    const laterCert = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END CERTIFICATE-----\nkeepcert`;
    const laterOut = redactSecretsInText(laterCert);
    assert.equal(laterOut.includes(body), false);
    assert.equal(laterOut.includes('-----END CERTIFICATE-----'), true);
    assert.equal(laterOut.includes('keepcert'), true);
  });

  it('still redacts a complete block and leaves a certificate and a bare header', () => {
    for (const kind of kinds) {
      const block = `-----BEGIN ${kind}PRIVATE KEY-----\n${body}\n-----END ${kind}PRIVATE KEY-----`;
      const out = redactSecretsInText(`before\n${block}\nafter`);
      assert.equal(out.includes(body), false, kind);
      assert.equal(out.includes('before'), true, kind);
      assert.equal(out.includes('after'), true, kind);
    }
    const mismatched = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END EC PRIVATE KEY-----`;
    assert.equal(redactSecretsInText(mismatched).includes(body), false);
    const cert = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    assert.equal(redactSecretsInText(cert), cert);
    const bare = '-----BEGIN PRIVATE KEY-----\n'.repeat(32);
    assert.equal(redactSecretsInText(bare), bare);
  });

  it('stays linear on a megabyte of headers and on truncated bodies', () => {
    const begin = '-----BEGIN PRIVATE KEY-----\n';
    const many = begin.repeat(Math.ceil(1_000_000 / begin.length));
    assert.ok(many.length >= 1_000_000);
    const started = Date.now();
    const untouched = redactSecretsInText(many);
    const elapsed = Date.now() - started;
    assert.equal(untouched, many);
    assert.equal(untouched.length, many.length);
    assert.ok(elapsed < 5000, `bare PEM headers took ${elapsed}ms`);

    const chunk = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n`;
    const big = chunk.repeat(Math.ceil(1_000_000 / chunk.length));
    assert.ok(big.length >= 1_000_000);
    const bodyStarted = Date.now();
    const redacted = redactSecretsInText(big);
    const bodyElapsed = Date.now() - bodyStarted;
    assert.equal(redacted.includes(body), false);
    assert.equal(redacted.includes('secretkeymaterial'), false);
    assert.ok(bodyElapsed < 5000, `truncated PEM bodies took ${bodyElapsed}ms`);
  });
});

describe('v1.0.57 kept paths on every redaction surface', { timeout: 180000 }, () => {
  it('keeps ordinary paths and masks secret-shaped tails in plain and JSON output', () => {
    const dir = gitRepo('ar1057-jwt-');
    const kept = [
      ['RS256', 342, '/Users/x/repo/a.ts'],
      ['PS256', 512, '/Users/pramod/repo/x.ts'],
      ['RS384', 683, 'UserProfile.tsx'],
      ['PS384', 342, 'HomeView.swift'],
      ['RS512', 512, 'MyClass.java'],
      ['PS512', 683, 'formatDate.ts'],
      ['RS256', 512, 'Dockerfile'],
      ['PS256', 683, 'package.json'],
    ];
    const masked = [
      ['RS256', 342, '/Ahsqowx.ts'],
      ['PS384', 512, '/OHALMQO.ts'],
      ['RS512', 683, 'QZXWVKT.md'],
    ];
    const paths = kept.map((row) => row[2]);
    const signatures = [];
    const parts = [];
    for (const [alg, at, path] of kept) {
      const signature = 'E'.repeat(at);
      signatures.push(signature);
      parts.push(`${jwtFor(alg, signature)}${path}`);
    }
    for (const [alg, at, path] of masked) {
      const stem = inSegment(path);
      const ext = path.slice(stem.length);
      const signature = `${'F'.repeat(at)}${stem}`;
      signatures.push(signature);
      parts.push(`${jwtFor(alg, signature)}${ext}`);
    }
    const note = parts.join(' ');
    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(paths[0]), true, 'stored receipt stays raw');
    assert.equal(stored.includes('E'.repeat(12)), true, 'stored signature stays raw');

    function gone(text, label) {
      for (const [, , path] of masked) {
        assertNoRawTailOnSurface(text, inSegment(path), label, dir);
      }
      assert.equal(text.includes('E'.repeat(8)), false, `${label} leaked a kept-path signature`);
      assert.equal(text.includes('F'.repeat(8)), false, `${label} leaked a masked-path signature`);
    }

    function keptPaths(text, label) {
      for (const path of paths) assert.equal(text.includes(path), true, `${label} dropped ${path}`);
    }

    const surfaces = [
      ['show', ['show', storedPath], true],
      ['last', ['last'], true],
      ['last --json', ['last', '--json'], true],
      ['compare', ['compare'], true],
      ['share', ['share', storedPath, '--md'], false],
      ['share --json', ['share', storedPath, '--json', '--out', 'shared.html', '--md', 'shared.redacted.md'], false],
      ['prove', ['prove', storedPath], false],
      ['prove --json', ['prove', storedPath, '--json'], false],
      ['verify', ['verify', storedPath], false],
      ['verify --json', ['verify', storedPath, '--json'], false],
    ];
    let shareJson = null;
    for (const [label, args, showPath] of surfaces) {
      const result = cli(dir, args);
      assert.equal(result.code, 0, `${label} ${result.err}${result.out}`);
      const text = result.out + result.err;
      gone(text, label);
      if (showPath) keptPaths(text, label);
      if (label === 'last --json') {
        const body = JSON.parse(result.out);
        assert.equal(typeof body.message, 'string');
        keptPaths(body.message, 'last --json message');
        gone(body.message, 'last --json message');
      }
      if (label === 'share --json') shareJson = JSON.parse(result.out);
    }

    const shareHtml = readFileSync(storedPath.replace(/\.md$/i, '.html'), 'utf8');
    gone(shareHtml, 'share html');
    keptPaths(shareHtml, 'share html');
    const redactedMd = readFileSync(storedPath.replace(/\.md$/i, '.redacted.md'), 'utf8');
    gone(redactedMd, 'share redacted md');
    keptPaths(redactedMd, 'share redacted md');
    assert.ok(shareJson && shareJson.htmlPath && shareJson.markdownPath, 'share --json names the files');
    assert.equal(existsSync(shareJson.htmlPath), true);
    assert.equal(existsSync(shareJson.markdownPath), true);
    keptPaths(readFileSync(shareJson.htmlPath, 'utf8'), 'share --json html');
    keptPaths(readFileSync(shareJson.markdownPath, 'utf8'), 'share --json md');

    assert.equal(cli(dir, ['keygen']).code, 0);
    const created = cli(dir, ['attest', storedPath, '--json']);
    assert.equal(created.code, 0, created.err + created.out);
    gone(created.out + created.err, 'attest --json');
    const attestPath = JSON.parse(created.out).path;
    const statement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(attestPath, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    const predicate = JSON.stringify(statement.predicate);
    gone(predicate, 'attest statement');
    keptPaths(statement.predicate.message, 'attest statement message');
    const plainAttest = cli(dir, ['attest', storedPath]);
    assert.equal(plainAttest.code, 0, plainAttest.err + plainAttest.out);
    gone(plainAttest.out + plainAttest.err, 'attest');
    const plainStatement = JSON.parse(Buffer.from(
      JSON.parse(readFileSync(attestPath, 'utf8').trim()).payload,
      'base64',
    ).toString('utf8'));
    keptPaths(plainStatement.predicate.message, 'attest plain statement');
  });
});
