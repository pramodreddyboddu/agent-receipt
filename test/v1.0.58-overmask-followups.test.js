/**
 * v1.0.58 — v1.0.57 Release QA follow-ups.
 * After a truncated private key and a gap, ordinary text stays visible.
 * A short mixed-case line such as Ab1 stays.
 * A 3-character path word such as nav does not keep a signature fragment.
 * Deep Java and PHP paths stay visible. Secret-shaped segments stay masked.
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
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LINE64 = ALPHABET.slice(0, 64);
const LINE70 = (ALPHABET + ALPHABET).slice(0, 70);

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

describe('v1.0.58 a gap after a truncated private key stops the mask', () => {
  const hex64 = 'a'.repeat(64);
  const hex40 = 'b'.repeat(40);
  const ident = 'IdentifierValue16';
  const path = '/src/components/Button.tsx';
  const sha = '0123456789abcdef'.repeat(4);
  const kinds = ['RSA ', 'OPENSSH ', 'EC ', 'DSA ', 'ENCRYPTED ', ''];

  function block(kind, nl, body, rest) {
    return `-----BEGIN ${kind}PRIVATE KEY-----${nl}${body}${nl}${rest}`;
  }

  it('shows hashes, identifiers, paths, and ok before a sha after a gap', () => {
    const gaps = ['', 'ok', ' ', '\t'];
    for (const kind of kinds) {
      for (const nl of ['\n', '\r\n', '\r']) {
        for (const gap of gaps) {
          const gapLine = gap === '' ? '' : gap;
          const rest = [gapLine, hex64, hex40, ident, path, `ok ${sha}`, 'Next'].join(nl) + nl;
          const raw = block(kind, nl, LINE64, rest);
          const out = redactSecretsInText(raw);
          const label = `${JSON.stringify(kind)} ${JSON.stringify(nl)} gap ${JSON.stringify(gap)}`;
          assert.equal(out.includes(LINE64), false, label);
          assert.equal(out.includes(hex64), true, label);
          assert.equal(out.includes(hex40), true, label);
          assert.equal(out.includes(ident), true, label);
          assert.equal(out.includes(path), true, label);
          assert.equal(out.includes(`ok ${sha}`), true, label);
          assert.equal(out.includes('Next'), true, label);
          assert.equal(out.startsWith(PEM_REPLACEMENT), true, label);
        }
      }
    }
  });

  it('still redacts the truncated key, including a later full-length line', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      const resumed = block('', nl, LINE64, ['', LINE64, 'Next'].join(nl) + nl);
      const out = redactSecretsInText(resumed);
      assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, JSON.stringify(nl));
      assert.equal(out.includes(LINE64), false);

      const openssh = block('OPENSSH ', nl, LINE70, ['ab', LINE70, 'README'].join(nl) + nl);
      const sshOut = redactSecretsInText(openssh);
      assert.equal(sshOut, `${PEM_REPLACEMENT}${nl}README${nl}`, `70 ${JSON.stringify(nl)}`);
      assert.equal(sshOut.includes(LINE70), false);

      const mid = block('EC ', nl, LINE64, ['YQ==', LINE64, 'TODO'].join(nl) + nl);
      assert.equal(redactSecretsInText(mid), `${PEM_REPLACEMENT}${nl}TODO${nl}`);

      const proc = [
        '-----BEGIN RSA PRIVATE KEY-----',
        'Proc-Type: 4,ENCRYPTED',
        'DEK-Info: DES-EDE3-CBC,0123456789ABCDEF',
        '',
        LINE64,
        LINE70,
        'Next',
      ].join(nl) + nl;
      const procOut = redactSecretsInText(proc);
      assert.equal(procOut, `${PEM_REPLACEMENT}${nl}Next${nl}`, `proc ${JSON.stringify(nl)}`);
      assert.equal(procOut.includes('Proc-Type'), false);
      assert.equal(procOut.includes('0123456789ABCDEF'), false);
    }

    const partial = `${ALPHABET.slice(0, 40)}==`;
    assert.equal(
      redactSecretsInText(`-----BEGIN RSA PRIVATE KEY-----\n${LINE64}\n${partial} PROSE_KEEP`),
      `${PEM_REPLACEMENT} PROSE_KEEP`,
    );
    assert.equal(redactSecretsInText(`-----BEGIN PRIVATE KEY-----\nYQ==\n`), PEM_REPLACEMENT);
    assert.equal(
      redactSecretsInText(`-----BEGIN PRIVATE KEY-----\r${LINE64}\r${LINE70}`),
      PEM_REPLACEMENT,
    );
  });

  it('keeps a short mixed-case alnum line such as Ab1', () => {
    const words = ['Ab1', 'aB1', 'Xy9', 'Next', 'README', 'npm', 'test', 'TODO', 'QUJD'];
    for (const word of words) {
      for (const nl of ['\n', '\r\n', '\r']) {
        const raw = `-----BEGIN PRIVATE KEY-----${nl}${LINE64}${nl}${word}${nl}`;
        assert.equal(
          redactSecretsInText(raw),
          `${PEM_REPLACEMENT}${nl}${word}${nl}`,
          `${word} ${JSON.stringify(nl)}`,
        );
      }
    }
    const note = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    const entry = note.slice(note.indexOf('## [1.0.58]'), note.indexOf('## [1.0.57]'));
    assert.match(entry, /Ab1/);
    assert.match(entry, /short mixed-case/);
  });
});

describe('v1.0.58 3-character path fragments stay masked', () => {
  const kept = [
    '/src/app.ts',
    '/ab.ts',
    '/a/b.js',
    '/App.md',
    '/src/components/Button.tsx',
    '/components/NavBar.vue',
    '/src/api/getUser.js',
    '/Users/pramod/repo/x.ts',
    '/home/runner/work/a/b.ts',
    'src/main/java/com/example/service/UserService.java',
    '/src/main/java/com/example/service/UserService.java',
    'app/Http/Controllers/Admin/UserController.php',
    '/app/Http/Controllers/Admin/UserController.php',
    '+src/main/java/com/example/service/UserService.java',
    '+/app/Http/Controllers/Admin/UserController.php',
  ];
  const masked = [
    '/nav.ts',
    'nav.ts',
    '/bar.ts',
    '/get.ts',
    '/src/nav.ts',
    '/nav/src.ts',
    '/xyz.ts',
    '/abc/def.ts',
    'src/main/java/com/example/service/Ahsqowx.java',
    '/src/main/java/com/example/service/Ahsqowx.java',
  ];

  it('keeps grounded paths and masks 3-character fragments on every alg', () => {
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        const signature = 'A'.repeat(at);
        const token = jwtFor(alg, signature);
        for (const path of kept) {
          const raw = `${token}${path}${TRAILER}`;
          for (const mode of ['general', 'strict']) {
            const out = maskJwtTokens(raw, mode);
            assert.equal(out, `[REDACTED]${path}${TRAILER}`, `${alg} ${at} ${mode} ${path}`);
          }
          assert.equal(redactSecretsInText(raw), `[REDACTED]${path}${TRAILER}`, path);
        }
        for (const path of masked) {
          const stem = inSegment(path);
          const ext = path.slice(stem.length);
          const raw = `${token}${path}${TRAILER}`;
          const residue = (out) => out.split('[REDACTED]').join('').split(TRAILER).join('').split(ext).join('');
          for (const mode of ['general', 'strict']) {
            assertNoRawTail(residue(maskJwtTokens(raw, mode)), stem, `${alg} ${at} ${mode} ${path}`);
          }
          assertNoRawTail(residue(redactSecretsInText(raw)), stem, `${alg} text ${path}`);
        }
      }
    }
  });

  it('seeded sweep leaks no 3+ raw signature characters', () => {
    const std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const bare = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const exts = ['.ts', '.tsx', '.md', '.swift', '.java', '.json', '.php'];
    const words = ['nav', 'bar', 'get', 'xyz', 'abc', 'qow'];
    const forcedWords = new Set(words);
    const next = lcg(0x1058);
    let probes = 0;
    let leaks = 0;
    const residueOf = (out, ext) => out.split('[REDACTED]').join('').split(TRAILER).join('').split(ext).join('');
    const countLeaks = (residue, signature, stem) => {
      const body = stem.startsWith('/') || stem.startsWith('+') ? stem.slice(1) : stem;
      const seg = body.split('/').pop();
      if (forcedWords.has(seg) && residue.includes(seg)) return 1;
      // A fully kept grounded path is the stem itself. Its letters are the
      // path. Anything else still in the residue is signature text.
      if (residue === stem) return 0;
      let n = 0;
      for (let i = 0; i + 3 <= signature.length; i += 1) {
        if (residue.includes(signature.slice(i, i + 3))) n += 1;
      }
      for (let i = 0; i + 3 <= stem.length; i += 1) {
        const window = stem.slice(i, i + 3);
        if (residue.includes(window)) n += 1;
      }
      return n;
    };
    const check = (signature, stem, ext) => {
      const raw = `${jwtFor(RSA_ALGS[probes % RSA_ALGS.length], signature + stem)}${ext}${TRAILER}`;
      for (const mode of ['general', 'strict']) {
        const out = maskJwtTokens(raw, mode);
        leaks += countLeaks(residueOf(out, ext), signature, stem);
        assert.equal(out.includes(TRAILER), true, stem);
      }
      const text = redactSecretsInText(raw);
      leaks += countLeaks(residueOf(text, ext), signature, stem);
      probes += 1;
    };
    for (let n = 0; n < 2048; n += 1) {
      const at = SPOTS[next() % SPOTS.length];
      let signature = '';
      for (let i = 0; i < at; i += 1) signature += bare[next() % bare.length];
      const ext = exts[next() % exts.length];
      let stem = '';
      const stemLen = 3 + (next() % 12);
      if (n % 2 === 0) {
        stem = next() % 2 === 0 ? '/' : '+';
        for (let i = 1; i < stemLen; i += 1) stem += std[next() % std.length];
      } else {
        for (let i = 0; i < stemLen; i += 1) stem += bare[next() % bare.length];
      }
      if (n % 5 === 0) {
        const word = words[next() % words.length];
        const slash = n % 2 === 0 ? '/' : '';
        stem = `${slash}${word}`;
      } else if (!/[A-Z]/.test(stem)) {
        const pos = stem.startsWith('/') || stem.startsWith('+') ? 1 : 0;
        stem = `${stem.slice(0, pos)}${upper[next() % upper.length]}${stem.slice(pos)}`;
      }
      check(signature, stem, ext);
    }
    assert.equal(probes, 2048);
    assert.equal(leaks, 0);
  });
});

describe('v1.0.58 deep Java and PHP paths on every redaction surface', { timeout: 180000 }, () => {
  it('keeps the paths and masks a secret-shaped segment in plain and JSON output', () => {
    const dir = gitRepo('ar1058-path-');
    const kept = [
      'src/main/java/com/example/service/UserService.java',
      '/src/main/java/com/example/service/UserService.java',
      'app/Http/Controllers/Admin/UserController.php',
      '/app/Http/Controllers/Admin/UserController.php',
    ];
    const masked = 'src/main/java/com/example/service/Ahsqowx.java';
    const secret = 'Ahsqowx';
    const parts = [];
    for (const path of kept) {
      parts.push(`${jwtFor('RS256', 'E'.repeat(342))}${path}`);
    }
    parts.push(`${jwtFor('PS256', `${'F'.repeat(512)}${inSegment(masked)}`)}.java`);
    const note = parts.join(' ');
    writeFileSync(join(dir, 'token.txt'), `${note}\n`);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', note]).code, 0);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(kept[0]), true, 'stored receipt stays raw');

    function gone(text, label) {
      assertNoRawTailOnSurface(text, secret, label, dir);
      assert.equal(text.includes('E'.repeat(8)), false, `${label} leaked a kept-path signature`);
      assert.equal(text.includes('F'.repeat(8)), false, `${label} leaked a masked-path signature`);
    }

    function keptPaths(text, label) {
      for (const path of kept) assert.equal(text.includes(path), true, `${label} dropped ${path}`);
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
    assert.ok(shareJson && shareJson.htmlPath && shareJson.markdownPath);
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
    gone(JSON.stringify(statement.predicate), 'attest statement');
    keptPaths(statement.predicate.message, 'attest statement message');
    const plainAttest = cli(dir, ['attest', storedPath]);
    assert.equal(plainAttest.code, 0, plainAttest.err + plainAttest.out);
    gone(plainAttest.out + plainAttest.err, 'attest');
  });
});
