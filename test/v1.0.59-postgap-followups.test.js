/**
 * v1.0.59 — v1.0.58 Release QA follow-ups.
 * A short base64-only final line after a truncated private key is redacted.
 * That includes an alphanumeric line after resumed full-width body lines.
 * A 3-letter directory word such as bin needs a second grounding segment.
 * A word-shaped identifier stays when it follows the gap and no body line
 * has resumed. The same shape after a resumed body line is key material.
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

function block(nl, lines) {
  return `-----BEGIN PRIVATE KEY-----${nl}${lines.join(nl)}${nl}`;
}

describe('v1.0.59 a short final key line after a gap is redacted', () => {
  const finals = [
    'LSZgnu18DKRYfmt0',
    'LSZgnu18DKRYfmt0A',
    'LSZgnu18DKRYfmt0AB',
    'LSZgnu18DKRYfmt0ABC',
    'abcdefghijklmnop',
  ];
  const prose = [
    'hello world',
    'hello!',
    'note: done',
    '/src/app.ts',
    'ok /src/app.ts',
    'Next',
    'Ab1',
    'user_profile_settings_name',
  ];
  const names = ['IdentifierValue16', 'veryLongCamelCaseIdentifier', 'HTTPServerConfig'];

  it('redacts a 16 to 19 character base64-only line, including after full-width lines', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const line of finals) {
        const gapOnly = block(nl, [LINE64, '', line, 'Next']);
        const out = redactSecretsInText(gapOnly);
        const label = `gap ${line.length} ${JSON.stringify(nl)}`;
        assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, label);
        assert.equal(out.includes(line), false, label);
        assert.equal(out.includes(LINE64), false, label);

        const resumed = block(nl, [LINE64, '', LINE64, line, 'Next']);
        const wide = redactSecretsInText(resumed);
        assert.equal(wide, `${PEM_REPLACEMENT}${nl}Next${nl}`, `wide ${label}`);
        assert.equal(wide.includes(line), false, label);
      }
    }
  });

  it('keeps ordinary short text, identifiers, and paths after the body', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const line of prose) {
        const raw = block(nl, [LINE64, '', line]);
        const out = redactSecretsInText(raw);
        const label = `${JSON.stringify(line)} ${JSON.stringify(nl)}`;
        assert.equal(out.includes(line), true, label);
        assert.equal(out.includes(LINE64), false, label);

        const resumed = block(nl, [LINE64, '', LINE64, line]);
        const wide = redactSecretsInText(resumed);
        assert.equal(wide.includes(line), true, `wide ${label}`);
        assert.equal(wide.includes(LINE64), false, `wide ${label}`);
      }
      for (const line of names) {
        const raw = block(nl, [LINE64, '', line, 'Next']);
        const out = redactSecretsInText(raw);
        const label = `${line} ${JSON.stringify(nl)}`;
        assert.equal(out, `${PEM_REPLACEMENT}${nl}${nl}${line}${nl}Next${nl}`, label);
        assert.equal(out.includes(LINE64), false, label);

        const resumed = block(nl, [LINE64, '', LINE64, line, 'Next']);
        const wide = redactSecretsInText(resumed);
        assert.equal(wide, `${PEM_REPLACEMENT}${nl}Next${nl}`, `wide ${label}`);
        assert.equal(wide.includes(line), false, `wide ${label}`);
        assert.equal(wide.includes(LINE64), false, `wide ${label}`);
      }
    }
  });

  it('keeps a camelCase name on a unified-diff addition line after a gap', () => {
    const ident = 'veryLongCamelCaseIdentifier';
    const raw = [
      '+-----BEGIN PRIVATE KEY-----',
      `+${LINE64}`,
      '+',
      `+${ident}`,
      '+user_profile_settings_name',
      `+${'ab'.repeat(24)}`,
      '+Next',
    ].join('\n');
    const out = redactSecretsInText(raw);
    assert.equal(out.includes(ident), true);
    assert.equal(out.includes('user_profile_settings_name'), true);
    assert.equal(out.includes('ab'.repeat(24)), true);
    assert.equal(out.includes(LINE64), false);
    assert.equal(out.includes('+Next'), true);
  });

  it('redacts a camelCase addition line that follows resumed diff body lines', () => {
    const ident = 'veryLongCamelCaseIdentifier';
    const raw = [
      '+-----BEGIN PRIVATE KEY-----',
      `+${LINE64}`,
      '+',
      `+${LINE64}`,
      '+LSZgnu18DKRYfmt0',
      `+${ident}`,
      '+Next',
    ].join('\n');
    const out = redactSecretsInText(raw);
    assert.equal(out.includes(ident), false);
    assert.equal(out.includes('LSZgnu18DKRYfmt0'), false);
    assert.equal(out.includes(LINE64), false);
    assert.equal(out.includes('+Next'), true);
  });

  it('still redacts a 20 character base64 line that is not an identifier', () => {
    const line = 'abcdefghijklmnopqrst';
    for (const nl of ['\n', '\r\n', '\r']) {
      const out = redactSecretsInText(block(nl, [LINE64, '', line, 'Next']));
      assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, JSON.stringify(nl));
      assert.equal(out.includes(line), false);
    }
  });
});

describe('v1.0.59 an alphanumeric final line after resumed body lines is redacted', () => {
  // Letter-only camelCase. The old identifier keep left these raw.
  const finals = {
    16: 'abcdefghijKmmmmm',
    19: 'abcdefghijKmmmmmmmm',
    20: 'abcdefghijKmmmmmmmmm',
    43: `abcdefghijK${'m'.repeat(32)}`,
  };

  it('redacts 16, 19, 20, and 43 character lines after 1 or 2 resumed lines', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const resumes of [1, 2]) {
        for (const length of [16, 19, 20, 43]) {
          const line = finals[length];
          assert.equal(line.length, length);
          const lines = [LINE64, ''];
          for (let n = 0; n < resumes; n += 1) lines.push(LINE64);
          lines.push(line, 'Next');
          const out = redactSecretsInText(block(nl, lines));
          const label = `${resumes} ${length} ${JSON.stringify(nl)}`;
          assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, label);
          assert.equal(out.includes(line), false, label);
          assert.equal(out.includes(LINE64), false, label);
        }
      }
    }
  });

  it('redacts a digit-mixed line after a gap and after resumed body lines', () => {
    const mixed = 'abcDe12fghijklmn';
    assert.equal(mixed.length, 16);
    for (const nl of ['\n', '\r\n', '\r']) {
      const gap = redactSecretsInText(block(nl, [LINE64, '', mixed, 'Next']));
      assert.equal(gap, `${PEM_REPLACEMENT}${nl}Next${nl}`, `gap ${JSON.stringify(nl)}`);
      const resumed = redactSecretsInText(block(nl, [LINE64, '', LINE64, mixed, 'Next']));
      assert.equal(resumed, `${PEM_REPLACEMENT}${nl}Next${nl}`, `wide ${JSON.stringify(nl)}`);
    }
  });

  it('keeps a hex digest after a gap and redacts one after resumed body lines', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const line of ['a'.repeat(32), 'b'.repeat(40), 'c'.repeat(64)]) {
        const resumed = redactSecretsInText(block(nl, [LINE64, '', LINE64, line, 'Next']));
        const label = `${line.length} ${JSON.stringify(nl)}`;
        assert.equal(resumed, `${PEM_REPLACEMENT}${nl}Next${nl}`, label);
        assert.equal(resumed.includes(line), false, label);
      }
      const hex40 = 'e'.repeat(40);
      const gap = redactSecretsInText(block(nl, [LINE64, '', hex40, 'Next']));
      assert.equal(gap, `${PEM_REPLACEMENT}${nl}${nl}${hex40}${nl}Next${nl}`, `gap ${JSON.stringify(nl)}`);
      assert.equal(gap.includes(LINE64), false);
    }
  });

  it('does not keep a random capital pair as an acronym', () => {
    const line = 'ABcdefghijklmnop';
    assert.equal(line.length, 16);
    for (const nl of ['\n', '\r\n', '\r']) {
      const out = redactSecretsInText(block(nl, [LINE64, '', line, 'Next']));
      assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, JSON.stringify(nl));
    }
  });

  it('seeded sweep leaks no final key line after resumed body lines', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const next = lcg(0x1059f11);
    const breaks = ['\n', '\r\n', '\r'];
    let probes = 0;
    const check = (line, resumes, nl) => {
      const lines = [LINE64, ''];
      for (let n = 0; n < resumes; n += 1) lines.push(LINE64);
      lines.push(line, 'Next');
      const out = redactSecretsInText(block(nl, lines));
      const label = `${resumes} ${line.length} ${JSON.stringify(nl)} ${line}`;
      assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, label);
      assert.equal(out.includes(line), false, label);
      assert.equal(out.includes(LINE64), false, label);
      probes += 1;
    };
    const forcedCamel = (len) => {
      let line = alphabet[26 + (next() % 26)];
      const capAt = 1 + (next() % (len - 2));
      for (let i = 1; i < len; i += 1) {
        if (i === capAt) line += alphabet[next() % 26];
        else line += alphabet[26 + (next() % 26)];
      }
      return line;
    };
    for (let n = 0; n < 2048; n += 1) {
      const len = 16 + (next() % 48);
      let line = '';
      if (n % 4 === 0) line = forcedCamel(len);
      else {
        for (let i = 0; i < len; i += 1) line += alphabet[next() % alphabet.length];
      }
      check(line, 1 + (next() % 2), breaks[next() % breaks.length]);
    }
    assert.equal(probes, 2048);
  });
});

describe('v1.0.59 identifiers and 48 or 56 hex stay after the key body', () => {
  const ident = 'veryLongCamelCaseIdentifier';
  const pascal = 'IdentifierValue16';
  const snake = 'user_profile_settings_name';
  const camel = 'getUserProfileSettingsNow';
  const hex48 = 'ab'.repeat(24);
  const hex56 = 'cd'.repeat(28);
  const hex64 = 'a'.repeat(64);

  it('shows names and 48-hex or 56-hex strings and keeps the key redacted', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      const raw = block(nl, [LINE64, '', ident, pascal, snake, camel, hex48, hex56, 'Next']);
      const out = redactSecretsInText(raw);
      const label = JSON.stringify(nl);
      assert.equal(out.includes(LINE64), false, label);
      for (const line of [ident, pascal, snake, camel, hex48, hex56, 'Next']) {
        assert.equal(out.includes(line), true, `${label} ${line}`);
      }

      const resumed = block(nl, [LINE64, '', LINE64, snake, hex48, hex56, 'Next']);
      const wide = redactSecretsInText(resumed);
      assert.equal(wide.includes(LINE64), false, `wide ${label}`);
      for (const line of [snake, hex48, hex56, 'Next']) {
        assert.equal(wide.includes(line), true, `wide ${label} ${line}`);
      }
      const named = block(nl, [LINE64, '', LINE64, ident, 'Next']);
      assert.equal(
        redactSecretsInText(named),
        `${PEM_REPLACEMENT}${nl}Next${nl}`,
        `wide name ${label}`,
      );
    }
  });

  it('still swallows a 64-hex line when a later body line follows', () => {
    const out = redactSecretsInText(`-----BEGIN PRIVATE KEY-----\n${LINE64}\n\n${hex64}\n${LINE64}\nNext\n`);
    assert.equal(out, `${PEM_REPLACEMENT}\nNext\n`);
    assert.equal(out.includes(hex64), false);
    const prose = redactSecretsInText(`-----BEGIN PRIVATE KEY-----\n${LINE64}\n\n${hex64}\nNext\n`);
    assert.equal(prose, `${PEM_REPLACEMENT}\n\n${hex64}\nNext\n`);
  });

  it('still redacts a hex body line at 44, 70, and 76', () => {
    const hex = '0123456789abcdef';
    for (const width of [44, 70, 76]) {
      let body = '';
      for (let i = 0; i < width; i += 1) body += ALPHABET[(i * 3 + width) % ALPHABET.length];
      if (/^[0-9a-fA-F]+$/.test(body)) body = `${body.slice(0, -1)}+`;
      let digits = '';
      for (let i = 0; i < width; i += 1) digits += hex[i % hex.length];
      const out = redactSecretsInText(`-----BEGIN PRIVATE KEY-----\n${body}\n\n${digits}\nNext\n`);
      assert.equal(out, `${PEM_REPLACEMENT}\nNext\n`, String(width));
      assert.equal(out.includes(digits), false, String(width));
    }
  });
});

describe('v1.0.59 a 3-letter bin directory needs a second ground', () => {
  const kept = [
    './bin/cli.js',
    '/bin/cli.js',
    'bin/cli.js',
    '/bin/run',
    'src/bin/main.rs',
    '/src/bin/main.rs',
    'node_modules/.bin/tsc',
    '/node_modules/.bin/tsc',
    'node_modules/.bin/cli.js',
    'node_modules/.bin/tsserver',
    '/src/app.ts',
    '/src/nav.ts',
    '/src/bin.ts',
    '/lib/nav.ts',
    'src/main/java/com/example/service/UserService.java',
    '/Users/pramod/repo/x.ts',
  ];
  const masked = ['/Bin.ts', '/bin.ts', '/BIN.ts', '/Bin.ts', '/nav.ts', '/o/bin.ts', '+/Bin.ts'];

  it('keeps grounded bin paths and masks a lone bin fragment', () => {
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
            const left = residue(maskJwtTokens(raw, mode));
            assert.equal(left.toLowerCase().includes('bin'), false, `${alg} ${at} ${mode} ${path} ${left}`);
            assertNoRawTail(left, stem.replace(/^[+/]/, ''), `${alg} ${at} ${mode} ${path}`);
          }
          const textLeft = residue(redactSecretsInText(raw));
          assert.equal(textLeft.toLowerCase().includes('bin'), false, path);
        }
      }
    }
  });

  it('seeded sweep leaks no 3+ raw signature characters', () => {
    const std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const bare = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const exts = ['.ts', '.tsx', '.md', '.swift', '.java', '.json', '.php'];
    const words = ['nav', 'bar', 'get', 'xyz', 'abc', 'qow', 'bin', 'Bin', 'BIN'];
    const forcedWords = new Set(words);
    const next = lcg(0x1059);
    let probes = 0;
    let leaks = 0;
    const residueOf = (out, ext) => out.split('[REDACTED]').join('').split(TRAILER).join('').split(ext).join('');
    const countLeaks = (residue, signature, stem) => {
      const body = stem.startsWith('/') || stem.startsWith('+') ? stem.slice(1) : stem;
      if (body.toLowerCase() === 'bin' && residue.toLowerCase().includes('bin')) return 1;
      const seg = body.split('/').pop();
      if (forcedWords.has(seg) && residue.includes(seg)) return 1;
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

describe('v1.0.59 keeps on plain and JSON redaction surfaces', { timeout: 180000 }, () => {
  it('shows identifiers and hashes, masks the key and a lone bin fragment', () => {
    const dir = gitRepo('ar1059-postgap-');
    const ident = 'veryLongCamelCaseIdentifier';
    const snake = 'user_profile_settings_name';
    const hex48 = 'ab'.repeat(24);
    const hex56 = 'cd'.repeat(28);
    const short = 'LSZgnu18DKRYfmt0';
    const keptPaths = [
      'node_modules/.bin/tsc',
      './bin/cli.js',
      'src/bin/main.rs',
      '/bin/cli.js',
      '/bin/run',
    ];
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      LINE64,
      '',
      LINE64,
      short,
      ident,
      snake,
      hex48,
      hex56,
      'hello world',
      '/src/app.ts',
      'Next',
    ];
    const parts = [];
    for (const path of keptPaths) {
      parts.push(`${jwtFor('RS256', 'E'.repeat(342))}${path}`);
    }
    parts.push(`${jwtFor('PS256', `${'F'.repeat(342)}/Bin`)}.ts`);
    const keepNote = ['qa keep', ident, snake, hex48, hex56, 'hello world', '/src/app.ts', 'Next', ...parts].join('\n');
    const note = `${pem.join('\n')}\n${keepNote}\n`;
    writeFileSync(join(dir, 'token.txt'), note);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', keepNote]).code, 0);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(ident), true, 'stored receipt stays raw');
    assert.equal(stored.includes(short), true, 'stored short line stays raw');
    assert.equal(stored.includes(LINE64), true, 'stored key stays raw');

    function gone(text, label) {
      assert.equal(text.includes(LINE64), false, `${label} leaked the key line`);
      assert.equal(text.includes(short), false, `${label} leaked the short final line`);
      assert.equal(text.includes('E'.repeat(8)), false, `${label} leaked a kept-path signature`);
      assert.equal(text.includes('/Bin'), false, `${label} kept /Bin`);
      assert.equal(text.includes('Bin.ts'), false, `${label} kept Bin.ts`);
      assert.equal(text.includes('F'.repeat(8)), false, `${label} leaked the bin signature`);
    }

    function kept(text, label) {
      for (const line of [ident, snake, hex48, hex56, 'hello world', '/src/app.ts', 'Next']) {
        assert.equal(text.includes(line), true, `${label} dropped ${line}`);
      }
      for (const path of keptPaths) {
        assert.equal(text.includes(path), true, `${label} dropped ${path}`);
      }
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
      if (showPath) kept(text, label);
      if (label === 'last --json') {
        const body = JSON.parse(result.out);
        kept(body.message, 'last --json message');
        gone(body.message, 'last --json message');
      }
      if (label === 'share --json') shareJson = JSON.parse(result.out);
    }

    const shareHtml = readFileSync(storedPath.replace(/\.md$/i, '.html'), 'utf8');
    gone(shareHtml, 'share html');
    kept(shareHtml, 'share html');
    const redactedMd = readFileSync(storedPath.replace(/\.md$/i, '.redacted.md'), 'utf8');
    gone(redactedMd, 'share redacted md');
    kept(redactedMd, 'share redacted md');
    assert.ok(shareJson && shareJson.htmlPath && shareJson.markdownPath);
    kept(readFileSync(shareJson.htmlPath, 'utf8'), 'share --json html');
    kept(readFileSync(shareJson.markdownPath, 'utf8'), 'share --json md');
    gone(readFileSync(shareJson.htmlPath, 'utf8'), 'share --json html');
    gone(readFileSync(shareJson.markdownPath, 'utf8'), 'share --json md');

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
    kept(statement.predicate.message, 'attest statement message');
    const plainAttest = cli(dir, ['attest', storedPath]);
    assert.equal(plainAttest.code, 0, plainAttest.err + plainAttest.out);
    gone(plainAttest.out + plainAttest.err, 'attest');
  });
});

describe('v1.0.59 changelog', () => {
  it('lists the three Release QA follow-ups', () => {
    const note = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    const entry = note.slice(note.indexOf('## [1.0.59]'), note.indexOf('## [1.0.58]'));
    assert.match(entry, /16 to 19/);
    assert.match(entry, /resumed full-width/);
    assert.match(entry, /HTTPServerConfig/);
    assert.match(entry, /bin/);
    assert.match(entry, /48-hex/);
    assert.match(entry, /56-hex/);
    assert.match(entry, /npm publish, which is on hold/);
    assert.match(entry, /v1\.0\.58 Release QA follow-ups/);
    assert.match(entry, /version was not bumped again/);
  });
});
