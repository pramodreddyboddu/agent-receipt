/**
 * v1.0.60 — v1.0.59 Release QA follow-ups.
 * A post-gap identifier stays only when every part is a real word.
 * A base64url tail of 1 to 3 characters split on _ or - is redacted.
 * An unfenced diff prefix is not part of a private-key body line.
 * A lone 3-letter path atom does not keep a signature fragment.
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
const OTHER_ALGS = [
  ['HS256', 43],
  ['ES256', 86],
  ['EdDSA', 86],
];
const TRAILER = '\u0001';
const PEM_REPLACEMENT = '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----';
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LINE64 = ALPHABET.slice(0, 64);
const SAMPLE = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
].join('.');

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

function block(nl, lines) {
  return `-----BEGIN PRIVATE KEY-----${nl}${lines.join(nl)}${nl}`;
}

describe('v1.0.60 a post-gap identifier must be real words', () => {
  const kept = [
    'veryLongCamelCaseIdentifier',
    'IdentifierValue16',
    'HTTPServerConfig',
    'getUserProfileSettingsNow',
    'thisIsAVeryLongCamelCaseIdentifierName',
    'parseJSONResponse',
    'user_profile_settings_name',
  ];
  const leaked = [
    'abcdefghIjklmnop',
    'abcdefghijKlmnopq',
    'abcDefghijklmnopqr',
    'abcdEfghijklmnopqrs',
    'ABcdefghijklmnop',
    'abcdefghijklmnop',
    'abcDe12fghijklmn',
  ];

  it('keeps real words after a gap and redacts them after a resumed body line', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const line of kept) {
        const gap = redactSecretsInText(block(nl, [LINE64, '', line, 'Next']));
        const label = `${line} ${JSON.stringify(nl)}`;
        assert.equal(gap.includes(line), true, label);
        assert.equal(gap.includes(LINE64), false, label);
        const wide = redactSecretsInText(block(nl, [LINE64, '', LINE64, line, 'Next']));
        if (line.includes('_')) {
          assert.equal(wide.includes(line), true, `wide ${label}`);
        } else {
          assert.equal(wide.includes(line), false, `wide ${label}`);
        }
        assert.equal(wide.includes(LINE64), false, `wide ${label}`);
      }
    }
  });

  it('redacts letters-only lines that only look like camelCase', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const line of leaked) {
        const out = redactSecretsInText(block(nl, [LINE64, '', line, 'Next']));
        const label = `${line} ${JSON.stringify(nl)}`;
        assert.equal(out, `${PEM_REPLACEMENT}${nl}Next${nl}`, label);
        assert.equal(out.includes(line), false, label);
      }
    }
  });

  it('keeps the same names inside a JSON value', () => {
    for (const line of kept) {
      const json = JSON.stringify({ message: line, note: 'share' });
      const out = redactSecretsInText(json);
      assert.equal(out.includes(line), true, line);
    }
    const random = 'abcdefghIjklmnop';
    const hidden = redactSecretsInText(block('\n', [LINE64, '', random]));
    assert.equal(hidden.includes(random), false);
  });

  it('seeded sweep leaks no letters-only 16 to 19 character line after a gap', () => {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const next = lcg(0x1060a11);
    const breaks = ['\n', '\r\n', '\r'];
    let probes = 0;
    for (let n = 0; n < 2048; n += 1) {
      const len = 16 + (next() % 4);
      let line = '';
      if (n % 4 === 0) {
        line = letters[26 + (next() % 26)];
        const capAt = 1 + (next() % (len - 2));
        for (let i = 1; i < len; i += 1) {
          if (i === capAt) line += letters[next() % 26];
          else line += letters[26 + (next() % 26)];
        }
      } else {
        for (let i = 0; i < len; i += 1) line += letters[next() % letters.length];
      }
      const nl = breaks[next() % breaks.length];
      const out = redactSecretsInText(block(nl, [LINE64, '', line, 'Next']));
      const label = `${line.length} ${JSON.stringify(nl)} ${line}`;
      assert.equal(out.includes(line), false, label);
      assert.equal(out.includes(LINE64), false, label);
      assert.equal(out.includes('Next'), true, label);
      probes += 1;
    }
    assert.equal(probes, 2048);
  });
});

describe('v1.0.60 a base64url tail of 1 to 3 characters is redacted', () => {
  const tails = ['_', '-', '_x', '-a', '_ab', '-ab'];

  it('masks an appended tail of 1, 2, and 3 characters', () => {
    for (const tail of tails) {
      assert.equal(tail.length >= 1 && tail.length <= 3, true, tail);
      for (const mode of ['general', 'strict']) {
        const masked = maskJwtTokens(`${SAMPLE}${tail}`, mode);
        assert.equal(masked, '[REDACTED]', `${mode} ${tail}`);
        assert.equal(masked.includes(tail), false, `${mode} ${tail}`);
      }
      const text = redactSecretsInText(`${SAMPLE}${tail}`);
      assert.equal(text, '[REDACTED]', tail);
      assert.equal(text.includes(SAMPLE), false, tail);
    }
  });

  it('masks a signature that itself ends in a 1, 2, or 3 character tail', () => {
    for (const tail of tails) {
      const token = jwtFor('HS256', `${'A'.repeat(40)}${tail}`);
      assert.equal(token.endsWith(tail), true, tail);
      for (const mode of ['general', 'strict']) {
        assert.equal(maskJwtTokens(token, mode), '[REDACTED]', `${mode} ${tail}`);
      }
      assert.equal(redactSecretsInText(token), '[REDACTED]', tail);
    }
  });

  it('still keeps a whole-word hyphen suffix and a joiner between two tokens', () => {
    assert.equal(redactSecretsInText(`${SAMPLE}-then`), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${SAMPLE}-Then`), '[REDACTED]-Then');
    assert.equal(redactSecretsInText(`${SAMPLE}-config-file`), '[REDACTED]-config-file');
    assert.equal(maskJwtTokens(`${SAMPLE}-then`, 'strict'), '[REDACTED]-then');
    assert.equal(redactSecretsInText(`${SAMPLE}_${SAMPLE}`), '[REDACTED]_[REDACTED]');
    assert.equal(redactSecretsInText(`${SAMPLE}-${SAMPLE}`), '[REDACTED]-[REDACTED]');
  });
});

describe('v1.0.60 an unfenced diff prefix is not part of a key line', () => {
  it('redacts minus and plus body lines and keeps markers and ordinary lines', () => {
    for (const nl of ['\n', '\r\n']) {
      const raw = [
        '--- a/secret.pem',
        '+++ b/secret.pem',
        '@@ -1,6 +1,6 @@',
        '-----BEGIN PRIVATE KEY-----',
        `-${LINE64}`,
        `-${LINE64}`,
        `-${LINE64}`,
        `+${LINE64}`,
        '+hello',
        '-removed ordinary line',
        ' context stays',
        '--- a/other.pem',
      ].join(nl);
      const out = redactSecretsInText(raw);
      assert.equal(out.includes(LINE64), false, JSON.stringify(nl));
      assert.equal(out.includes('--- a/secret.pem'), true);
      assert.equal(out.includes('+++ b/secret.pem'), true);
      assert.equal(out.includes('@@ -1,6 +1,6 @@'), true);
      assert.equal(out.includes('+hello'), true);
      assert.equal(out.includes('-removed ordinary line'), true);
      assert.equal(out.includes(' context stays'), true);
      assert.equal(out.includes('--- a/other.pem'), true);
      assert.equal(out.includes('[REDACTED]'), true);
    }
  });

  it('keeps a diff-prefixed word after a gap and redacts one after resumed body lines', () => {
    const ident = 'veryLongCamelCaseIdentifier';
    const longName = 'thisIsAVeryLongCamelCaseIdentifierName';
    const raw = [
      '+-----BEGIN PRIVATE KEY-----',
      `+${LINE64}`,
      '+',
      `+${ident}`,
      `-${longName}`,
      '+user_profile_settings_name',
      `+${'ab'.repeat(24)}`,
      '+Next',
    ].join('\n');
    const out = redactSecretsInText(raw);
    assert.equal(out.includes(ident), true);
    assert.equal(out.includes(longName), true);
    assert.equal(out.includes('user_profile_settings_name'), true);
    assert.equal(out.includes('ab'.repeat(24)), true);
    assert.equal(out.includes(LINE64), false);
    assert.equal(out.includes('+Next'), true);

    const resumed = [
      '- -----BEGIN PRIVATE KEY-----',
      `-${LINE64}`,
      '-',
      `-${LINE64}`,
      `-abcdefghIjklmnop`,
      `+${ident}`,
      '+Next',
    ].join('\n');
    const wide = redactSecretsInText(resumed);
    assert.equal(wide.includes(ident), false);
    assert.equal(wide.includes('abcdefghIjklmnop'), false);
    assert.equal(wide.includes(LINE64), false);
    assert.equal(wide.includes('+Next'), true);
  });

  it('redacts a short key fragment on a diff line and keeps the trailing prose', () => {
    const raw = `-----BEGIN PRIVATE KEY-----\n-${LINE64} trailing note\n+Next\n`;
    const out = redactSecretsInText(raw);
    assert.equal(out.includes(LINE64), false);
    assert.equal(out.includes('trailing note'), true);
    assert.equal(out.includes('+Next'), true);
    const short = redactSecretsInText(`-----BEGIN PRIVATE KEY-----\n-YQ==\nNext\n`);
    assert.equal(short.includes('YQ=='), false);
    assert.equal(short.includes('Next'), true);
  });
});

describe('v1.0.60 a lone 3-letter path atom stays masked', () => {
  const kept = [
    './src/app.ts',
    'src/App.tsx',
    'app/src/index.ts',
    '/src/app.ts',
    '/src/App.tsx',
    '/src/nav.ts',
    './bin/cli.js',
    'src/bin/main.rs',
    '/Src/lib/App.tsx',
    'UserProfile.tsx',
    'HomeView.swift',
    '/components/NavBar.vue',
    '/docs/README.md',
    '/README.md',
    '/ab.ts',
    '/a/b.js',
    '/lib/parseJSON.ts',
  ];
  const masked = ['/Src.ts', '/App.ts', '/src.ts', '/app.ts', '/lib.ts', '/Api.ts', '/App.md', '/Bin.ts'];

  function check(alg, signature, path, stay) {
    const token = jwtFor(alg, signature);
    const raw = `${token}${path}${TRAILER}`;
    for (const mode of ['general', 'strict']) {
      const out = maskJwtTokens(raw, mode);
      const label = `${alg} ${signature.length} ${mode} ${path}`;
      assert.equal(out.includes('A'.repeat(8)), false, `${label} signature`);
      assert.equal(out.includes(TRAILER), true, label);
      if (stay) assert.equal(out.includes(path), true, label);
      else {
        assert.equal(out.includes(path), false, label);
        const stem = path.slice(0, path.lastIndexOf('.'));
        assert.equal(out.includes(stem), false, `${label} stem`);
      }
    }
  }

  it('masks /Src.ts and /App.ts and keeps a path with a second segment', () => {
    for (const alg of RSA_ALGS) {
      for (const at of SPOTS) {
        const signature = 'A'.repeat(at);
        for (const path of kept) check(alg, signature, path, true);
        for (const path of masked) check(alg, signature, path, false);
      }
    }
    for (const [alg, at] of OTHER_ALGS) {
      const signature = 'A'.repeat(at);
      for (const path of ['/Src.ts', '/App.ts', '/App.md', '/src.ts', '/Bin.ts']) {
        check(alg, signature, path, false);
      }
      for (const path of ['./src/app.ts', '/src/app.ts', '/src/App.tsx', '/src/nav.ts', './bin/cli.js', '/ab.ts', '/README.md']) {
        check(alg, signature, path, true);
      }
    }
  });
});

describe('v1.0.60 long identifiers stay on plain and JSON surfaces', { timeout: 180000 }, () => {
  it('shows the names and masks the key, a random line, and a lone path atom', () => {
    const dir = gitRepo('ar1060-ident-');
    const longName = 'thisIsAVeryLongCamelCaseIdentifierName';
    const parsed = 'parseJSONResponse';
    const ident = 'veryLongCamelCaseIdentifier';
    const random = 'abcdefghIjklmnop';
    const keptPaths = ['./src/app.ts', 'src/App.tsx', 'app/src/index.ts', '/src/app.ts', '/src/App.tsx'];
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      LINE64,
      '',
      random,
      'Next',
    ];
    const parts = [`${jwtFor('RS256', `${'E'.repeat(342)}/Src`)}.ts`, `${jwtFor('RS256', `${'F'.repeat(342)}/App`)}.md`];
    for (const path of keptPaths) parts.push(`${jwtFor('RS256', 'G'.repeat(342))}${path}`);
    const keepNote = ['qa keep', longName, parsed, ident, 'Next', ...keptPaths, ...parts].join('\n');
    const note = `${pem.join('\n')}\n${keepNote}\n`;
    writeFileSync(join(dir, 'token.txt'), note);
    git(dir, ['add', 'token.txt']);
    git(dir, ['commit', '-m', 'add token']);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', 'baseline']).code, 0);
    assert.equal(cli(dir, ['capture', '--agent', 'cursor', '--message', keepNote]).code, 0);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(longName), true, 'stored receipt stays raw');
    assert.equal(stored.includes(LINE64), true, 'stored key stays raw');

    function gone(text, label) {
      assert.equal(text.includes(LINE64), false, `${label} leaked the key line`);
      assert.equal(text.includes(random), false, `${label} kept a random camelCase line`);
      assert.equal(text.includes('E'.repeat(8)), false, `${label} leaked /Src`);
      assert.equal(text.includes('/Src'), false, `${label} kept /Src`);
      assert.equal(text.includes('Src.ts'), false, `${label} kept Src.ts`);
      assert.equal(text.includes('F'.repeat(8)), false, `${label} leaked /App`);
      assert.equal(text.includes('/App.md'), false, `${label} kept /App.md`);
    }

    function kept(text, label) {
      for (const line of [longName, parsed, ident, 'Next']) {
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

describe('v1.0.60 changelog', () => {
  it('lists the five Release QA follow-ups', () => {
    const note = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    const entry = note.slice(note.indexOf('## [1.0.60]'), note.indexOf('## [1.0.59]'));
    assert.match(entry, /real word/);
    assert.match(entry, /parseJSONResponse/);
    assert.match(entry, /_x/);
    assert.match(entry, /unified diff/);
    assert.match(entry, /\/Src\.ts/);
    assert.match(entry, /thisIsAVeryLongCamelCaseIdentifierName/);
    assert.match(entry, /npm publish, which is on hold/);
    assert.match(entry, /v1\.0\.59 Release QA follow-ups/);
    assert.match(entry, /1\.0\.47 through 1\.0\.59/);
  });
});
