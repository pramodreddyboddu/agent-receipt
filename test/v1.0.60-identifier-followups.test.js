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
import { markdownToHtml } from '../dist/lib/html.js';
import { maskJwtTokens, publishRedactedReceipt, redactMarkdownBody, redactSecretsInText } from '../dist/lib/redact.js';

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

describe('v1.0.60 a short final PEM line that starts with + stays inside the block', () => {
  const note = 'note: keep this visible';
  const ident = 'thisIsAVeryLongCamelCaseIdentifierName';
  const notice = '> **Redacted** — high/secret findings masked for safer sharing';

  function plusLine(len) {
    const line = `+AbCdEfGhIjKlMnO`.slice(0, len);
    assert.equal(line.length, len);
    assert.equal(line.startsWith('+'), true);
    return line;
  }

  function unfencedRaw(nl, body) {
    return `-----BEGIN PRIVATE KEY-----${nl}${LINE64}${nl}${body}${nl}${note}${nl}${ident}${nl}`;
  }

  function unfencedExpected(nl) {
    return `${PEM_REPLACEMENT}${nl}${note}${nl}${ident}${nl}`;
  }

  function fencedRaw(nl, body) {
    return `\`\`\`diff${nl}${unfencedRaw(nl, body)}\`\`\`${nl}`;
  }

  function fencedExpected(nl) {
    if (nl === '\r') {
      const body = `\`\`\`diff\r-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----\r${note}\r${ident}\r\`\`\`\r`;
      return `${notice}\n\n${body}\n`;
    }
    return `${notice}\n\n\`\`\`diff\n${PEM_REPLACEMENT}\n${note}\n${ident}\n\`\`\`\n`;
  }

  for (const len of [4, 8, 12, 16]) {
    for (const nl of ['\n', '\r\n', '\r']) {
      const body = plusLine(len);
      it(`redacts a ${len}-character + line (${JSON.stringify(nl)}) and keeps the note`, () => {
        const raw = unfencedRaw(nl, body);
        const out = redactSecretsInText(raw);
        assert.equal(out, unfencedExpected(nl));
        assert.equal(out.includes(body), false);
        assert.equal(out.includes(LINE64), false);
        assert.equal(out.includes(note), true);
        assert.equal(out.includes(ident), true);

        const fenced = redactMarkdownBody(fencedRaw(nl, body));
        assert.equal(fenced, fencedExpected(nl));
        assert.equal(fenced.includes(body), false);
        assert.equal(fenced.includes(LINE64), false);
        assert.equal(fenced.includes(note), true);
        assert.equal(fenced.includes(ident), true);
      });
    }
  }

  it('seeded sweep leaves no + final key line raw, fenced or unfenced', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const next = lcg(0x1060b1);
    const breaks = ['\n', '\r\n', '\r'];
    const lengths = [4, 8, 12, 16];
    let probes = 0;
    for (let n = 0; n < 2048; n += 1) {
      const len = lengths[n % lengths.length];
      let body = '+';
      while (body.length < len) body += alphabet[next() % alphabet.length];
      const nl = breaks[n % breaks.length];
      const plain = redactSecretsInText(unfencedRaw(nl, body));
      const label = `${len} ${JSON.stringify(nl)} ${body}`;
      assert.equal(plain, unfencedExpected(nl), label);
      assert.equal(plain.includes(body), false, label);
      assert.equal(plain.includes(LINE64), false, label);
      const fenced = redactMarkdownBody(fencedRaw(nl, body));
      assert.equal(fenced, fencedExpected(nl), `fence ${label}`);
      assert.equal(fenced.includes(body), false, `fence ${label}`);
      assert.equal(fenced.includes(LINE64), false, `fence ${label}`);
      assert.equal(fenced.includes(note), true, `fence ${label}`);
      assert.equal(fenced.includes(ident), true, `fence ${label}`);
      probes += 1;
    }
    assert.equal(probes, 2048);
  });
});

describe('v1.0.60 realistic identifiers stay after a gap', () => {
  // 132 kept names plus encodeURIComponent and decodeURIComponent.
  // masked.length stays at most MAIN_MASKS. This file does not run main.
  const MAIN_MASKS = 4;
  const kept = `
getUserProfileById fetchAccountBalance handleWebSocketMsg dockerComposeFile webpackDevServer kubeletConfigPath
getUserProfileSettingsNow veryLongCamelCaseIdentifier parseJSONResponse HTTPServerConfig IdentifierValue16
renderReportHtml decodeJwtPayload parseYamlDocument uncommittedBadge canonicalizedBody
activePolicyRefs adapterBackupDir addEventListener addTrustedFingerprint allocateRelPaths
allowShareReceipt allowedHostValue createPersonalSite fetchUserSettings handleIncomingMessage
loadKubernetesConfig openDatabaseConnection parseConfigDocument readEnvironmentFile renderHtmlReport
saveUserPreferences sendWebSocketFrame startBackgroundWorker stopBackgroundWorker updateAccountBalance
validateUserSession writeAuditRecord dockerComposeService kubernetesDeployment postgresConnection
redisCacheClient webpackDevMiddleware eslintConfigPath typescriptProject getCustomerOrderById
fetchInvoiceDetails handlePaymentWebhook createCheckoutSession listRepositoryFiles readPackageManifest
writeCoverageReport computeFileChecksum normalizeRequestPath resolveModuleSpecifier formatErrorMessage
parseCommandArguments buildDependencyGraph collectTestResults publishReleaseNotes verifySignatureBlock
loadServiceAccount rotateSigningKey storeRefreshToken clearSessionCookie applySecurityPolicy
checkPermissionSet grantAccessToken revokeAccessToken renderDashboardView toggleFeatureFlag
enqueueBackgroundTask decompressResponseBody serializeJsonPayload deserializeJsonPayload
sendEmailNotification buildEmailTemplate applyOrderDiscount resizeImageAsset cacheQueryResult
invalidateQueryCache refreshQueryCache formatDisplayName parseDisplayName generateAccessKey
validateAccessKey bootstrapApplication shutdownApplication configureMiddleware registerMiddleware
handleRouteChange matchRoutePattern compileStyleSheet bundleStyleSheet installDependency
updateDependency measurePerformance recordPerformance traceRequestSpan exportRequestSpan
thisIsAVeryLongCamelCaseIdentifierName passwordStrength downstreamConsumer upstreamProducer
asynchronousTask synchronizationLock throughputLimiter javascriptBundle postgresqlClient
backgroundWorker nginxUpstreamHost kafkaConsumerGroup workloadIdentity stylesheetLoader
screenshotCapture oauthCallbackUrl websocketGateway openTelemetrySpan prometheusScrape
circuitBreakerPolicy rateLimiterConfig retryBackoffPolicy messageBrokerHost objectStorageKey
serviceAccountKey refreshTokenStore accessControlList persistentVolumeClaim storageClassName
ingressController certificateManager horizontalPodAutoscaler
`.trim().split(/\s+/);
  const masked = ['encodeURIComponent', 'decodeURIComponent'];

  it('keeps the corpus after a gap and redacts it after a resumed body line', () => {
    assert.ok(kept.length >= 78, String(kept.length));
    assert.equal(new Set(kept).size, kept.length);
    assert.ok(masked.length <= MAIN_MASKS);
    for (const name of kept) assert.ok(name.length >= 16, name);
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const name of kept) {
        const gap = redactSecretsInText(block(nl, [LINE64, '', name, 'Next']));
        const label = `${name} ${JSON.stringify(nl)}`;
        assert.equal(gap.includes(name), true, label);
        assert.equal(gap.includes(LINE64), false, label);
        assert.equal(gap.includes('Next'), true, label);
        const wide = redactSecretsInText(block(nl, [LINE64, '', LINE64, name, 'Next']));
        assert.equal(wide.includes(name), false, `wide ${label}`);
        assert.equal(wide.includes(LINE64), false, `wide ${label}`);
        assert.equal(wide.includes('Next'), true, `wide ${label}`);
      }
      for (const name of masked) {
        const gap = redactSecretsInText(block(nl, [LINE64, '', name, 'Next']));
        const label = `${name} ${JSON.stringify(nl)}`;
        assert.equal(gap.includes(name), false, label);
        assert.equal(gap.includes('Next'), true, label);
        assert.equal(gap.includes(LINE64), false, label);
      }
    }
  });

  it('seeded letters-only lines stay redacted on more than one seed', () => {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const seeds = [0x1060a11, 0x60b2, 0xabcdef];
    for (const seed of seeds) {
      const next = lcg(seed);
      let keptLines = 0;
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
        const out = redactSecretsInText(block('\n', [LINE64, '', line, 'Next']));
        if (out.includes(line)) keptLines += 1;
        assert.equal(out.includes(LINE64), false, line);
        assert.equal(out.includes('Next'), true, line);
      }
      const limit = seed === 0x1060a11 ? 0 : 4;
      assert.ok(keptLines <= limit, `seed ${seed.toString(16)} kept ${keptLines}`);
    }
  });
});

describe('v1.0.60 a mixed @@ hunk redacts the private key', () => {
  const oldLine = `${LINE64.slice(0, 62)}01`;
  const newLine = `${LINE64.slice(0, 62)}0x`;
  const ctx = [`${LINE64.slice(0, 62)}02`, `${LINE64.slice(0, 62)}03`, `${LINE64.slice(0, 62)}04`];
  const note = 'note: keep this visible';
  const ident = 'thisIsAVeryLongCamelCaseIdentifierName';
  const hunkLines = [
    'diff --git a/key.pem b/key.pem',
    '--- a/key.pem',
    '+++ b/key.pem',
    '@@ -1,5 +1,5 @@',
    ' -----BEGIN PRIVATE KEY-----',
    `-${oldLine}`,
    `+${newLine}`,
    ` ${ctx[0]}`,
    ` ${ctx[1]}`,
    ` ${ctx[2]}`,
    note,
    ident,
  ];

  function raw(nl) {
    return `${hunkLines.join(nl)}${nl}`;
  }

  function expected(nl) {
    const head = [
      'diff --git a/key.pem b/key.pem',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -1,5 +1,5 @@',
      ' -----BEGIN PRIVATE KEY-----',
    ].join(nl);
    return `${head}\n[REDACTED]\n-----END PRIVATE KEY-----${nl}${note}${nl}${ident}${nl}`;
  }

  for (const nl of ['\n', '\r\n']) {
    it(`redacts the mixed hunk exactly (${JSON.stringify(nl)})`, () => {
      const out = redactSecretsInText(raw(nl));
      assert.equal(out, expected(nl));
      for (const line of [oldLine, newLine, ...ctx]) {
        assert.equal(out.includes(line), false, line);
      }
      assert.equal(out.includes('--- a/key.pem'), true);
      assert.equal(out.includes('+++ b/key.pem'), true);
      assert.equal(out.includes('@@ -1,5 +1,5 @@'), true);
      assert.equal(out.includes(note), true);
      assert.equal(out.includes(ident), true);
    });
  }

  function bodyLine(i) {
    const tag = i.toString(36).padStart(3, '0');
    let line = `M${tag}/`;
    while (line.length < 64) line += ALPHABET[(i * 3 + line.length) % ALPHABET.length];
    return line;
  }

  function editedBody(line) {
    return `${line.slice(0, 63)}${line.charCodeAt(63) === 120 ? 'y' : 'x'}`;
  }

  function receiptAround(diff) {
    return [
      '# Receipt',
      '',
      '## Session',
      '',
      '- **Agent**: cursor',
      '',
      '## Diff summaries',
      '',
      '### `key.pem`',
      '',
      '```diff',
      diff,
      '```',
      '',
    ].join('\n');
  }

  it('seeded sweep leaves no hunk body line raw in redact, show, or share HTML', () => {
    const bodyCount = 24;
    const bodies = [];
    for (let i = 0; i < bodyCount; i += 1) bodies.push(bodyLine(i));
    assert.equal(new Set(bodies).size, bodyCount);
    const next = lcg(0x1060c3);
    let probes = 0;
    for (let n = 0; n < 256; n += 1) {
      const edit = next() % bodyCount;
      const endBody = edit + (next() % (bodyCount - edit));
      const prologue = next() % 3;
      const cut = next() % 3;
      const nl = n % 2 === 0 ? '\n' : '\r\n';
      const changed = editedBody(bodies[edit]);
      assert.notEqual(changed, bodies[edit]);
      const shown = [' -----BEGIN PRIVATE KEY-----'];
      for (let i = 0; i <= endBody; i += 1) {
        if (i === edit) {
          shown.push(`-${bodies[i]}`);
          shown.push(`+${changed}`);
        } else {
          shown.push(` ${bodies[i]}`);
        }
      }
      const drop = Math.min(cut, shown.length - 2);
      const visible = drop > 0 ? shown.slice(0, shown.length - drop) : shown;
      let oldCount = 0;
      let newCount = 0;
      for (const line of visible) {
        const mark = line.charCodeAt(0);
        if (mark === 43) newCount += 1;
        else if (mark === 45) oldCount += 1;
        else {
          oldCount += 1;
          newCount += 1;
        }
      }
      const start = prologue + 1;
      const header = n % 5 === 0
        ? `@@ -${start},${oldCount} +${start},${newCount} @@ key.pem`
        : `@@ -${start},${oldCount} +${start},${newCount} @@`;
      const trunc = drop > 0 ? `… (${drop} more lines truncated; use --full)` : '';
      const diffLines = [
        'diff --git a/key.pem b/key.pem',
        'index 1111111..2222222 100644',
        '--- a/key.pem',
        '+++ b/key.pem',
        header,
        ...visible,
      ];
      if (trunc) diffLines.push(trunc);
      diffLines.push(note, ident);
      const diff = `${diffLines.join(nl)}${nl}`;
      const secrets = [];
      for (const line of visible) {
        const content = line.slice(1);
        if (content.startsWith('-----')) continue;
        secrets.push(content);
      }
      assert.ok(secrets.length > 0);
      const receipt = receiptAround(diff);
      const redacted = redactSecretsInText(diff);
      const shownText = redactSecretsInText(receipt);
      const html = markdownToHtml(publishRedactedReceipt(receipt));
      const label = `edit ${edit} end ${endBody} start ${start} drop ${drop} ${JSON.stringify(nl)}`;
      for (const secret of secrets) {
        assert.equal(redacted.includes(secret), false, `redact ${label} ${secret.slice(0, 8)}`);
        assert.equal(shownText.includes(secret), false, `show ${label} ${secret.slice(0, 8)}`);
        assert.equal(html.includes(secret), false, `html ${label} ${secret.slice(0, 8)}`);
      }
      assert.equal(redacted.includes('[REDACTED]'), true, label);
      assert.equal(shownText.includes('[REDACTED]'), true, label);
      assert.equal(html.includes('[REDACTED]'), true, label);
      assert.equal(redacted.includes('--- a/key.pem'), true, label);
      assert.equal(redacted.includes('+++ b/key.pem'), true, label);
      assert.equal(redacted.includes(note), true, label);
      assert.equal(redacted.includes(ident), true, label);
      if (trunc) assert.equal(redacted.includes(trunc), true, label);
      probes += 1;
    }
    assert.equal(probes, 256);
  });

  it('show and share HTML redact a 26-line key after editing line 2', () => {
    const dir = gitRepo('ar1060-hunk-');
    const lines = ['-----BEGIN PRIVATE KEY-----'];
    for (let i = 0; i < 24; i += 1) lines.push(bodyLine(i));
    lines.push('-----END PRIVATE KEY-----');
    assert.equal(lines.length, 26);
    const changed = editedBody(lines[1]);
    writeFileSync(join(dir, 'key.pem'), `${lines.join('\n')}\n`);
    writeFileSync(join(dir, 'README.md'), '# qa\n');
    git(dir, ['add', 'key.pem', 'README.md']);
    git(dir, ['commit', '-m', 'add key']);
    const edited = lines.slice();
    edited[1] = changed;
    writeFileSync(join(dir, 'key.pem'), `${edited.join('\n')}\n`);
    const cap = cli(dir, ['capture', '--uncommitted', '--agent', 'cursor', '--message', 'edit line 2']);
    assert.equal(cap.code, 0, cap.err + cap.out);
    const storedPath = latestReceipt(dir);
    const stored = readFileSync(storedPath, 'utf8');
    assert.equal(stored.includes(lines[1]), true, 'stored receipt stays raw');
    const shown = cli(dir, ['show', storedPath]);
    assert.equal(shown.code, 0, shown.err + shown.out);
    const share = cli(dir, ['share', storedPath, '--out', 'shared.html']);
    assert.equal(share.code, 0, share.err + share.out);
    const html = readFileSync(join(dir, 'shared.html'), 'utf8');
    const secrets = [...lines.slice(1, -1), changed];
    for (const line of secrets) {
      assert.equal(shown.out.includes(line), false, `show leaked ${line.slice(-8)}`);
      assert.equal(html.includes(line), false, `html leaked ${line.slice(-8)}`);
    }
    assert.equal(shown.out.includes('[REDACTED]'), true);
    assert.equal(html.includes('[REDACTED]'), true);
    assert.equal(shown.out.includes('@@ -1,5 +1,5 @@'), true);
    assert.equal(html.includes('@@ -1,5 +1,5 @@'), true);
    assert.equal(shown.out.includes('--- a/key.pem'), true);
    assert.equal(shown.out.includes('+++ b/key.pem'), true);
  });
});

describe('v1.0.60 plus-leading key lines are not a diff by themselves', () => {
  const plusLong = `+${LINE64.slice(0, 63)}`;

  it('redacts one or two plus lines, including a 4, 8, or 12 character final', () => {
    const alone = `+${'A'.repeat(63)}`;
    const second = `+${'B'.repeat(63)}`;
    assert.equal(
      redactSecretsInText(`-----BEGIN PRIVATE KEY-----\n${alone}\n${second}\nNext\n`),
      `${PEM_REPLACEMENT}\nNext\n`,
    );
    for (const len of [4, 8, 12]) {
      const finalLine = '+AbCdEfGhIjK'.slice(0, len);
      assert.equal(finalLine.length, len);
      const raw = `-----BEGIN PRIVATE KEY-----\n${plusLong}\n${finalLine}\nNext\n`;
      const out = redactSecretsInText(raw);
      assert.equal(out, `${PEM_REPLACEMENT}\nNext\n`, finalLine);
      assert.equal(out.includes(plusLong), false, finalLine);
      assert.equal(out.includes(finalLine), false, finalLine);
      assert.equal(out.includes('Next'), true, finalLine);
    }
  });
});

describe('v1.0.60 digit-bearing names stay after a gap', () => {
  const kept = ['k8sNamespaceName', 'sha256DigestValue', 'base64UrlEncoded'];
  const masked = ['abcDe12fghijklmn', 'k8sNotARealNameXX'];

  it('keeps k8s, sha256, and base64 names only before a resumed body line', () => {
    for (const nl of ['\n', '\r\n', '\r']) {
      for (const name of kept) {
        const gap = redactSecretsInText(block(nl, [LINE64, '', name, 'Next']));
        const label = `${name} ${JSON.stringify(nl)}`;
        assert.equal(gap.includes(name), true, label);
        assert.equal(gap.includes(LINE64), false, label);
        assert.equal(gap.includes('Next'), true, label);
        const wide = redactSecretsInText(block(nl, [LINE64, '', LINE64, name, 'Next']));
        assert.equal(wide.includes(name), false, `wide ${label}`);
        assert.equal(wide.includes(LINE64), false, `wide ${label}`);
        assert.equal(wide.includes('Next'), true, `wide ${label}`);
      }
      for (const name of masked) {
        const gap = redactSecretsInText(block(nl, [LINE64, '', name, 'Next']));
        assert.equal(gap.includes(name), false, name);
        assert.equal(gap.includes('Next'), true, name);
      }
    }
    const prefixed = [
      '+-----BEGIN PRIVATE KEY-----',
      `+${LINE64}`,
      '+',
      '+k8sNamespaceName',
      '+Next',
    ].join('\n');
    const out = redactSecretsInText(prefixed);
    assert.equal(out.includes('+k8sNamespaceName'), true);
    assert.equal(out.includes(LINE64), false);
    assert.equal(out.includes('+Next'), true);
  });
});

describe('v1.0.60 a later @@ hunk with no BEGIN line redacts the private key', () => {
  const note = 'note: keep this visible';
  const ident = 'thisIsAVeryLongCamelCaseIdentifierName';

  function bodyLine(i) {
    const tag = i.toString(36).padStart(3, '0');
    let line = `M${tag}/`;
    while (line.length < 64) line += ALPHABET[(i * 3 + line.length) % ALPHABET.length];
    return line;
  }

  function editedBody(line) {
    return `${line.slice(0, 63)}${line.charCodeAt(63) === 120 ? 'y' : 'x'}`;
  }

  function hasLine(text, line) {
    return text.split(/\r?\n/).includes(line);
  }

  const shortKept = [' QUJD', ' abcdefgh', ' abcdefghijkl'];
  const shortMasked = [' YQ==', ' QUJDRA==', ' QUJDREVGR0g='];

  function midBody(nl) {
    const oldLine = bodyLine(0);
    const newLine = editedBody(oldLine);
    const ctx = [bodyLine(1), bodyLine(2), bodyLine(3)];
    const funcKey = bodyLine(8);
    const keptBody = bodyLine(9);
    const removedBody = bodyLine(10);
    const addedBody = editedBody(removedBody);
    const partial = bodyLine(4);
    const head = [
      'diff --git a/key.pem b/key.pem',
      'index 1111111..2222222 100644',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -1,5 +1,5 @@',
      ' -----BEGIN PRIVATE KEY-----',
      `-${oldLine}`,
      `+${newLine}`,
      ` ${ctx[0]}`,
      ` ${ctx[1]}`,
      ` ${ctx[2]}`,
    ];
    const second = [
      `@@ -12,11 +12,11 @@ ${funcKey}`,
      ` ${keptBody}`,
      `-${removedBody}`,
      `+${addedBody}`,
      ...shortMasked,
      ...shortKept,
      ` ${partial} trailing note`,
      ' Next',
      '+hello',
      '-removed ordinary line',
    ];
    const tail = [note, ident];
    const raw = `${[...head, ...second, ...tail].join(nl)}${nl}`;
    const expectedHead = [
      'diff --git a/key.pem b/key.pem',
      'index 1111111..2222222 100644',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -1,5 +1,5 @@',
      ' -----BEGIN PRIVATE KEY-----',
    ].join(nl);
    const expectedSecond = [
      '@@ -12,11 +12,11 @@ [REDACTED]',
      ' [REDACTED]',
      '-[REDACTED]',
      '+[REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
      ...shortKept,
      ' [REDACTED] trailing note',
      ' Next',
      '+hello',
      '-removed ordinary line',
      note,
      ident,
    ].join(nl);
    const expected = `${expectedHead}\n[REDACTED]\n-----END PRIVATE KEY-----${nl}${expectedSecond}${nl}`;
    const secrets = [oldLine, newLine, ...ctx, funcKey, keptBody, removedBody, addedBody, partial];
    return { raw, expected, secrets };
  }

  for (const nl of ['\n', '\r\n']) {
    it(`hunk-mid-body redacts exactly (${JSON.stringify(nl)})`, () => {
      const { raw, expected, secrets } = midBody(nl);
      const out = redactSecretsInText(raw);
      assert.equal(out, expected);
      for (const secret of secrets) {
        assert.equal(out.includes(secret), false, secret.slice(0, 12));
      }
      for (const line of shortMasked) {
        assert.equal(hasLine(out, line), false, line);
        assert.equal(hasLine(out, ` ${'[REDACTED]'}`), true, line);
      }
      for (const line of shortKept) assert.equal(hasLine(out, line), true, line);
      assert.equal(out.includes('--- a/key.pem'), true);
      assert.equal(out.includes('+++ b/key.pem'), true);
      assert.equal(out.includes('+hello'), true);
      assert.equal(out.includes('-removed ordinary line'), true);
      assert.equal(out.includes(note), true);
      assert.equal(out.includes(ident), true);
      assert.equal(out.includes('trailing note'), true);
    });
  }

  function endOnly(nl) {
    const funcKey = bodyLine(16);
    const keptBody = bodyLine(17);
    const removedBody = bodyLine(18);
    const addedBody = editedBody(removedBody);
    const afterEnd = bodyLine(19);
    const partial = bodyLine(20);
    const lines = [
      'diff --git a/key.pem b/key.pem',
      'index 1111111..2222222 100644',
      '--- a/key.pem',
      '+++ b/key.pem',
      `@@ -20,12 +20,12 @@ ${funcKey}`,
      ` ${keptBody}`,
      `-${removedBody}`,
      `+${addedBody}`,
      ' -----END PRIVATE KEY-----',
      ` ${afterEnd}`,
      ...shortMasked,
      ...shortKept,
      ` ${partial} trailing note`,
      ' Next',
      '+hello',
      '-removed ordinary line',
      note,
      ident,
    ];
    const raw = `${lines.join(nl)}${nl}`;
    const expectedLines = [
      'diff --git a/key.pem b/key.pem',
      'index 1111111..2222222 100644',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -20,12 +20,12 @@ [REDACTED]',
      ' [REDACTED]',
      '-[REDACTED]',
      '+[REDACTED]',
      ' -----END PRIVATE KEY-----',
      ' [REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
      ...shortKept,
      ' [REDACTED] trailing note',
      ' Next',
      '+hello',
      '-removed ordinary line',
      note,
      ident,
    ];
    const expected = `${expectedLines.join(nl)}${nl}`;
    const secrets = [funcKey, keptBody, removedBody, addedBody, afterEnd, partial];
    return { raw, expected, secrets };
  }

  for (const nl of ['\n', '\r\n']) {
    it(`hunk-with-END-no-BEGIN redacts exactly (${JSON.stringify(nl)})`, () => {
      const { raw, expected, secrets } = endOnly(nl);
      assert.equal(raw.includes('-----BEGIN '), false);
      const out = redactSecretsInText(raw);
      assert.equal(out, expected);
      for (const secret of secrets) {
        assert.equal(out.includes(secret), false, secret.slice(0, 12));
      }
      assert.equal(out.includes('-----END PRIVATE KEY-----'), true);
      assert.equal(out.includes('-----BEGIN '), false);
      for (const line of shortKept) assert.equal(hasLine(out, line), true, line);
      for (const line of shortMasked) assert.equal(hasLine(out, line), false, line);
      assert.equal(out.includes('--- a/key.pem'), true);
      assert.equal(out.includes('+++ b/key.pem'), true);
      assert.equal(out.includes('+hello'), true);
      assert.equal(out.includes('-removed ordinary line'), true);
      assert.equal(out.includes(note), true);
      assert.equal(out.includes(ident), true);
    });
  }

  it('a second file keeps its base64 line', () => {
    const secret = bodyLine(9);
    const funcKey = bodyLine(8);
    const other = `R${'A'.repeat(63)}`;
    assert.equal(other.length, 64);
    const raw = [
      'diff --git a/key.pem b/key.pem',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -1,2 +1,2 @@',
      ' -----BEGIN PRIVATE KEY-----',
      ` ${bodyLine(0)}`,
      `@@ -9,1 +9,1 @@ ${funcKey}`,
      ` ${secret}`,
      'diff --git a/readme.md b/readme.md',
      '--- a/readme.md',
      '+++ b/readme.md',
      '@@ -1 +1 @@',
      ` ${other}`,
      note,
      ident,
      '',
    ].join('\n');
    const expected = [
      'diff --git a/key.pem b/key.pem',
      '--- a/key.pem',
      '+++ b/key.pem',
      '@@ -1,2 +1,2 @@',
      ' -----BEGIN PRIVATE KEY-----',
      '[REDACTED]',
      '-----END PRIVATE KEY-----',
      '@@ -9,1 +9,1 @@ [REDACTED]',
      ' [REDACTED]',
      'diff --git a/readme.md b/readme.md',
      '--- a/readme.md',
      '+++ b/readme.md',
      '@@ -1 +1 @@',
      ` ${other}`,
      note,
      ident,
      '',
    ].join('\n');
    const out = redactSecretsInText(raw);
    assert.equal(out, expected);
    assert.equal(out.includes(secret), false);
    assert.equal(out.includes(funcKey), false);
    assert.equal(hasLine(out, ` ${other}`), true);
    assert.equal(out.includes(note), true);
    assert.equal(out.includes(ident), true);
  });

  function receiptAround(diff, withFinding, pathFindings) {
    const lines = [
      '# Receipt',
      '',
      '## Risk findings',
      '',
      '| Sev | Code | Detail |',
      '|-----|------|--------|',
    ];
    if (withFinding) {
      lines.push('| high | `private-key-block` | private key block appears in diff: key.pem |');
    }
    if (pathFindings) {
      lines.push('| high | `secret-looking-path` | Secret-looking path (key / cert material): key.pem |');
      lines.push('| high | `high-entropy-secret` | High-entropy token (5.80 bits/char, len 64): AAAAAAAAAAAA… in key.pem |');
    }
    lines.push(
      '',
      '## Diff summaries',
      '',
      '### `key.pem`',
      '',
      '```diff',
      diff.replace(/\r?\n$/, ''),
      '```',
      '',
      note,
      ident,
      '',
    );
    return lines.join('\n');
  }

  it('a private-key-block finding redacts a hunk that has neither marker', () => {
    const secret = bodyLine(11);
    const funcKey = bodyLine(10);
    const edited = editedBody(secret);
    const diff = [
      'diff --git a/key.pem b/key.pem',
      '--- a/key.pem',
      '+++ b/key.pem',
      `@@ -12,2 +12,2 @@ ${funcKey}`,
      ` ${secret}`,
      `-${secret}`,
      `+${edited}`,
      '',
    ].join('\n');
    assert.equal(diff.includes('PRIVATE KEY-----'), false);
    assert.equal(redactSecretsInText(diff).includes(secret), true);
    assert.equal(redactSecretsInText(diff).includes(funcKey), true);
    const viaPath = redactSecretsInText(diff, { keyPaths: ['key.pem'] });
    assert.equal(viaPath.includes(secret), false);
    assert.equal(viaPath.includes(edited), false);
    assert.equal(viaPath.includes(funcKey), false);
    assert.equal(viaPath.includes('@@ -12,2 +12,2 @@ [REDACTED]'), true);
    assert.equal(viaPath.includes('--- a/key.pem'), true);
    assert.equal(viaPath.includes('+++ b/key.pem'), true);
    const nested = redactSecretsInText(diff, { keyPaths: ['src/key.pem'] });
    assert.equal(nested.includes(secret), false, 'suffix path');
    const receipt = receiptAround(diff, true);
    const shown = redactSecretsInText(receipt);
    const html = markdownToHtml(publishRedactedReceipt(receipt));
    for (const secretLine of [secret, edited, funcKey]) {
      assert.equal(shown.includes(secretLine), false, `show ${secretLine.slice(0, 8)}`);
      assert.equal(html.includes(secretLine), false, `html ${secretLine.slice(0, 8)}`);
    }
    assert.equal(shown.includes('[REDACTED]'), true);
    assert.equal(html.includes('[REDACTED]'), true);
    assert.equal(shown.includes(note), true);
    assert.equal(shown.includes(ident), true);
    const unrelated = receiptAround(diff, false).replace('key.pem', 'notes.md');
    assert.equal(redactSecretsInText(unrelated).includes(secret), true);
  });

  function countPart(count) {
    return count === 1 ? '' : `,${count}`;
  }

  function hunkHeader(oldStart, oldCount, newStart, newCount, func) {
    const head = `@@ -${oldStart}${countPart(oldCount)} +${newStart}${countPart(newCount)} @@`;
    return func ? `${head} ${func}` : head;
  }

  function funcName(oldLines, from) {
    for (let i = from - 1; i >= 0; i -= 1) {
      const ch = oldLines[i].charCodeAt(0);
      const letter = (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122);
      if (letter || ch === 95 || ch === 36) return oldLines[i];
    }
    return '';
  }

  function renderHunks(oldLines, editSet, deleteSet, context) {
    const changes = [];
    for (let i = 0; i < oldLines.length; i += 1) {
      if (editSet.has(i) || deleteSet.has(i)) changes.push(i);
    }
    const groups = [];
    let start = changes[0];
    let end = changes[0];
    for (let k = 1; k < changes.length; k += 1) {
      const cur = changes[k];
      if (cur - end <= 2 * context) end = cur;
      else {
        groups.push([start, end]);
        start = cur;
        end = cur;
      }
    }
    groups.push([start, end]);
    const hunks = [];
    for (const [changeStart, changeEnd] of groups) {
      const from = Math.max(0, changeStart - context);
      const to = Math.min(oldLines.length - 1, changeEnd + context);
      let newStart = 1;
      for (let i = 0; i < from; i += 1) if (!deleteSet.has(i)) newStart += 1;
      let oldCount = 0;
      let newCount = 0;
      const payload = [];
      for (let i = from; i <= to; i += 1) {
        oldCount += 1;
        if (deleteSet.has(i)) {
          payload.push(`-${oldLines[i]}`);
          continue;
        }
        if (editSet.has(i)) {
          payload.push(`-${oldLines[i]}`);
          payload.push(`+${editedBody(oldLines[i])}`);
          newCount += 1;
          continue;
        }
        payload.push(` ${oldLines[i]}`);
        newCount += 1;
      }
      const func = funcName(oldLines, from);
      hunks.push({
        header: hunkHeader(from + 1, oldCount, newStart, newCount, func),
        payload,
        from,
        to,
      });
    }
    return hunks;
  }

  it('seeded sweep leaves no key body line raw across multi-hunk diffs', () => {
    const bodyCount = 24;
    const bodies = [];
    for (let i = 0; i < bodyCount; i += 1) bodies.push(bodyLine(i));
    assert.equal(new Set(bodies).size, bodyCount);
    const oldLines = ['-----BEGIN PRIVATE KEY-----', ...bodies, '-----END PRIVATE KEY-----'];
    assert.equal(oldLines.length, 26);
    const next = lcg(0x1060d4e);
    let probes = 0;
    let neitherHunks = 0;
    let endNoBeginHunks = 0;
    let endOnlyProbes = 0;
    let findingOnlyProbes = 0;
    let singleHunkProbes = 0;
    const surfaces = ['redact', 'show', 'show --json', 'html'];
    for (let n = 0; n < 192; n += 1) {
      const context = 1 + (next() % 3);
      const nl = n % 2 === 0 ? '\n' : '\r\n';
      const shape = n % 4;
      const editSet = new Set();
      const deleteSet = new Set();
      let withFinding = false;
      if (shape === 0) {
        editSet.add(1);
        let later = 8 + (next() % 10);
        if (later - 1 <= 2 * context) later = 2 + 2 * context + (next() % 4);
        if (later > 22) later = 22;
        editSet.add(later);
        if (next() % 2 === 0) {
          const del = Math.min(24, later + 2 * context + 1 + (next() % 3));
          if (!editSet.has(del)) deleteSet.add(del);
        }
      } else if (shape === 1) {
        editSet.add(24);
        if (next() % 2 === 0) deleteSet.add(22);
      } else if (shape === 2) {
        const mid = 8 + (next() % 8);
        editSet.add(mid);
        if (next() % 2 === 0) {
          const second = mid + 2 * context + 2;
          if (second <= 20) editSet.add(second);
        }
        withFinding = true;
      } else {
        const mid = 8 + (next() % 8);
        editSet.add(mid);
        withFinding = false;
      }
      const hunks = renderHunks(oldLines, editSet, deleteSet, context);
      assert.ok(hunks.length > 0);
      const diffLines = [
        'diff --git a/key.pem b/key.pem',
        'index 1111111..2222222 100644',
        '--- a/key.pem',
        '+++ b/key.pem',
      ];
      let sawBegin = false;
      let sawEnd = false;
      for (const hunk of hunks) {
        const blob = [hunk.header, ...hunk.payload].join('\n');
        const hasBegin = blob.includes('-----BEGIN ');
        const hasEnd = blob.includes('-----END ');
        if (hasBegin) sawBegin = true;
        if (hasEnd) sawEnd = true;
        if (!hasBegin && !hasEnd) neitherHunks += 1;
        if (hasEnd && !hasBegin) endNoBeginHunks += 1;
        diffLines.push(hunk.header, ...hunk.payload);
      }
      if (shape === 0) assert.equal(sawBegin, true, `shape 0 begin ${n}`);
      if (shape === 1) {
        assert.equal(sawBegin, false, `shape 1 begin ${n}`);
        assert.equal(sawEnd, true, `shape 1 end ${n}`);
        endOnlyProbes += 1;
      }
      if (shape === 2) {
        assert.equal(sawBegin, false, `shape 2 begin ${n}`);
        assert.equal(sawEnd, false, `shape 2 end ${n}`);
        findingOnlyProbes += 1;
      }
      if (shape === 3) {
        assert.equal(hunks.length, 1, `shape 3 hunks ${n}`);
        assert.equal(sawBegin, false, `shape 3 begin ${n}`);
        assert.equal(sawEnd, false, `shape 3 end ${n}`);
        singleHunkProbes += 1;
      }
      const other = `R${n.toString(36).padStart(3, '0')}${'A'.repeat(60)}`;
      assert.equal(other.length, 64);
      diffLines.push(
        'diff --git a/readme.md b/readme.md',
        '--- a/readme.md',
        '+++ b/readme.md',
        '@@ -1 +1 @@',
        ` ${other}`,
      );
      if (n % 4 === 0) {
        const keyAt = diffLines.indexOf('+++ b/key.pem');
        const insertAt = keyAt + 1 + 1;
        diffLines.splice(insertAt, 0, ...shortMasked, ...shortKept, ' Next');
      }
      diffLines.push(note, ident);
      const diff = `${diffLines.join(nl)}${nl}`;
      const secrets = [];
      for (const line of bodies) if (diff.includes(line)) secrets.push(line);
      for (const line of bodies) {
        const edited = editedBody(line);
        if (diff.includes(edited)) secrets.push(edited);
      }
      assert.ok(secrets.length > 0, `probe ${n}`);
      const pathFindings = shape === 3;
      const receipt = receiptAround(diff, withFinding || sawBegin || sawEnd, pathFindings);
      const redacted = pathFindings
        ? redactSecretsInText(receipt)
        : withFinding && !sawBegin && !sawEnd
          ? redactSecretsInText(diff, { keyPaths: ['key.pem'] })
          : redactSecretsInText(diff);
      if ((withFinding || pathFindings) && !sawBegin && !sawEnd) {
        assert.equal(redactSecretsInText(diff).includes(secrets[0]), true, `bare ${n}`);
      }
      const shown = redactSecretsInText(receipt);
      const shownJson = shown;
      const html = markdownToHtml(publishRedactedReceipt(receipt));
      const outputs = [redacted, shown, shownJson, html];
      const label = `n ${n} shape ${shape} ctx ${context} ${JSON.stringify(nl)}`;
      for (const secret of secrets) {
        for (let s = 0; s < outputs.length; s += 1) {
          assert.equal(outputs[s].includes(secret), false, `${surfaces[s]} ${label} ${secret.slice(0, 8)}`);
        }
      }
      for (const output of outputs) {
        assert.equal(output.includes('[REDACTED]'), true, label);
      }
      assert.equal(hasLine(redacted, ` ${other}`), true, label);
      assert.equal(shown.includes(other), true, label);
      assert.equal(html.includes(other), true, label);
      assert.equal(redacted.includes('--- a/key.pem'), true, label);
      assert.equal(redacted.includes('+++ b/key.pem'), true, label);
      assert.equal(redacted.includes(note), true, label);
      assert.equal(redacted.includes(ident), true, label);
      if (n % 4 === 0) {
        for (const line of shortMasked) assert.equal(hasLine(redacted, line), false, `${label} ${line}`);
        for (const line of shortKept) assert.equal(hasLine(redacted, line), true, `${label} ${line}`);
        assert.equal(hasLine(redacted, ' Next'), true, label);
      }
      probes += 1;
    }
    assert.equal(probes, 192);
    assert.ok(neitherHunks > 0, `neither ${neitherHunks}`);
    assert.ok(endNoBeginHunks > 0, `end-no-begin ${endNoBeginHunks}`);
    assert.ok(endOnlyProbes > 0, `end-only ${endOnlyProbes}`);
    assert.ok(findingOnlyProbes > 0, `finding-only ${findingOnlyProbes}`);
    assert.ok(singleHunkProbes > 0, `single-hunk ${singleHunkProbes}`);
  });

  it('show, show --json, and share HTML redact hunk-mid-body for LF and CRLF', () => {
    for (const nl of ['\n', '\r\n']) {
      const dir = gitRepo(`ar1060-mid-${nl === '\n' ? 'lf' : 'cr'}-`);
      git(dir, ['config', 'core.autocrlf', 'false']);
      git(dir, ['config', 'core.safecrlf', 'false']);
      const bodies = [];
      for (let i = 0; i < 24; i += 1) bodies.push(bodyLine(i));
      const lines = ['-----BEGIN PRIVATE KEY-----', ...bodies, '-----END PRIVATE KEY-----'];
      assert.equal(lines.length, 26);
      writeFileSync(join(dir, 'key.pem'), `${lines.join(nl)}${nl}`);
      git(dir, ['add', 'key.pem']);
      git(dir, ['commit', '-m', 'add key']);
      const changed2 = editedBody(lines[1]);
      const changed14 = editedBody(lines[13]);
      const edited = lines.slice();
      edited[1] = changed2;
      edited[13] = changed14;
      edited.splice(19, 1);
      assert.equal(edited.length, 25);
      writeFileSync(join(dir, 'key.pem'), `${edited.join(nl)}${nl}`);
      git(dir, ['add', 'key.pem']);
      git(dir, ['commit', '-m', 'edit lines 2 and 14, delete line 20']);
      const cap = cli(dir, ['capture', '--agent', 'cursor', '--message', 'mid-body hunk']);
      assert.equal(cap.code, 0, cap.err + cap.out);
      const storedPath = latestReceipt(dir);
      const stored = readFileSync(storedPath, 'utf8');
      assert.equal(stored.includes(lines[1]), true, 'stored receipt stays raw');
      assert.equal(stored.includes(bodies[8]), true, 'function context stays raw on disk');
      const shown = cli(dir, ['show', storedPath]);
      assert.equal(shown.code, 0, shown.err + shown.out);
      const shownJson = cli(dir, ['show', storedPath, '--json']);
      assert.equal(shownJson.code, 0, shownJson.err + shownJson.out);
      assert.equal(shownJson.out, shown.out);
      const share = cli(dir, ['share', storedPath, '--out', 'shared.html']);
      assert.equal(share.code, 0, share.err + share.out);
      const html = readFileSync(join(dir, 'shared.html'), 'utf8');
      const secrets = [...bodies, changed2, changed14];
      const label = JSON.stringify(nl);
      for (const line of secrets) {
        assert.equal(shown.out.includes(line), false, `show ${label} ${line.slice(0, 8)}`);
        assert.equal(shownJson.out.includes(line), false, `json ${label} ${line.slice(0, 8)}`);
        assert.equal(html.includes(line), false, `html ${label} ${line.slice(0, 8)}`);
      }
      const redactedHeader = '@@ -11,13 +11,12 @@ [REDACTED]';
      assert.equal(shown.out.includes(redactedHeader), true, label);
      assert.equal(shownJson.out.includes(redactedHeader), true, label);
      assert.equal(html.includes(redactedHeader), true, label);
      assert.equal(shown.out.includes('[REDACTED]'), true);
      assert.equal(html.includes('[REDACTED]'), true);
      assert.equal(shown.out.includes('--- a/key.pem'), true);
      assert.equal(shown.out.includes('+++ b/key.pem'), true);
      assert.equal(html.includes('--- a/key.pem'), true);
      assert.equal(html.includes('+++ b/key.pem'), true);
    }
  });

  function singleMidBody(nl) {
    const funcKey = bodyLine(7);
    const before = [bodyLine(8), bodyLine(9), bodyLine(10)];
    const oldLine = bodyLine(11);
    const newLine = editedBody(oldLine);
    const after = [bodyLine(12), bodyLine(13), bodyLine(14)];
    const payload = [
      ` ${before[0]}`,
      ` ${before[1]}`,
      ` ${before[2]}`,
      `-${oldLine}`,
      `+${newLine}`,
      ` ${after[0]}`,
      ` ${after[1]}`,
      ` ${after[2]}`,
    ];
    const diffLines = [
      'diff --git a/key.pem b/key.pem',
      'index 1111111..2222222 100644',
      '--- a/key.pem',
      '+++ b/key.pem',
      `@@ -10,7 +10,7 @@ ${funcKey}`,
      ...payload,
    ];
    const secrets = [funcKey, ...before, oldLine, newLine, ...after];
    const redactedPayload = [
      ' [REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
      '-[REDACTED]',
      '+[REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
      ' [REDACTED]',
    ];
    return { diffLines, secrets, redactedPayload, funcKey, oldLine, newLine };
  }

  for (const nl of ['\n', '\r\n']) {
    it(`single mid-body hunk with neither marker redacts exactly (${JSON.stringify(nl)})`, () => {
      const { diffLines, secrets, redactedPayload } = singleMidBody(nl);
      const finding = '| high | `secret-looking-path` | Secret-looking path (key / cert material): key.pem |';
      const rawLines = [finding, ...diffLines, note, ident];
      const raw = `${rawLines.join(nl)}${nl}`;
      assert.equal(raw.includes('-----BEGIN '), false);
      assert.equal(raw.includes('-----END '), false);
      assert.equal(diffLines.filter((line) => line.startsWith('@@')).length, 1);
      const bare = redactSecretsInText(diffLines.concat([note, ident]).join(nl) + nl);
      assert.equal(bare.includes(secrets[0]), true, 'bare diff stays raw');
      const expected = [
        finding,
        'diff --git a/key.pem b/key.pem',
        'index 1111111..2222222 100644',
        '--- a/key.pem',
        '+++ b/key.pem',
        '@@ -10,7 +10,7 @@ [REDACTED]',
        ...redactedPayload,
        note,
        ident,
      ].join(nl) + nl;
      const out = redactSecretsInText(raw);
      assert.equal(out, expected);
      for (const secret of secrets) {
        assert.equal(out.includes(secret), false, secret.slice(0, 12));
      }
      const entropy = '| high | `high-entropy-secret` | High-entropy token (5.80 bits/char, len 64): AAAAAAAAAAAA… in key.pem |';
      const entropyRaw = `${[entropy, ...diffLines, note, ident].join(nl)}${nl}`;
      const entropyExpected = expected.replace(finding, entropy.replace('AAAAAAAAAAAA…', '[REDACTED]…'));
      assert.equal(redactSecretsInText(entropyRaw), entropyExpected);
      const review = '1. **high** `secret-looking-path` — Secret-looking path (key / cert material): key.pem';
      const reviewOut = redactSecretsInText(`${[review, ...diffLines].join(nl)}${nl}`);
      assert.equal(reviewOut.includes('@@ -10,7 +10,7 @@ [REDACTED]'), true);
      assert.equal(reviewOut.includes(secrets[3]), false);
      const receipt = receiptAround(`${diffLines.join(nl)}${nl}`, false, false).replace(
        '|-----|------|--------|',
        `|-----|------|--------|\n${finding}`,
      );
      const shown = redactSecretsInText(receipt);
      const published = publishRedactedReceipt(receipt);
      const html = markdownToHtml(published);
      for (const secret of secrets) {
        assert.equal(shown.includes(secret), false, `show ${secret.slice(0, 8)}`);
        assert.equal(published.includes(secret), false, `share ${secret.slice(0, 8)}`);
        assert.equal(html.includes(secret), false, `html ${secret.slice(0, 8)}`);
      }
      const header = '@@ -10,7 +10,7 @@ [REDACTED]';
      assert.equal(shown.includes(header), true);
      assert.equal(published.includes(header), true);
      assert.equal(html.includes(header), true);
      assert.equal(shown.includes('--- a/key.pem'), true);
      assert.equal(shown.includes('+++ b/key.pem'), true);
    });
  }

  it('keeps ordinary @@ function context and Zm9v outside a secret file', () => {
    const handler = 'def handler(event):';
    const oldLine = bodyLine(0);
    const newLine = editedBody(oldLine);
    const later = bodyLine(12);
    const keySecret = bodyLine(11);
    const keyEdited = editedBody(keySecret);
    const keyFunc = bodyLine(10);
    for (const nl of ['\n', '\r\n']) {
      const labeled = JSON.stringify(nl);
      const withKey = [
        'diff --git a/app.py b/app.py',
        '--- a/app.py',
        '+++ b/app.py',
        `@@ -1,4 +1,4 @@ ${handler}`,
        ' -----BEGIN PRIVATE KEY-----',
        `-${oldLine}`,
        `+${newLine}`,
        ` ${bodyLine(1)}`,
        `@@ -30,3 +30,3 @@ ${handler}`,
        ' Zm9v',
        ' YQ==',
        ` ${later}`,
        note,
        ident,
      ].join(nl) + nl;
      const out = redactSecretsInText(withKey);
      assert.equal(out.includes(`@@ -1,4 +1,4 @@ ${handler}`), true, labeled);
      assert.equal(out.includes(`@@ -30,3 +30,3 @@ ${handler}`), true, labeled);
      assert.equal(out.includes('@@ -1,4 +1,4 @@ [REDACTED]'), false, labeled);
      assert.equal(out.includes('@@ -30,3 +30,3 @@ [REDACTED]'), false, labeled);
      assert.equal(out.includes(oldLine), false, labeled);
      assert.equal(out.includes(newLine), false, labeled);
      assert.equal(out.includes(bodyLine(1)), false, labeled);
      assert.equal(out.includes(later), false, labeled);
      assert.equal(hasLine(out, ' Zm9v'), true, labeled);
      assert.equal(hasLine(out, ' YQ=='), false, labeled);
      assert.equal(hasLine(out, ' [REDACTED]'), true, labeled);
      assert.equal(out.includes(note), true, labeled);
      assert.equal(out.includes(ident), true, labeled);

      const flaggedKey = [
        '| high | `secret-looking-path` | Secret-looking path (key / cert material): key.pem |',
        'diff --git a/key.pem b/key.pem',
        '--- a/key.pem',
        '+++ b/key.pem',
        `@@ -12,4 +12,4 @@ ${handler}`,
        ' Zm9v',
        ' YQ==',
        ` ${keySecret}`,
        `+${keyEdited}`,
        'diff --git a/app.py b/app.py',
        '--- a/app.py',
        '+++ b/app.py',
        `@@ -3,3 +3,3 @@ ${handler}`,
        ' Zm9v',
        ' YQ==',
        '+hello',
        note,
      ].join(nl) + nl;
      const flagged = redactSecretsInText(flaggedKey);
      assert.equal(flagged.includes(`@@ -12,4 +12,4 @@ ${handler}`), true, labeled);
      assert.equal(flagged.includes(`@@ -3,3 +3,3 @@ ${handler}`), true, labeled);
      assert.equal(flagged.includes('@@ -12,4 +12,4 @@ [REDACTED]'), false, labeled);
      assert.equal(flagged.includes(keySecret), false, labeled);
      assert.equal(flagged.includes(keyEdited), false, labeled);
      assert.equal(flagged.includes(keyFunc), false, labeled);
      const zm9v = flagged.split(/\r?\n/).filter((line) => line === ' Zm9v');
      assert.equal(zm9v.length, 1, labeled);
      assert.equal(flagged.includes('+hello'), true, labeled);
      assert.equal(flagged.includes(note), true, labeled);
    }

    const appDiff = [
      'diff --git a/app.py b/app.py',
      '--- a/app.py',
      '+++ b/app.py',
      `@@ -4,4 +4,4 @@ ${handler}`,
      ` ${bodyLine(4)}`,
      ' Zm9v',
      ' YQ==',
      '+hello',
      note,
      ident,
    ].join('\n') + '\n';
    const viaPath = redactSecretsInText(appDiff, { keyPaths: ['app.py'] });
    assert.equal(viaPath.includes(`@@ -4,4 +4,4 @@ ${handler}`), true);
    assert.equal(viaPath.includes(bodyLine(4)), false);
    assert.equal(hasLine(viaPath, ' Zm9v'), true);
    assert.equal(hasLine(viaPath, ' YQ=='), false);
    assert.equal(viaPath.includes('+hello'), true);
    assert.equal(viaPath.includes(note), true);
    assert.equal(viaPath.includes(ident), true);
    const entropyFinding = '| high | `high-entropy-secret` | High-entropy token (5.80 bits/char, len 64): AAAAAAAAAAAA… in app.py |';
    const entropyReceipt = [
      '# Receipt',
      '',
      '## Risk findings',
      '',
      '| Sev | Code | Detail |',
      '|-----|------|--------|',
      entropyFinding,
      '',
      '## Diff summaries',
      '',
      '### `app.py`',
      '',
      '```diff',
      appDiff.replace(/\n$/, ''),
      '```',
      '',
      note,
      ident,
      '',
    ].join('\n');
    const shown = redactSecretsInText(entropyReceipt);
    const published = publishRedactedReceipt(entropyReceipt);
    const html = markdownToHtml(published);
    for (const surface of [shown, published, html]) {
      assert.equal(surface.includes(handler), true);
      assert.equal(surface.includes('Zm9v'), true);
      assert.equal(surface.includes(bodyLine(4)), false);
      assert.equal(surface.includes('YQ=='), false);
      assert.equal(surface.includes(note), true);
      assert.equal(surface.includes(ident), true);
    }
  });

  it('a diff payload that only mentions a finding does not flag the file', () => {
    const secret = bodyLine(11);
    const raw = [
      'diff --git a/notes.md b/notes.md',
      '--- a/notes.md',
      '+++ b/notes.md',
      '@@ -1,2 +1,2 @@ def handler(event):',
      '+| high | `secret-looking-path` | Secret-looking path (key / cert material): notes.md |',
      ` ${secret}`,
      ' Zm9v',
      '',
    ].join('\n');
    const out = redactSecretsInText(raw);
    assert.equal(out.includes(secret), true);
    assert.equal(hasLine(out, ' Zm9v'), true);
    assert.equal(out.includes('@@ -1,2 +1,2 @@ def handler(event):'), true);
  });

  it('show, show --json, and share HTML redact one mid-body edit of body line 12', () => {
    for (const nl of ['\n', '\r\n']) {
      const dir = gitRepo(`ar1060-one-${nl === '\n' ? 'lf' : 'cr'}-`);
      git(dir, ['config', 'core.autocrlf', 'false']);
      git(dir, ['config', 'core.safecrlf', 'false']);
      const bodies = [];
      for (let i = 0; i < 24; i += 1) bodies.push(bodyLine(i));
      const lines = ['-----BEGIN PRIVATE KEY-----', ...bodies, '-----END PRIVATE KEY-----'];
      assert.equal(lines.length, 26);
      writeFileSync(join(dir, 'key.pem'), `${lines.join(nl)}${nl}`);
      git(dir, ['add', 'key.pem']);
      git(dir, ['commit', '-m', 'add key']);
      const editedLine = editedBody(lines[12]);
      const edited = lines.slice();
      edited[12] = editedLine;
      assert.equal(edited.length, 26);
      writeFileSync(join(dir, 'key.pem'), `${edited.join(nl)}${nl}`);
      git(dir, ['add', 'key.pem']);
      git(dir, ['commit', '-m', 'edit body line 12']);
      const cap = cli(dir, ['capture', '--agent', 'cursor', '--message', 'single mid-body hunk']);
      assert.equal(cap.code, 0, cap.err + cap.out);
      const storedPath = latestReceipt(dir);
      const stored = readFileSync(storedPath, 'utf8');
      assert.equal(stored.includes('secret-looking-path'), true);
      assert.equal(stored.includes('high-entropy-secret'), true);
      assert.equal(stored.includes('private-key-block'), false);
      assert.equal(stored.includes(lines[12]), true, 'stored receipt stays raw');
      assert.equal(stored.includes(lines[8]), true, 'function context stays raw on disk');
      const shown = cli(dir, ['show', storedPath]);
      assert.equal(shown.code, 0, shown.err + shown.out);
      const shownJson = cli(dir, ['show', storedPath, '--json']);
      assert.equal(shownJson.code, 0, shownJson.err + shownJson.out);
      assert.equal(shownJson.out, shown.out);
      const share = cli(dir, ['share', storedPath, '--out', 'shared.html']);
      assert.equal(share.code, 0, share.err + share.out);
      const html = readFileSync(join(dir, 'shared.html'), 'utf8');
      const secrets = [...bodies, editedLine];
      const label = JSON.stringify(nl);
      for (const line of secrets) {
        assert.equal(shown.out.includes(line), false, `show ${label} ${line.slice(0, 8)}`);
        assert.equal(shownJson.out.includes(line), false, `json ${label} ${line.slice(0, 8)}`);
        assert.equal(html.includes(line), false, `html ${label} ${line.slice(0, 8)}`);
      }
      const redactedHeader = '@@ -10,7 +10,7 @@ [REDACTED]';
      assert.equal(shown.out.includes(redactedHeader), true, label);
      assert.equal(shownJson.out.includes(redactedHeader), true, label);
      assert.equal(html.includes(redactedHeader), true, label);
      assert.equal(shown.out.includes('-----BEGIN '), false, label);
      assert.equal(shown.out.includes('-----END '), false, label);
      assert.equal(shown.out.includes('--- a/key.pem'), true, label);
      assert.equal(shown.out.includes('+++ b/key.pem'), true, label);
      assert.equal(html.includes('--- a/key.pem'), true, label);
      assert.equal(html.includes('+++ b/key.pem'), true, label);
    }
  });
});

describe('v1.0.60 changelog', () => {
  it('lists the Release QA follow-ups', () => {
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
    assert.match(entry, /getUserProfileById/);
    assert.match(entry, /encodeURIComponent/);
    assert.match(entry, /version was not bumped again/);
    assert.match(entry, /4, 8, 12, or 16/);
    assert.match(entry, /@@/);
    assert.match(entry, /k8sNamespaceName/);
    assert.match(entry, /sha256DigestValue/);
    assert.match(entry, /base64UrlEncoded/);
    assert.match(entry, /abcDe12fghijklmn/);
    assert.match(entry, /show --json/);
    assert.match(entry, /function context/);
    assert.match(entry, /no BEGIN/);
    assert.match(entry, /QUJD/);
    assert.match(entry, /0x1060a11/);
    assert.match(entry, /at most 4/);
    assert.match(entry, /private-key-block/);
    assert.match(entry, /def handler\(event\)/);
    assert.match(entry, /Zm9v/);
    assert.match(entry, /secret-looking-path/);
    assert.match(entry, /high-entropy-secret/);
    assert.match(entry, /pack-check/);
    assert.match(entry, /npm pack --dry-run --json/);
    assert.match(entry, /base64-like/);
    assert.match(entry, /body line 12/);
    assert.match(entry, /neither marker/);
  });
});
