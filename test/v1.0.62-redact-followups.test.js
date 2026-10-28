/**
 * v1.0.62 — v1.0.61 Release QA follow-ups.
 * Code-word humps stay visible. Random humps that only contain those
 * words stay masked. A glued path does not leave the next secret line raw.
 * The 3000-sample keep-rate line is whatever the corpus script prints.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { humpWordAt } from '../dist/lib/hump-words.js';
import { redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LINE64 = ALPHABET.slice(0, 64);
const PATHS = [
  '/src/app.ts',
  '/src/components/Button.tsx',
  './src/app.ts',
  'src/App.tsx',
  'app/src/index.ts',
  '/src/lib/redact.ts',
];

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state;
  };
}

function block(lines) {
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n`;
}

function keptAfterGap(name) {
  const gap = redactSecretsInText(block([LINE64, '', name, 'Next']));
  return gap.includes(name) && !gap.includes(LINE64) && gap.includes('Next');
}

const CODE_WORDS = [
  'reducer', 'widget', 'logger', 'init', 'selector', 'params', 'descriptor',
  'executable', 'enum', 'cfg', 'ctx', 'req', 'res', 'msg', 'btn', 'idx', 'len',
  'str', 'num', 'src', 'dst', 'tmp', 'util', 'impl', 'auth', 'env', 'repo', 'pkg',
];

describe('v1.0.62 code-word humps stay and random humps stay masked', () => {
  const kept = [
    'initLoggerReducer',
    'widgetSelectorParams',
    'loadCfgCtxReqRes',
    'authEnvRepoPkgImpl',
    'msgBtnIdxLenStrNum',
    'srcDstTmpUtilImpl',
    'descriptorExecutable',
    'enumLoggerReducer',
    'CorrectHorseBatteryStaple',
  ];

  it('keeps identifiers built from the code words after a gap', () => {
    for (const word of CODE_WORDS) {
      assert.equal(humpWordAt(word, 0, word.length), true, word);
      const titled = word[0].toUpperCase() + word.slice(1);
      assert.equal(humpWordAt(titled, 0, titled.length), true, titled);
    }
    for (const name of kept) {
      assert.ok(name.length >= 16, name);
      assert.equal(keptAfterGap(name), true, name);
      const wide = redactSecretsInText(block([LINE64, '', LINE64, name, 'Next']));
      assert.equal(wide.includes(name), false, `wide ${name}`);
      assert.equal(wide.includes(LINE64), false, `wide ${name}`);
      assert.equal(wide.includes('Next'), true, `wide ${name}`);
    }
  });

  it('masks a random line that only borrows those humps', () => {
    const masked = [
      'xqzCfgWqrtReducer',
      'plqvWidgetMntxLogger',
      'bqxInitNrvDescriptor',
      'mntExecutableQxvEnum',
      'aaCfgZzBtnQqIdxYy',
      'qvLenZzStrQqNumYy',
      'xqzSrcDstTmpUtil',
      'plqvAuthEnvRepoPkg',
    ];
    for (const name of masked) {
      assert.ok(name.length >= 16, name);
      const gap = redactSecretsInText(block([LINE64, '', name, 'Next']));
      assert.equal(gap.includes(name), false, name);
      assert.equal(gap.includes(LINE64), false, name);
      assert.equal(gap.includes('Next'), true, name);
    }
  });
});

describe('v1.0.62 a glued path does not leak the next secret', () => {
  function leaks(line) {
    const secret = 'S'.repeat(64);
    const out = redactSecretsInText(
      `-----BEGIN PRIVATE KEY-----\n${'B'.repeat(64)}\n${line}\n${secret}\nNext\n`,
    );
    assert.equal(out.includes('B'.repeat(64)), false, line);
    assert.equal(out.includes('Next'), true, line);
    return out.includes(secret);
  }

  it('leaks none of 900 seeded glued paths', () => {
    const next = lcg(0x1062);
    let found = 0;
    for (let n = 0; n < 900; n += 1) {
      const len = 24 + (next() % 17);
      let prefix = '';
      for (let i = 0; i < len; i += 1) prefix += ALPHABET[next() % 64];
      const line = prefix + PATHS[next() % PATHS.length];
      if (leaks(line)) found += 1;
    }
    assert.equal(found, 0, `leaks ${found} of 900`);
  });

  it('leaks none of 200 letters-only prefixes glued to a path', () => {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    const next = lcg(0x1062b17);
    let found = 0;
    for (let n = 0; n < 200; n += 1) {
      const len = 16 + (next() % 9);
      let prefix = '';
      for (let i = 0; i < len; i += 1) prefix += letters[next() % 26];
      const line = prefix + PATHS[next() % PATHS.length];
      if (leaks(line)) found += 1;
    }
    assert.equal(found, 0, `letter leaks ${found} of 200`);
  });

  it('still stops on a real path and keeps the following line', () => {
    const stops = [
      '/src/app.ts',
      '/src/components/Button.tsx',
      './src/app.ts',
      'src/App.tsx',
      'app/src/index.ts',
      '/src/lib/redact.ts',
      '/src/handleClickEvent.ts',
      'src/main/java/com/example/service/UserService.java',
      'app/Http/Controllers/Admin/UserController.php',
      '/src/my-app/index.js',
      '/api/v1/app.ts',
      '/src/i18n/en.ts',
      '/src/implementations/index.ts',
      'hello world',
      'note: done',
    ];
    const tail = 'E'.repeat(64);
    for (const stop of stops) {
      const out = redactSecretsInText(block(['B'.repeat(64), stop, tail, 'Next']));
      assert.equal(out.includes(stop), true, stop);
      assert.equal(out.includes(tail), true, stop);
      assert.equal(out.includes('Next'), true, stop);
      assert.equal(out.includes('B'.repeat(64)), false, stop);
    }
  });
});

describe('v1.0.62 reproducible corpus and wording', () => {
  it('prints the keep-rate line the changelog quotes', () => {
    const ran = spawnSync(process.execPath, ['scripts/print-corpus-keep-rate.mjs'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(ran.status, 0, ran.stderr);
    const line = ran.stdout.split('\n').find((row) => /^masked \d+ of 3000$/.test(row));
    assert.ok(line, ran.stdout);
    const note = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    const entry61 = note.slice(note.indexOf('## [1.0.61]'), note.indexOf('## [1.0.60]'));
    const entry62 = note.slice(note.indexOf('## [1.0.62]'), note.indexOf('## [1.0.61]'));
    assert.match(entry61, /73 of 78 identifiers stay/);
    assert.equal(entry61.includes('773 of 3000'), false);
    assert.equal(entry61.includes('246 of 3000'), false);
    assert.equal(entry61.includes('about 69%'), false);
    assert.match(entry62, /73 of 78 identifiers stay/);
    assert.match(entry62, /v1\.0\.61 Release QA follow-ups/);
    assert.ok(entry62.includes(line), `${line} missing from changelog`);
    assert.match(entry62, /1\.0\.62/);
    assert.match(entry62, /npm publish, which is on hold/);
    assert.match(entry62, /does not publish to npm/);
    assert.match(entry62, /not a certificate authority/);
  });

  it('states that the hump list is self-authored and not the frequency lists', () => {
    const src = readFileSync(join(root, 'src', 'lib', 'hump-words.ts'), 'utf8');
    assert.match(src, /self-authored/);
    assert.match(src, /not shipped/);
    assert.equal(src.includes('inflateSync'), false);
    assert.equal(src.includes('PACKED_HUMP_WORDS'), false);
    const gap = ['accrual', 'amortized', 'foreclosure', 'tranche', 'fiduciary'];
    for (const word of gap) assert.equal(humpWordAt(word, 0, word.length), false, word);
  });
});
