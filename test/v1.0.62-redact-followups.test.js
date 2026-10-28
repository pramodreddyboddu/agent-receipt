/**
 * v1.0.62 — v1.0.61 Release QA follow-ups.
 * A hump stays only when it is an ENABLE dictionary word or a light stem
 * of one. A code word is not a hump on its own. Random humps stay masked.
 * A glued path does not leave the next secret line raw on the seeded
 * sweeps. A fresh draw can still leak when `/` splits the prefix. The
 * gap-word 3000-sample line is circular. The real-identifier line is
 * whatever the corpus script prints from node_modules.
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

const DICTIONARY_HUMPS = [
  'reducer', 'widget', 'logger', 'selector', 'descriptor', 'executable', 'repo',
];
const NOT_HUMPS = [
  'init', 'params', 'enum', 'cfg', 'ctx', 'req', 'btn', 'idx', 'len', 'str',
  'num', 'dst', 'tmp', 'impl', 'env',
];

describe('v1.0.62 dictionary humps stay and code words do not', () => {
  const kept = [
    'loggerReducerSelector',
    'widgetSelectorDescriptor',
    'executableLoggerReducer',
    'CorrectHorseBatteryStaple',
  ];
  const maskedNames = [
    'initLoggerReducer',
    'widgetSelectorParams',
    'loadCfgCtxReqRes',
  ];

  it('keeps a name only when every hump is a dictionary word', () => {
    for (const word of DICTIONARY_HUMPS) {
      assert.equal(humpWordAt(word, 0, word.length), true, word);
      const titled = word[0].toUpperCase() + word.slice(1);
      assert.equal(humpWordAt(titled, 0, titled.length), true, titled);
    }
    for (const word of NOT_HUMPS) {
      assert.equal(humpWordAt(word, 0, word.length), false, word);
    }
    assert.equal(humpWordAt('batteries', 0, 'batteries'.length), true);
    assert.equal(humpWordAt('tax', 0, 3), true);
    for (const name of kept) {
      assert.ok(name.length >= 16, name);
      assert.equal(keptAfterGap(name), true, name);
      const wide = redactSecretsInText(block([LINE64, '', LINE64, name, 'Next']));
      assert.equal(wide.includes(name), false, `wide ${name}`);
      assert.equal(wide.includes(LINE64), false, `wide ${name}`);
      assert.equal(wide.includes('Next'), true, `wide ${name}`);
    }
    for (const name of maskedNames) {
      assert.equal(keptAfterGap(name), false, name);
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

  it('leaks 56 of 2000 fresh draws when a slash splits the prefix', () => {
    // mulberry32, not the sweep LCG. The LCG's low bits almost never
    // place `/` so every segment is shorter than 16 and free of `+`/`=`.
    function mulberry32(seed) {
      let a = seed >>> 0;
      return () => {
        a |= 0;
        a = (a + 0x6D2B79F5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return (t ^ (t >>> 14)) >>> 0;
      };
    }
    const next = mulberry32(0xC0FFEE);
    let found = 0;
    for (let n = 0; n < 2000; n += 1) {
      const len = 24 + (next() % 17);
      let prefix = '';
      for (let i = 0; i < len; i += 1) prefix += ALPHABET[next() % 64];
      const line = prefix + PATHS[next() % PATHS.length];
      if (leaks(line)) found += 1;
    }
    assert.equal(found, 56, `fresh leaks ${found} of 2000`);
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

describe('v1.0.62 pronounceable and code-word keep rates', () => {
  // mulberry32, seed 7, restarted for each length. Humps are 3 to 6
  // letters, consonant then vowel. 400 draws. Every hump has to be a
  // dictionary word, so this family keeps 0 of 400 at 20 to 24
  // characters. The previous tip kept 5, 5, 2, 3, and 4 of 400, and
  // before that 74 to 114 of 400. Code-word endings at 16 and 19 stay
  // at 0 of 400. The tip before the code-word check kept 128 to 134.

  const CODE = [
    'reducer', 'widget', 'logger', 'init', 'selector', 'params', 'descriptor',
    'executable', 'enum', 'cfg', 'ctx', 'req', 'res', 'btn', 'idx', 'len',
    'str', 'num', 'src', 'dst', 'tmp', 'util', 'impl', 'auth', 'env', 'repo', 'pkg',
  ];
  const V = 'aeiou';
  const C = 'bcdfghjklmnprstvwz';

  function mulberry32(seed) {
    let s = seed;
    return () => {
      s |= 0;
      s = (s + 0x6D2B79F5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function keptCount(length, endCode) {
    const rnd = mulberry32(7);
    const pick = (list) => list[Math.floor(rnd() * list.length)];
    const cap = (word) => word[0].toUpperCase() + word.slice(1);
    const syl = (n) => {
      let hump = '';
      for (let i = 0; i < n; i += 1) hump += i % 2 ? pick(V) : pick(C);
      return hump;
    };
    const rhump = () => cap(syl(3 + Math.floor(rnd() * 4)));
    const build = (gen) => {
      for (let k = 0; k < 8000; k += 1) {
        const name = gen();
        if (name.length === length) return name;
      }
      throw new Error(`no name of length ${length}`);
    };
    let kept = 0;
    for (let i = 0; i < 400; i += 1) {
      const name = endCode
        ? build(() => {
          let text = rhump();
          text = text[0].toLowerCase() + text.slice(1);
          while (text.length < length - 3) text += rhump();
          return text + cap(pick(CODE));
        })
        : build(() => {
          let text = rhump();
          text = text[0].toLowerCase() + text.slice(1);
          while (text.length < length) text += rhump();
          return text;
        });
      if (keptAfterGap(name)) kept += 1;
    }
    return kept;
  }

  it('keeps few pronounceable humps of 20 to 24 characters', () => {
    const kept = [20, 21, 22, 23, 24].map((length) => keptCount(length, false));
    assert.deepEqual(kept, [0, 0, 0, 0, 0]);
    for (const count of kept) assert.ok(count <= 12, String(count));
  });

  it('masks random humps that end in a code word at 16 to 19 characters', () => {
    for (const length of [16, 17, 18, 19]) {
      assert.equal(keptCount(length, true), 0, String(length));
    }
    for (const name of ['TosiliWibuSelector', 'NugiRawigExecutable']) {
      assert.equal(keptAfterGap(name), false, name);
    }
  });
});

describe('v1.0.62 every hump is a dictionary word', () => {
  // Same syllable generator as the Release QA family: consonant, vowel,
  // mulberry32. Seeds 7, 11, and 13, 400 draws each, so each cell is
  // 1200 names. Lengths 16, 19, 20, 21, and 24. c671acc kept 4 of 1200
  // dictionary-tail names at length 16 and 0 at the other lengths.
  const DICT = ['Value', 'Name', 'Data', 'Token', 'Config', 'Result', 'Handler', 'Count', 'Index', 'State'];
  const V = 'aeiou';
  const C = 'bcdfghjklmnprstvwz';
  const LENGTHS = [16, 19, 20, 21, 24];
  const SEEDS = [7, 11, 13];

  function mulberry32(seed) {
    let s = seed;
    return () => {
      s |= 0;
      s = (s + 0x6D2B79F5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function keptAt(lo, hi, useTail) {
    const totals = Object.fromEntries(LENGTHS.map((length) => [length, 0]));
    for (const seed of SEEDS) {
      const rnd = mulberry32(seed);
      const pick = (list) => list[Math.floor(rnd() * list.length)];
      const cap = (word) => word[0].toUpperCase() + word.slice(1);
      const lc = (word) => word[0].toLowerCase() + word.slice(1);
      const syl = (n) => {
        let hump = '';
        for (let i = 0; i < n; i += 1) hump += i % 2 ? pick(V) : pick(C);
        return hump;
      };
      const hump = () => cap(syl(lo + Math.floor(rnd() * (hi - lo + 1))));
      const build = (length, end) => {
        for (let k = 0; k < 20000; k += 1) {
          let text = lc(hump());
          const target = length - end.length;
          while (text.length < target) text += hump();
          text += end;
          if (text.length === length) return text;
        }
        throw new Error(`no name of length ${length}`);
      };
      for (const length of LENGTHS) {
        for (let i = 0; i < 400; i += 1) {
          const end = useTail ? pick(DICT) : '';
          if (keptAfterGap(build(length, end))) totals[length] += 1;
        }
      }
    }
    return LENGTHS.map((length) => totals[length]);
  }

  it('keeps few random humps that end in one dictionary word at 16 to 24 characters', () => {
    const kept = keptAt(3, 6, true);
    assert.deepEqual(kept, [0, 0, 0, 0, 0]);
    assert.equal(keptAfterGap('TosiliWibuHandler'), false);
    assert.equal(keptAfterGap('KoramiDataConfigName'), false);
  });

  it('keeps few pronounceable humps of 7 to 10 letters', () => {
    assert.deepEqual(keptAt(7, 10, false), [0, 0, 0, 0, 0]);
  });

  it('keeps few mixed humps of 4 to 8 letters', () => {
    assert.deepEqual(keptAt(4, 8, false), [0, 0, 0, 0, 0]);
  });
});

describe('v1.0.62 reproducible corpus and wording', () => {
  it('prints the keep-rate line the changelog quotes', () => {
    const ran = spawnSync(process.execPath, ['scripts/print-corpus-keep-rate.mjs'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(ran.status, 0, ran.stderr);
    assert.match(ran.stdout, /kind circular-gap-words/);
    assert.match(ran.stdout, /kind node_modules-dts-camelCase/);
    const line = ran.stdout.split('\n').find((row) => /^masked \d+ of 3000$/.test(row));
    const real = ran.stdout.split('\n').find((row) => /^real-masked \d+ of 3000$/.test(row));
    const frozen = ran.stdout.split('\n').find((row) => /^frozen-masked \d+ of 3000$/.test(row));
    assert.ok(line, ran.stdout);
    assert.ok(real, ran.stdout);
    assert.ok(frozen, ran.stdout);
    assert.equal(line, 'masked 2083 of 3000');
    assert.equal(real, 'real-masked 690 of 3000');
    assert.equal(frozen, 'frozen-masked 736 of 3000');
    const note = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
    const entry61 = note.slice(note.indexOf('## [1.0.61]'), note.indexOf('## [1.0.60]'));
    const entry62 = note.slice(note.indexOf('## [1.0.62]'), note.indexOf('## [1.0.61]'));
    assert.match(entry61, /73 of 78 identifiers stay/);
    assert.match(entry61, /773 of 3000/);
    assert.match(entry61, /246 of 3000/);
    assert.match(entry61, /CorrectHorseBatteryStaple/);
    assert.match(entry61, /16 to 24/);
    assert.match(entry61, /about 69%/);
    assert.match(entry61, /same as main/);
    assert.equal(entry61.includes('The 78 identifiers stay'), false);
    assert.match(entry62, /73 of 78 identifiers stay/);
    assert.match(entry62, /v1\.0\.61 Release QA follow-ups/);
    assert.match(entry62, /circular/);
    assert.match(entry62, /not a real-identifier over-mask rate/);
    assert.ok(entry62.includes(line), `${line} missing from changelog`);
    assert.ok(entry62.includes(real), `${real} missing from changelog`);
    assert.ok(entry62.includes(frozen), `${frozen} missing from changelog`);
    assert.match(entry62, /773 of 3000 is what v1\.0\.61 masks on Release QA's rq74b real\.txt corpus/);
    assert.match(entry62, /not a sample of node_modules type declarations/);
    assert.match(entry62, /frozen-masked 736 of 3000/);
    assert.match(entry62, /598 of 1876/);
    assert.match(entry62, /655 of 3000/);
    assert.match(entry62, /c671acc masked 621/);
    assert.match(entry62, /32a1260 tip masked 1783 of 1876/);
    assert.match(entry62, /2560 of 6000/);
    assert.match(entry62, /111 of 5000/);
    assert.match(entry62, /randPronStartCode` keeps 1 of 6000/);
    assert.match(entry62, /c671acc kept 0 of 6000/);
    assert.match(entry62, /10,603/);
    assert.match(entry62, /public domain/);
    assert.match(entry62, /Pramod's sign-off at merge/);
    assert.equal(entry62.includes('551 vs 901'), false);
    assert.equal(entry62.includes('above 773 of 3000'), false);
    assert.equal(entry62.includes('at or below the v1.0.61 rate of 773 of 3000'), false);
    assert.equal(entry62.includes('tuned to'), false);
    assert.equal(entry62.includes('self-authored'), false);
    const frozenFile = readFileSync(join(root, 'test', 'fixtures', 'v1.0.62', 'real-identifiers.txt'), 'utf8');
    const frozenHeader = frozenFile.split('\n').slice(0, 12).join('\n');
    assert.match(frozenHeader, /rq74b real\.txt/);
    assert.match(frozenHeader, /not type declarations/);
    assert.equal(frozenHeader.includes('taken from installed type'), false);
    assert.equal(frozenHeader.includes('stays at or below'), false);
    const rule = readFileSync(join(root, 'src', 'lib', 'redact.ts'), 'utf8');
    assert.equal(rule.includes('past 773'), false);
    assert.equal(rule.includes('tuned to'), false);
    const script = readFileSync(join(root, 'scripts', 'print-corpus-keep-rate.mjs'), 'utf8');
    assert.equal(script.includes('551 vs 901'), false);
    assert.match(script, /That walk is not a v1\.0\.61 comparison/);
    assert.match(entry62, /That walk is not a v1\.0\.61 comparison/);
    assert.match(entry62, /depends on the lockfile/);
    assert.match(entry62, /CorrectHorseBatteryStaple/);
    assert.match(entry62, /56 of 2000/);
    assert.match(entry62, /about 3%/);
    assert.match(entry62, /leaks 0/);
    assert.match(entry62, /1\.0\.62/);
    assert.match(entry62, /npm publish, which is on hold/);
    assert.match(entry62, /does not publish to npm/);
    assert.match(entry62, /not a certificate authority/);
  });

  it('states the ENABLE provenance and does not ship the frequency lists', () => {
    const src = readFileSync(join(root, 'src', 'lib', 'hump-words.ts'), 'utf8');
    const note = readFileSync(join(root, 'docs', 'hump-words.md'), 'utf8');
    assert.match(src, /ENABLE1, public domain/);
    assert.match(src, /not shipped/);
    assert.match(note, /public domain/);
    assert.match(note, /10,603/);
    assert.match(note, /not a rank picked by scoring the rq74b/);
    assert.match(note, /7,611/);
    assert.match(note, /Pramod's sign-off at merge/);
    assert.match(note, /CC-BY-SA-4\.0/);
    assert.equal(src.includes('inflateSync'), false);
    assert.equal(src.includes('PACKED_HUMP_WORDS'), false);
    assert.equal(src.includes('self-authored'), false);
    const gap = ['accrual', 'amortized', 'foreclosure', 'tranche', 'fiduciary', 'quixotic'];
    for (const word of gap) assert.equal(humpWordAt(word, 0, word.length), false, word);
  });
});
