/**
 * Print the v1.0.62 identifier keep-rate line.
 *
 * Regenerate:
 *   node scripts/print-corpus-keep-rate.mjs
 *
 * The vocabulary is test/fixtures/v1.0.62/identifier-fragments.txt.
 * Seed 0x1062c15. Same LCG as the redact sweeps:
 *   state = (Math.imul(1664525, state) + 1013904223) >>> 0
 * Build 3000 camelCase names of length 16 to 48 with 2 to 7 parts.
 * A name is masked when it does not stay after a truncated PEM and a gap.
 * Gap words in the fixture must not be hump-dictionary words.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { humpWordAt } from '../dist/lib/hump-words.js';
import { redactSecretsInText } from '../dist/lib/redact.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = join(root, 'test', 'fixtures', 'v1.0.62', 'identifier-fragments.txt');
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LINE64 = ALPHABET.slice(0, 64);

function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state;
  };
}

function load(text) {
  const dictionary = [];
  const gap = [];
  let section = '';
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#')) {
      if (line === '# dictionary') section = 'dictionary';
      else if (line === '# gap') section = 'gap';
      continue;
    }
    if (section === 'dictionary') dictionary.push(line);
    else if (section === 'gap') gap.push(line);
  }
  return { dictionary, gap };
}

const { dictionary, gap } = load(readFileSync(fixture, 'utf8'));
if (dictionary.length < 8 || gap.length < 8) {
  throw new Error('fixture is missing dictionary or gap words');
}
for (const word of gap) {
  if (humpWordAt(word, 0, word.length)) {
    throw new Error(`gap word is in the hump dictionary: ${word}`);
  }
}
for (const word of dictionary) {
  if (!humpWordAt(word, 0, word.length)) {
    throw new Error(`dictionary word is missing from the hump list: ${word}`);
  }
}

const vocab = dictionary.concat(gap);
const camel = (parts) => parts.map((word, i) => (i ? word[0].toUpperCase() + word.slice(1) : word)).join('');
const next = lcg(0x1062c15);
const names = new Set();
let guard = 0;
while (names.size < 3000 && guard < 3000 * 80) {
  guard += 1;
  const parts = [];
  let line = '';
  while (line.length < 16 && parts.length < 7) {
    parts.push(vocab[next() % vocab.length]);
    line = camel(parts);
  }
  if (line.length >= 16 && line.length <= 48 && parts.length >= 2) names.add(line);
}
if (names.size !== 3000) throw new Error(`built ${names.size} names`);

let masked = 0;
for (const name of names) {
  const raw = `-----BEGIN PRIVATE KEY-----\n${LINE64}\n\n${name}\nNext\n`;
  const out = redactSecretsInText(raw);
  const kept = out.includes(name) && !out.includes(LINE64) && out.includes('Next');
  if (!kept) masked += 1;
}

console.log('fixture test/fixtures/v1.0.62/identifier-fragments.txt');
console.log('seed 0x1062c15');
console.log('samples 3000');
console.log(`masked ${masked} of 3000`);
