/**
 * Print the v1.0.62 corpus lines.
 *
 * Regenerate:
 *   node scripts/print-corpus-keep-rate.mjs
 *
 * The first count is circular. The vocabulary is
 * test/fixtures/v1.0.62/identifier-fragments.txt. Seed 0x1062c15.
 * Same LCG as the redact sweeps:
 *   state = (Math.imul(1664525, state) + 1013904223) >>> 0
 * It builds 3000 camelCase names of length 16 to 48 with 2 to 7 parts
 * from hump-list words plus gap words. A gap word is defined as a word
 * that is not in the hump list, so this count is not a real-identifier
 * over-mask rate.
 *
 * The second count is not built from that list. It takes camelCase
 * identifiers from node_modules type declarations, length 16 to 48,
 * sorts them, and keeps the first 3000. That walk depends on the
 * lockfile and the installed node_modules. 551 vs 901 is v1.0.61 on
 * the same sample: 901 is what v1.0.61 prints for this walk, and 551
 * is what the previous tip of this branch printed for it. 773 of 3000
 * is what v1.0.61 masks on Release QA's rq74b real.txt corpus, not on
 * this walk.
 *
 * The third count is the frozen file
 * test/fixtures/v1.0.62/real-identifiers.txt. Those 3000 names are
 * Release QA's rq74b real.txt corpus, length 16 to 24. They are not
 * type declarations. The harness is two PEM body lines, a gap, the
 * name, then "~ ctx". v1.0.61 masks 773 of those 3000.
 * A name is masked when it does not stay after a truncated PEM and a gap.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
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
console.log('kind circular-gap-words');
console.log(`masked ${masked} of 3000`);

function walkDts(dir, acc) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    const path = join(dir, name);
    let st;
    try {
      st = statSync(path);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (name === 'node_modules' && dir !== root) continue;
      walkDts(path, acc);
    } else if (name.endsWith('.d.ts')) acc.push(path);
  }
}

const declFiles = [];
walkDts(join(root, 'node_modules'), declFiles);
const identRe = /\b[A-Za-z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+\b/g;
const realNames = new Set();
for (const file of declFiles) {
  const text = readFileSync(file, 'utf8');
  for (const match of text.matchAll(identRe)) {
    const name = match[0];
    if (name.length >= 16 && name.length <= 48) realNames.add(name);
  }
}
const realSample = [...realNames].sort().slice(0, 3000);
if (realSample.length !== 3000) throw new Error(`built ${realSample.length} real identifiers`);
let realMasked = 0;
for (const name of realSample) {
  const raw = `-----BEGIN PRIVATE KEY-----\n${LINE64}\n\n${name}\nNext\n`;
  const out = redactSecretsInText(raw);
  const kept = out.includes(name) && !out.includes(LINE64) && out.includes('Next');
  if (!kept) realMasked += 1;
}
console.log('kind node_modules-dts-camelCase');
console.log(`real-masked ${realMasked} of 3000`);

const frozenPath = join(root, 'test', 'fixtures', 'v1.0.62', 'real-identifiers.txt');
const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7aZ9+/QxWv3LmP';
const frozen = readFileSync(frozenPath, 'utf8').split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
if (frozen.length !== 3000) throw new Error(`built ${frozen.length} frozen identifiers`);
let frozenMasked = 0;
for (const name of frozen) {
  const raw = `-----BEGIN PRIVATE KEY-----\n${body}\n${body}\n\n${name}\n~ ctx\n`;
  const out = redactSecretsInText(raw);
  if (!out.includes(name)) frozenMasked += 1;
}
console.log('kind frozen-real-identifiers');
console.log(`frozen-masked ${frozenMasked} of 3000`);
