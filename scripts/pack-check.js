#!/usr/bin/env node
/**
 * Runs `npm pack --dry-run` and asserts the tarball includes bin + dist.
 * Exit 0 on success; non-zero with a clear message on failure.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const result = spawnSync('npm', ['pack', '--dry-run'], {
  cwd: root,
  encoding: 'utf8',
  shell: false,
});

const out = `${result.stdout || ''}${result.stderr || ''}`;
if (result.status !== 0) {
  console.error('npm pack --dry-run failed:\n' + out);
  process.exit(result.status ?? 1);
}

const lines = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
// npm prints "npm notice" lines listing package contents
const hasBin =
  lines.some((l) => /bin\/agent-receipt\.js/.test(l)) ||
  lines.some((l) => /\bbin\b/.test(l) && /agent-receipt/.test(l));
const hasDist =
  lines.some((l) => /dist\/index\.js/.test(l)) ||
  lines.some((l) => /dist\//.test(l));

const missing = [];
if (!hasBin) missing.push('bin/agent-receipt.js (or bin/)');
if (!hasDist) missing.push('dist/ (e.g. dist/index.js)');

if (missing.length) {
  console.error('pack:check failed — tarball missing required paths:');
  for (const m of missing) console.error('  - ' + m);
  console.error('\nnpm pack --dry-run output:\n' + out);
  process.exit(1);
}

console.log('pack:check OK — bin + dist present in dry-run tarball');
// Echo a short summary of top-level entries for humans
const notices = lines.filter((l) => /npm notice/.test(l) || /^agent-receipt-/.test(l));
if (notices.length) {
  console.log(notices.slice(0, 40).join('\n'));
  if (notices.length > 40) console.log(`… (${notices.length - 40} more lines)`);
}
process.exit(0);
