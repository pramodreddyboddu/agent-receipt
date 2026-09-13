#!/usr/bin/env node
/**
 * Runs `npm pack --dry-run` and asserts the tarball includes bin + dist.
 * Also guards against the npm 11 bin-path footgun: a leading `./` on bin
 * targets is treated as invalid at publish time and can strip the CLI.
 * Exit 0 on success; non-zero with a clear message on failure.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const binMap =
  typeof pkg.bin === 'string'
    ? { [pkg.name.split('/').pop()]: pkg.bin }
    : pkg.bin && typeof pkg.bin === 'object'
      ? pkg.bin
      : {};

const badBinPaths = [];
for (const [name, target] of Object.entries(binMap)) {
  if (typeof target !== 'string' || target.startsWith('./') || target.startsWith('.\\')) {
    badBinPaths.push(`${name} -> ${JSON.stringify(target)}`);
  }
}
if (!binMap['agent-receipt']) {
  console.error('pack:check failed — package.json bin missing "agent-receipt"');
  process.exit(1);
}
if (badBinPaths.length) {
  console.error(
    'pack:check failed — bin paths must be relative without a leading "./" (npm 11 publish strips ./ and may drop the bin):',
  );
  for (const b of badBinPaths) console.error('  - ' + b);
  console.error('Use e.g. "bin/agent-receipt.js" not "./bin/agent-receipt.js".');
  process.exit(1);
}

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

// Flag publish-time auto-correct noise if dry-run surfaces it
const publishWarn = lines.filter((l) => /warn publish.*bin/i.test(l) || /bin\[.+\]".*invalid|cleaned/i.test(l));
if (publishWarn.length) {
  console.error('pack:check failed — npm would auto-correct/remove bin metadata:');
  for (const w of publishWarn) console.error('  ' + w);
  process.exit(1);
}

console.log('pack:check OK — bin + dist present; bin path has no leading "./"');
const notices = lines.filter((l) => /npm notice/.test(l) || /^agent-receipt-/.test(l) || /pramodreddyboddu-agent-receipt-/.test(l));
if (notices.length) {
  console.log(notices.slice(0, 40).join('\n'));
  if (notices.length > 40) console.log(`… (${notices.length - 40} more lines)`);
}
process.exit(0);
