#!/usr/bin/env node
/**
 * Runs `npm pack --dry-run --json` and asserts the tarball includes bin + dist.
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

const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
  cwd: root,
  encoding: 'utf8',
  shell: false,
});

const out = `${result.stdout || ''}${result.stderr || ''}`;
if (result.status !== 0) {
  console.error('npm pack --dry-run --json failed:\n' + out);
  process.exit(result.status ?? 1);
}

let packed;
try {
  packed = JSON.parse(result.stdout || '');
} catch {
  console.error('pack:check failed — npm pack --dry-run --json did not print JSON on stdout');
  console.error(out);
  process.exit(1);
}
const entry = Array.isArray(packed) ? packed[0] : packed;
const files = Array.isArray(entry && entry.files)
  ? entry.files.map((file) => (typeof file === 'string' ? file : file && file.path) || '')
  : [];

const missing = [];
if (!files.includes('bin/agent-receipt.js')) missing.push('bin/agent-receipt.js');
if (!files.includes('dist/index.js')) missing.push('dist/index.js');
for (const pack of ['baseline.yml', 'supply-chain.yml', 'ci-protect.yml', 'strict.yml']) {
  const needle = `policies/${pack}`;
  if (!files.includes(needle)) missing.push(needle);
}

if (missing.length) {
  console.error('pack:check failed — tarball missing required paths:');
  for (const m of missing) console.error('  - ' + m);
  console.error('\nnpm pack --dry-run --json output:\n' + out);
  process.exit(1);
}

const errLines = `${result.stderr || ''}`.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
// Flag publish-time auto-correct noise if dry-run surfaces it
const publishWarn = errLines.filter((l) => /warn publish.*bin/i.test(l) || /bin\[.+\]".*invalid|cleaned/i.test(l));
if (publishWarn.length) {
  console.error('pack:check failed — npm would auto-correct/remove bin metadata:');
  for (const w of publishWarn) console.error('  ' + w);
  process.exit(1);
}

console.log('pack:check OK — bin + dist present; bin path has no leading "./"');
const filename = entry && typeof entry.filename === 'string' ? entry.filename : '';
if (filename) console.log(filename);
console.log(`${files.length} paths in npm pack --dry-run --json`);
process.exit(0);
