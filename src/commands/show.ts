import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig } from '../lib/config.js';
import { extractEmbeddedHash } from '../lib/hash.js';

function findLatestReceipt(cwd: string): string | null {
  const cfg = loadConfig(cwd);
  const dir = join(cwd, cfg.outDir);
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => join(dir, f))
    .filter((p) => statSync(p).isFile())
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  return files[0] ?? null;
}

export function resolveReceiptPath(cwd: string, pathArg?: string): string {
  if (pathArg) {
    const p = pathArg.startsWith('/') ? pathArg : join(cwd, pathArg);
    if (!existsSync(p)) throw new Error(`Receipt not found: ${p}`);
    return p;
  }
  const latest = findLatestReceipt(cwd);
  if (!latest) {
    throw new Error(
      'No receipt found. Pass a path or run `agent-receipt capture` first.',
    );
  }
  return latest;
}

export function cmdShow(cwd: string, pathArg?: string): void {
  const path = resolveReceiptPath(cwd, pathArg);
  const text = readFileSync(path, 'utf8');
  const hash = extractEmbeddedHash(text);

  console.log(`── ${path} ──`);
  if (hash) console.log(`integrity: sha256:${hash.slice(0, 16)}…`);
  console.log('');
  console.log(text);
}
