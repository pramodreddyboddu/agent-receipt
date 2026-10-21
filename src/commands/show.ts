import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { loadConfig } from '../lib/config.js';
import { runGit } from '../lib/git.js';
import { extractEmbeddedHash } from '../lib/hash.js';
import { redactSecretsInText } from '../lib/redact.js';
import {
  isInsideSessionPackage,
  isInsideSharePackage,
  isProveOnePagerName,
  isSessionPackageDirName,
} from '../lib/receipt.js';

export function findLatestReceipt(cwd: string): string | null {
  const store = resolveStoreRoot(cwd);
  const cfg = loadConfig(store);
  const dir = join(store, cfg.outDir);
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir)
    .filter((f) => !isSessionPackageDirName(f))
    .filter((f) => f.endsWith('.md') && !isProveOnePagerName(f))
    .map((f) => join(dir, f))
    .filter((p) => !isInsideSharePackage(p) && !isInsideSessionPackage(p))
    .filter((p) => {
      try {
        return statSync(p).isFile();
      } catch {
        return false;
      }
    })
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  return files[0] ?? null;
}

function notFound(p: string): Error {
  // Display only. The lookup still used the raw path.
  const shown = redactSecretsInText(p);
  return new Error(
    `Receipt not found: ${shown}\nRun \`agent-receipt last\` to see the newest receipt, or \`capture\` first.`,
  );
}

/** Absolute path of `pathArg` under `base`, or null when it leaves `base` or is missing. */
function pathInside(base: string, pathArg: string): string | null {
  if (!base || isAbsolute(pathArg)) return null;
  const root = resolve(base);
  const abs = resolve(root, pathArg);
  if (abs !== root && !abs.startsWith(root + sep)) return null;
  return existsSync(abs) ? abs : null;
}

function gitToplevel(cwd: string): string | null {
  try {
    const top = runGit(['rev-parse', '--show-toplevel'], cwd);
    return top || null;
  } catch {
    return null;
  }
}

function containsPath(base: string, file: string): boolean {
  const root = resolve(base);
  const abs = resolve(file);
  return abs === root || abs.startsWith(root + sep);
}

/**
 * True when `dir` holds receipt data. A receipt markdown file under the
 * configured outDir counts. So does `.agent-receipt/index.json` when its
 * `receipts` array is non-empty. An audit log, keys, a config file, an
 * empty receipts directory, or an extra file beside `audit.jsonl` do not.
 */
export function hasReceiptData(dir: string): boolean {
  const root = resolve(dir);
  let outDir = '.agent-receipt/receipts';
  try {
    const configured = loadConfig(root).outDir.trim();
    if (configured) outDir = configured;
  } catch {
    /* unreadable config is not receipt data */
  }
  const receipts = isAbsolute(outDir) ? outDir : join(root, outDir);
  let names: string[] = [];
  try {
    names = readdirSync(receipts);
  } catch {
    names = [];
  }
  for (const name of names) {
    if (!name.endsWith('.md') || isProveOnePagerName(name)) continue;
    if (isSessionPackageDirName(name)) continue;
    const file = join(receipts, name);
    if (isInsideSharePackage(file) || isInsideSessionPackage(file)) continue;
    try {
      if (statSync(file).isFile()) return true;
    } catch {
      /* skip an unreadable entry */
    }
  }
  const indexFile = join(root, '.agent-receipt', 'index.json');
  try {
    const raw = JSON.parse(readFileSync(indexFile, 'utf8')) as { receipts?: unknown };
    if (Array.isArray(raw.receipts) && raw.receipts.length > 0) return true;
  } catch {
    /* missing or unreadable index is not receipt data */
  }
  return false;
}

/**
 * Nearest directory at or above `start` that holds receipt data.
 * Null when none does.
 */
export function findReceiptsRoot(start: string): string | null {
  let dir = resolve(start);
  for (;;) {
    if (hasReceiptData(dir)) return dir;
    const parent = resolve(dir, '..');
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * Store directory for readers. The receipts root when this directory is
 * inside one, otherwise `cwd` itself. Calling it again returns the same path.
 */
export function resolveStoreRoot(cwd: string): string {
  return findReceiptsRoot(cwd) ?? resolve(cwd);
}

/**
 * Directory `relativePath` is computed against. Git toplevel first.
 * With no toplevel, the nearest receipts root at or above `cwd` that
 * contains `filePath`. When none does (share started above the project),
 * the receipts root of the file.
 */
export function receiptsRootFor(cwd: string, filePath: string): string {
  const top = gitToplevel(cwd);
  if (top) return top;
  const file = resolve(filePath);
  let dir = resolve(cwd);
  for (;;) {
    if (hasReceiptData(dir) && containsPath(dir, file)) return dir;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  return findReceiptsRoot(dirname(filePath)) ?? resolve(cwd);
}

export function resolveReceiptPath(cwd: string, pathArg?: string): string {
  if (pathArg) {
    if (isAbsolute(pathArg) || pathArg.startsWith('/')) {
      if (!existsSync(pathArg)) throw notFound(pathArg);
      return pathArg;
    }
    const atCwd = join(cwd, pathArg);
    if (existsSync(atCwd)) return atCwd;
    // share --json relativePath is repo-root relative. From a subdirectory
    // that string is not under cwd. Git toplevel first. With no toplevel,
    // walk every receipts root above cwd until one contains the path.
    // A nearer root that does not hold the file is not the end of the walk.
    const top = gitToplevel(cwd);
    if (top) {
      const resolved = pathInside(top, pathArg);
      if (resolved) return resolved;
      throw notFound(atCwd);
    }
    let dir = resolve(cwd);
    for (;;) {
      if (hasReceiptData(dir)) {
        const resolved = pathInside(dir, pathArg);
        if (resolved) return resolved;
      }
      const parent = resolve(dir, '..');
      if (parent === dir) break;
      dir = parent;
    }
    throw notFound(atCwd);
  }
  const latest = findLatestReceipt(cwd);
  if (!latest) {
    throw new Error(
      'No receipt found under the configured outDir.\n' +
        'Run `agent-receipt capture` first, or pass an explicit path.',
    );
  }
  return latest;
}

export function cmdShow(cwd: string, pathArg?: string): void {
  const path = resolveReceiptPath(cwd, pathArg);
  const text = readFileSync(path, 'utf8');
  const hash = extractEmbeddedHash(text);

  // Display only. The file on disk stays as captured so verify still matches.
  console.log(`── ${redactSecretsInText(path)} ──`);
  if (hash) console.log(`integrity: sha256:${hash.slice(0, 16)}…`);
  console.log('');
  console.log(redactSecretsInText(text));
}
