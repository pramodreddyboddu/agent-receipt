import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, resolve, sep } from 'node:path';
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
  const cfg = loadConfig(cwd);
  const dir = join(cwd, cfg.outDir);
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
  return new Error(
    `Receipt not found: ${p}\nRun \`agent-receipt last\` to see the newest receipt, or \`capture\` first.`,
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

/**
 * Project directory that holds receipts when this cwd is not a git checkout.
 * The nearest parent with `.agent-receipt` or `.agent-receipt.yml`.
 */
function receiptsRoot(cwd: string): string | null {
  let dir = resolve(cwd);
  for (;;) {
    if (existsSync(join(dir, '.agent-receipt')) || existsSync(join(dir, '.agent-receipt.yml'))) {
      return dir;
    }
    const parent = resolve(dir, '..');
    if (parent === dir) return null;
    dir = parent;
  }
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
    // that string is not under cwd. Git toplevel first; receipts root only
    // when this directory is not a git checkout.
    const top = gitToplevel(cwd);
    const base = top ?? receiptsRoot(cwd);
    const resolved = base ? pathInside(base, pathArg) : null;
    if (resolved) return resolved;
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
