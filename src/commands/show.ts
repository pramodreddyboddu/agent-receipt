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

/**
 * True when `.agent-receipt` holds only `audit.jsonl` and there is no
 * `.agent-receipt.yml`. `share` from a subdirectory used to create that
 * directory, and the next lookup then treated it as the receipts root.
 */
function isAuditOnlyAgentReceipt(dir: string): boolean {
  if (existsSync(join(dir, '.agent-receipt.yml'))) return false;
  const marker = join(dir, '.agent-receipt');
  if (!existsSync(marker)) return false;
  let names: string[];
  try {
    names = readdirSync(marker);
  } catch {
    return false;
  }
  return names.length === 1 && names[0] === 'audit.jsonl';
}

/**
 * Project directory that holds receipts. The nearest directory at or above
 * `start` with `.agent-receipt` or `.agent-receipt.yml`. A directory whose
 * `.agent-receipt` contains only `audit.jsonl` is not a root.
 */
export function findReceiptsRoot(start: string): string | null {
  let dir = resolve(start);
  for (;;) {
    const yml = existsSync(join(dir, '.agent-receipt.yml'));
    const marker = existsSync(join(dir, '.agent-receipt'));
    if ((yml || marker) && !isAuditOnlyAgentReceipt(dir)) return dir;
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
    const base = top ?? findReceiptsRoot(cwd);
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
