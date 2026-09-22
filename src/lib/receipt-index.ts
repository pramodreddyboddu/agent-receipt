import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { loadConfig } from './config.js';
import { summarizeRisks, type RiskHint, type RiskSummary } from './risk.js';
import { sha256Hex, canonicalBody } from './hash.js';

export const INDEX_REL = '.agent-receipt/index.json';

export interface ReceiptIndexEntry {
  /** Path relative to repo root (posix-ish). */
  path: string;
  timestamp: string;
  agent?: string | null;
  message?: string | null;
  head?: string | null;
  branch?: string | null;
  uncommitted?: boolean;
  files: number;
  insertions: number;
  deletions: number;
  risk: RiskSummary;
  sha256?: string | null;
}

export interface ReceiptIndex {
  version: 1;
  updatedAt: string;
  receipts: ReceiptIndexEntry[];
}

export function indexPath(cwd: string): string {
  return join(cwd, INDEX_REL);
}

export function loadIndex(cwd: string): ReceiptIndex {
  const p = indexPath(cwd);
  if (!existsSync(p)) {
    return { version: 1, updatedAt: new Date(0).toISOString(), receipts: [] };
  }
  try {
    const raw = JSON.parse(readFileSync(p, 'utf8')) as Partial<ReceiptIndex>;
    return {
      version: 1,
      updatedAt: String(raw.updatedAt ?? new Date(0).toISOString()),
      receipts: Array.isArray(raw.receipts) ? (raw.receipts as ReceiptIndexEntry[]) : [],
    };
  } catch {
    return { version: 1, updatedAt: new Date(0).toISOString(), receipts: [] };
  }
}

export function writeIndex(cwd: string, index: ReceiptIndex): string {
  const p = indexPath(cwd);
  mkdirSync(dirname(p), { recursive: true });
  const body = JSON.stringify(index, null, 2) + '\n';
  writeFileSync(p, body, 'utf8');
  return p;
}

/**
 * Read index.json. Missing file → empty index.
 * Invalid JSON or a non-object body throws so prune can refuse to delete.
 */
export function readIndexStrict(cwd: string): { index: ReceiptIndex; existed: boolean } {
  const p = indexPath(cwd);
  if (!existsSync(p)) {
    return {
      index: { version: 1, updatedAt: new Date(0).toISOString(), receipts: [] },
      existed: false,
    };
  }
  let raw: string;
  try {
    raw = readFileSync(p, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read index (${p}): ${msg} — prune refused to delete receipts`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`index.json is not valid JSON (${p}) — prune refused to delete receipts`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`index.json is not an object (${p}) — prune refused to delete receipts`);
  }
  const obj = parsed as Partial<ReceiptIndex>;
  if (obj.receipts !== undefined && !Array.isArray(obj.receipts)) {
    throw new Error(
      `index.json receipts is not an array (${p}) — prune refused to delete receipts`,
    );
  }
  return {
    existed: true,
    index: {
      version: 1,
      updatedAt: String(obj.updatedAt ?? new Date(0).toISOString()),
      receipts: Array.isArray(obj.receipts) ? (obj.receipts as ReceiptIndexEntry[]) : [],
    },
  };
}

/** Write index.json via temp file + rename so a crash cannot truncate the catalog. */
export function writeIndexAtomic(cwd: string, index: ReceiptIndex): string {
  const p = indexPath(cwd);
  mkdirSync(dirname(p), { recursive: true });
  const body = JSON.stringify({ ...index, version: 1 as const }, null, 2) + '\n';
  const tmp = `${p}.tmp-${process.pid}`;
  writeFileSync(tmp, body, 'utf8');
  try {
    renameSync(tmp, p);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* leave the temp file if unlink also fails */
    }
    throw err;
  }
  return p;
}

export interface IndexCaptureMeta {
  outPath: string;
  timestamp: string;
  agent?: string;
  message?: string;
  head: string;
  branch: string;
  uncommitted?: boolean;
  files: number;
  insertions: number;
  deletions: number;
  risks: RiskHint[];
  markdown: string;
}

/** Resolve configured receipts dir absolute path (for rebuild helpers). */
export function receiptsDir(cwd: string): string {
  const cfg = loadConfig(cwd);
  return cfg.outDir.startsWith('/') ? cfg.outDir : join(cwd, cfg.outDir);
}

/** True when absPath resolves inside the configured outDir. */
export function isInsideOutDir(cwd: string, absPath: string): boolean {
  const dir = resolve(receiptsDir(cwd));
  const abs = resolve(absPath);
  const rel = relative(dir, abs);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Prepend a new capture into `.agent-receipt/index.json` (newest first).
 * Captures written outside configured outDir (e.g. `--out ./share.md`) are
 * skipped so they do not become history/`newest` ahead of outDir receipts.
 * Returns the index path, or null when skipped.
 */
export function updateIndexOnCapture(
  cwd: string,
  meta: IndexCaptureMeta,
): string | null {
  const absOut = resolve(cwd, meta.outPath);
  if (!isInsideOutDir(cwd, absOut)) {
    return null;
  }

  let rel = relative(cwd, absOut).replace(/\\/g, '/');
  if (rel.startsWith('../') || rel === '..') {
    // Outside repo — keep basename under a synthetic key
    rel = absOut;
  }

  const entry: ReceiptIndexEntry = {
    path: rel,
    timestamp: meta.timestamp,
    agent: meta.agent ?? null,
    message: meta.message ?? null,
    head: meta.head,
    branch: meta.branch,
    uncommitted: Boolean(meta.uncommitted),
    files: meta.files,
    insertions: meta.insertions,
    deletions: meta.deletions,
    risk: summarizeRisks(meta.risks),
    sha256: sha256Hex(canonicalBody(meta.markdown)),
  };

  const idx = loadIndex(cwd);
  // Drop prior entry with same path (re-capture / overwrite)
  idx.receipts = idx.receipts.filter((r) => r.path !== entry.path);
  idx.receipts.unshift(entry);
  // Cap index size so it stays useful
  if (idx.receipts.length > 500) idx.receipts = idx.receipts.slice(0, 500);
  idx.updatedAt = new Date().toISOString();
  idx.version = 1;
  return writeIndex(cwd, idx);
}
