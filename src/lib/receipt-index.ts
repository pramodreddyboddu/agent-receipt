import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
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

/** Prepend a new capture into `.agent-receipt/index.json` (newest first). */
export function updateIndexOnCapture(cwd: string, meta: IndexCaptureMeta): string {
  const absOut = resolve(cwd, meta.outPath);
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

/** Resolve configured receipts dir absolute path (for rebuild helpers). */
export function receiptsDir(cwd: string): string {
  const cfg = loadConfig(cwd);
  return cfg.outDir.startsWith('/') ? cfg.outDir : join(cwd, cfg.outDir);
}
