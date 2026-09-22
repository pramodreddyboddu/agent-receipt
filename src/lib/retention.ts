/**
 * Opt-in retention for receipts under outDir.
 *
 * Nothing is deleted unless `maxCount` and/or `maxAgeDays` is set
 * (config or CLI) and `prune` is run without `--dry-run`. Capture,
 * wrap, and watch do not prune.
 */
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  unlinkSync,
} from 'node:fs';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import type { AgentReceiptConfig } from './config.js';
import {
  indexPath,
  isInsideOutDir,
  readIndexStrict,
  receiptsDir,
  writeIndexAtomic,
  type ReceiptIndex,
  type ReceiptIndexEntry,
} from './receipt-index.js';

export const DISK_PRESSURE_BYTES = 20 * 1024 * 1024;
export const DISK_PRESSURE_COUNT = 100;

const DAY_MS = 24 * 60 * 60 * 1000;
const PROTECTED_BASENAMES = new Set(['index.json', 'audit.jsonl', 'SETUP.md']);

export interface RetentionPolicy {
  maxCount: number | null;
  maxAgeDays: number | null;
  /** True when at least one limit will actually delete. */
  enabled: boolean;
}

export interface RetentionOverrides {
  maxCount?: number;
  maxAgeDays?: number;
}

export interface ReceiptFile {
  abs: string;
  rel: string;
  timestampMs: number;
  timestamp: string;
  bytes: number;
  jsonAbs: string | null;
  jsonRel: string | null;
  jsonBytes: number;
}

export interface PruneCandidate {
  rel: string;
  abs: string;
  jsonAbs: string | null;
  jsonRel: string | null;
  timestamp: string;
  bytes: number;
  reasons: Array<'maxCount' | 'maxAgeDays'>;
}

export interface PrunePlan {
  delete: PruneCandidate[];
  keep: ReceiptFile[];
}

export function resolveRetentionPolicy(
  cfg: Pick<AgentReceiptConfig, 'maxCount' | 'maxAgeDays'>,
  overrides: RetentionOverrides = {},
): RetentionPolicy {
  const maxCount = overrides.maxCount ?? cfg.maxCount ?? null;
  const maxAgeDays = overrides.maxAgeDays ?? cfg.maxAgeDays ?? null;
  return {
    maxCount,
    maxAgeDays,
    enabled: maxCount != null || maxAgeDays != null,
  };
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function policyLabel(policy: RetentionPolicy): string {
  const parts: string[] = [];
  if (policy.maxCount != null) parts.push(`maxCount=${policy.maxCount}`);
  if (policy.maxAgeDays != null) parts.push(`maxAgeDays=${policy.maxAgeDays}`);
  return parts.join(', ') || 'retention off';
}

/** Refuse repo-root or outside-repo outDirs. Dry-run and apply both call this. */
export function assertPruneOutDir(cwd: string, outAbs: string): void {
  const root = resolve(cwd);
  const dir = resolve(outAbs);
  if (dir === root) {
    throw new Error(
      `refusing to prune outDir (${dir}): it is the repo root. Point outDir at a subdirectory such as .agent-receipt/receipts.`,
    );
  }
  const rel = relative(root, dir);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(
      `refusing to prune outDir (${dir}): it must be a directory inside the repo.`,
    );
  }
}

function posixRel(cwd: string, filePath: string): string {
  const abs = isAbsolute(filePath) ? filePath : resolve(cwd, filePath);
  const rel = relative(cwd, abs).replace(/\\/g, '/');
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) return abs;
  return rel;
}

function fileHasHashMarker(abs: string, size: number): boolean {
  const fd = openSync(abs, 'r');
  try {
    const n = Math.min(size, 4096);
    const buf = Buffer.alloc(n);
    const start = Math.max(0, size - n);
    const read = readSync(fd, buf, 0, n, start);
    return buf.subarray(0, read).toString('utf8').includes('agent-receipt-sha256');
  } finally {
    closeSync(fd);
  }
}

function indexedPaths(cwd: string, index: ReceiptIndex): Set<string> {
  const set = new Set<string>();
  for (const entry of index.receipts) {
    if (!entry || typeof entry.path !== 'string') continue;
    set.add(posixRel(cwd, entry.path));
  }
  return set;
}

function timestampFor(
  cwd: string,
  rel: string,
  mtimeMs: number,
  index: ReceiptIndex,
): { timestampMs: number; timestamp: string } {
  const entry = index.receipts.find(
    (r) => r && typeof r.path === 'string' && posixRel(cwd, r.path) === rel,
  );
  if (entry?.timestamp) {
    const parsed = Date.parse(entry.timestamp);
    if (Number.isFinite(parsed)) {
      return { timestampMs: parsed, timestamp: new Date(parsed).toISOString() };
    }
  }
  return { timestampMs: mtimeMs, timestamp: new Date(mtimeMs).toISOString() };
}

/**
 * Receipt markdown files directly under outDir (not nested).
 * Symlinks are skipped. SETUP.md / index.json / audit.jsonl are never receipts.
 * A file counts when it is in the index, named `receipt-*.md`, or carries a hash footer.
 */
export function listReceiptFiles(cwd: string, index?: ReceiptIndex): ReceiptFile[] {
  const dir = receiptsDir(cwd);
  if (!existsSync(dir)) return [];
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const catalog = index ?? safeLoadForList(cwd);
  const known = indexedPaths(cwd, catalog);
  const out: ReceiptFile[] = [];

  for (const name of names) {
    if (name.includes('/') || name.includes('\\')) continue;
    if (!name.toLowerCase().endsWith('.md')) continue;
    if (PROTECTED_BASENAMES.has(name)) continue;
    const abs = join(dir, name);
    let st;
    try {
      st = lstatSync(abs);
    } catch {
      continue;
    }
    if (st.isSymbolicLink() || !st.isFile()) continue;
    if (!isInsideOutDir(cwd, abs)) continue;
    const rel = posixRel(cwd, abs);
    const named = /^receipt-.+\.md$/i.test(name);
    const indexed = known.has(rel);
    let marker = false;
    if (!named && !indexed) {
      try {
        marker = fileHasHashMarker(abs, st.size);
      } catch {
        marker = false;
      }
    }
    if (!named && !indexed && !marker) continue;

    const { timestampMs, timestamp } = timestampFor(cwd, rel, st.mtimeMs, catalog);
    const jsonName = name.replace(/\.md$/i, '.json');
    let jsonAbs: string | null = null;
    let jsonRel: string | null = null;
    let jsonBytes = 0;
    if (!PROTECTED_BASENAMES.has(jsonName)) {
      const candidate = join(dir, jsonName);
      try {
        const js = lstatSync(candidate);
        if (js.isFile() && !js.isSymbolicLink() && isInsideOutDir(cwd, candidate)) {
          jsonAbs = candidate;
          jsonRel = posixRel(cwd, candidate);
          jsonBytes = js.size;
        }
      } catch {
        /* no companion */
      }
    }
    out.push({
      abs,
      rel,
      timestampMs,
      timestamp,
      bytes: st.size,
      jsonAbs,
      jsonRel,
      jsonBytes,
    });
  }
  return out;
}

function safeLoadForList(cwd: string): ReceiptIndex {
  try {
    return readIndexStrict(cwd).index;
  } catch {
    return { version: 1, updatedAt: new Date(0).toISOString(), receipts: [] };
  }
}

export function receiptBytes(files: Array<{ bytes: number; jsonBytes: number }>): number {
  return files.reduce((n, f) => n + f.bytes + f.jsonBytes, 0);
}

/**
 * True when outDir holds enough receipts or bytes that an unset limit is a
 * prod concern (same thresholds as the doctor retention WARN).
 */
export function outDirUnderPressure(cwd: string): boolean {
  const files = listReceiptFiles(cwd);
  return files.length >= DISK_PRESSURE_COUNT || receiptBytes(files) >= DISK_PRESSURE_BYTES;
}

/**
 * Newest-first. A receipt is removed when it is past `maxCount` (if set)
 * or strictly older than `maxAgeDays` (if set). Both limits apply together:
 * keep only files that satisfy every limit that is set.
 * A timestamp exactly `maxAgeDays` old is kept.
 */
export function planRetention(
  files: ReceiptFile[],
  policy: RetentionPolicy,
  now = Date.now(),
): PrunePlan {
  if (!policy.enabled) return { delete: [], keep: [...files] };
  const sorted = [...files].sort((a, b) => {
    if (b.timestampMs !== a.timestampMs) return b.timestampMs - a.timestampMs;
    return a.rel.localeCompare(b.rel);
  });
  const cutoff =
    policy.maxAgeDays != null ? now - policy.maxAgeDays * DAY_MS : null;
  const del: PruneCandidate[] = [];
  const keep: ReceiptFile[] = [];
  sorted.forEach((f, i) => {
    const reasons: Array<'maxCount' | 'maxAgeDays'> = [];
    if (policy.maxCount != null && i >= policy.maxCount) reasons.push('maxCount');
    if (cutoff != null && f.timestampMs < cutoff) reasons.push('maxAgeDays');
    if (!reasons.length) {
      keep.push(f);
      return;
    }
    del.push({
      rel: f.rel,
      abs: f.abs,
      jsonAbs: f.jsonAbs,
      jsonRel: f.jsonRel,
      timestamp: f.timestamp,
      bytes: f.bytes + f.jsonBytes,
      reasons,
    });
  });
  return { delete: del, keep };
}

export function staleIndexCount(cwd: string, index: ReceiptIndex): number {
  return index.receipts.filter((r) => isStaleEntry(cwd, r)).length;
}

function isStaleEntry(cwd: string, entry: ReceiptIndexEntry): boolean {
  if (!entry || typeof entry.path !== 'string' || !entry.path) return false;
  const abs = resolve(cwd, entry.path);
  if (!isInsideOutDir(cwd, abs)) return false;
  return !existsSync(abs);
}

function assertDeletable(cwd: string, abs: string): void {
  const base = basename(abs);
  if (PROTECTED_BASENAMES.has(base)) {
    throw new Error(`refusing to delete protected file ${base}`);
  }
  const st = lstatSync(abs);
  if (st.isSymbolicLink()) {
    throw new Error(`refusing to delete symlink ${abs}`);
  }
  if (!st.isFile()) {
    throw new Error(`refusing to delete non-file ${abs}`);
  }
  if (!isInsideOutDir(cwd, abs)) {
    throw new Error(`refusing to delete outside outDir: ${abs}`);
  }
}

/** Delete planned receipts. Missing files are ignored. Throws before any partial unlink policy violation. */
export function deletePlanned(cwd: string, planned: PruneCandidate[]): void {
  for (const item of planned) {
    if (item.jsonAbs) {
      if (existsSync(item.jsonAbs)) {
        assertDeletable(cwd, item.jsonAbs);
        unlinkSync(item.jsonAbs);
      }
    }
    if (existsSync(item.abs)) {
      assertDeletable(cwd, item.abs);
      unlinkSync(item.abs);
    }
  }
}

/**
 * Drop index rows whose files are gone under outDir. Rows outside outDir
 * are left alone. Returns the number of rows removed. Does not write when
 * nothing changed.
 */
export function refreshIndexAfterPrune(cwd: string, index: ReceiptIndex): number {
  const next = index.receipts.filter((r) => !isStaleEntry(cwd, r));
  const removed = index.receipts.length - next.length;
  if (removed <= 0) return 0;
  writeIndexAtomic(cwd, {
    version: 1,
    updatedAt: new Date().toISOString(),
    receipts: next,
  });
  return removed;
}

export interface RetentionCheck {
  name: 'retention';
  status: 'pass' | 'fail' | 'warn' | 'info';
  detail: string;
}

/** Doctor row. Never deletes. */
export function retentionCheck(cwd: string, cfg: AgentReceiptConfig): RetentionCheck {
  if (cfg.retentionInvalid?.length) {
    return {
      name: 'retention',
      status: 'fail',
      detail: cfg.retentionInvalid.join('; '),
    };
  }

  if (existsSync(indexPath(cwd))) {
    try {
      readIndexStrict(cwd);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        name: 'retention',
        status: 'warn',
        detail: `${msg} Ages fall back to file mtime until it is valid JSON.`,
      };
    }
  }

  const policy = resolveRetentionPolicy(cfg);
  if (policy.enabled) {
    try {
      assertPruneOutDir(cwd, receiptsDir(cwd));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { name: 'retention', status: 'fail', detail: msg };
    }
  }
  let files: ReceiptFile[] = [];
  try {
    files = listReceiptFiles(cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      name: 'retention',
      status: 'warn',
      detail: `could not read ${cfg.outDir} (${msg})`,
    };
  }
  const bytes = receiptBytes(files);

  if (!policy.enabled) {
    if (files.length >= DISK_PRESSURE_COUNT || bytes >= DISK_PRESSURE_BYTES) {
      return {
        name: 'retention',
        status: 'warn',
        detail:
          `opt-in off — ${files.length} receipt(s), ${formatBytes(bytes)} in ${cfg.outDir}. ` +
          'Set maxCount and/or maxAgeDays, then agent-receipt prune --dry-run',
      };
    }
    return {
      name: 'retention',
      status: 'info',
      detail:
        `opt-in off (no maxCount / maxAgeDays) — ${files.length} receipt(s), ${formatBytes(bytes)}. ` +
        'prune will not delete anything.',
    };
  }

  const plan = planRetention(files, policy);
  const label = policyLabel(policy);
  if (plan.delete.length) {
    const freed = plan.delete.reduce((n, d) => n + d.bytes, 0);
    return {
      name: 'retention',
      status: 'warn',
      detail:
        `${label} — ${plan.delete.length} receipt(s) (${formatBytes(freed)}) would be removed. ` +
        'Run: agent-receipt prune',
    };
  }
  return {
    name: 'retention',
    status: 'pass',
    detail: `${label} — ${files.length} receipt(s), ${formatBytes(bytes)}, within policy`,
  };
}
