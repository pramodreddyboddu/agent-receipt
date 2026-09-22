import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig } from '../lib/config.js';
import { resolveReceiptPath, findLatestReceipt } from './show.js';
import { color } from '../lib/color.js';

export interface ReceiptGlance {
  path: string;
  head?: string;
  branch?: string;
  agent?: string;
  message?: string;
  timestamp?: string;
  files: string[];
  risks: Array<{ severity: string; code: string; detail: string }>;
  fileCount?: number;
  insertions?: number;
  deletions?: number;
  riskTotal?: number;
  sha?: string;
  /** True when the session snapshot line marks a dirty working tree. */
  uncommitted?: boolean;
}

/** List receipt .md files newest-first under configured outDir. */
export function listReceipts(cwd: string): string[] {
  const cfg = loadConfig(cwd);
  const dir = join(cwd, cfg.outDir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => join(dir, f))
    .filter((p) => {
      try {
        return statSync(p).isFile();
      } catch {
        return false;
      }
    })
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
}

export function findPreviousReceipt(cwd: string, newerPath?: string): string | null {
  const all = listReceipts(cwd);
  if (!all.length) return null;
  if (!newerPath) return all[1] ?? null;
  const abs = newerPath.startsWith('/') ? newerPath : join(cwd, newerPath);
  const idx = all.findIndex((p) => p === abs);
  if (idx >= 0) return all[idx + 1] ?? null;
  // If newerPath is outside outDir (explicit path), treat latest as "previous" baseline
  return all[0] ?? null;
}

/** Best-effort parse of a Markdown receipt into comparable fields. */
export function parseReceiptGlance(path: string): ReceiptGlance {
  const text = readFileSync(path, 'utf8');
  const glance: ReceiptGlance = { path, files: [], risks: [] };

  const session = (label: string): string | undefined => {
    const re = new RegExp(`^- \\*\\*${label}\\*\\*:\\s*(.+)$`, 'm');
    const m = text.match(re);
    if (!m) return undefined;
    return m[1].replace(/^`|`$/g, '').trim();
  };

  glance.timestamp = session('Timestamp');
  glance.branch = session('Branch');
  glance.head = session('HEAD');
  glance.agent = session('Agent');
  glance.message = session('Message');
  glance.uncommitted = /\*\*Snapshot\*\*:\s*\*\*uncommitted\*\*/.test(text);

  const sha = text.match(/agent-receipt-sha256:\s*([a-f0-9]{64})/);
  if (sha) glance.sha = sha[1];

  const filesMatch = text.match(/\| Files \| (\d+)/);
  if (filesMatch) glance.fileCount = parseInt(filesMatch[1], 10);
  const linesMatch = text.match(/\| Lines \| \+(\d+) \/ −(\d+)/);
  if (linesMatch) {
    glance.insertions = parseInt(linesMatch[1], 10);
    glance.deletions = parseInt(linesMatch[2], 10);
  }
  const riskMatch = text.match(/\| Risk \| (\d+)/);
  if (riskMatch) glance.riskTotal = parseInt(riskMatch[1], 10);

  // Files table rows: | M | `path` | n | n |
  const filesSection = text.split('## Files changed')[1]?.split(/^## /m)[0] || '';
  for (const line of filesSection.split('\n')) {
    const m = line.match(/^\|\s*\w+\s*\|\s*`([^`]+)`\s*\|/);
    if (m) glance.files.push(m[1]);
  }

  const riskSection = text.split('## Risk findings')[1]?.split(/^## /m)[0] || '';
  for (const line of riskSection.split('\n')) {
    const m = line.match(/^\|\s*(\w+)\s*\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|$/);
    if (m && m[1] !== 'Sev') {
      glance.risks.push({
        severity: m[1],
        code: m[2],
        detail: m[3],
      });
    }
  }

  return glance;
}

function setDiff(a: string[], b: string[]): { onlyA: string[]; onlyB: string[]; both: string[] } {
  const setA = new Set(a);
  const setB = new Set(b);
  const onlyA: string[] = [];
  const onlyB: string[] = [];
  const both: string[] = [];
  for (const x of a) {
    if (setB.has(x)) both.push(x);
    else onlyA.push(x);
  }
  for (const x of b) {
    if (!setA.has(x)) onlyB.push(x);
  }
  return { onlyA, onlyB, both };
}

function riskKey(r: { severity: string; code: string; detail: string }): string {
  return `${r.severity}:${r.code}:${r.detail}`;
}

export interface CompareOptions {
  /** When true, print machine-friendly minimal output */
  quiet?: boolean;
}

/**
 * Compare two receipts (explicit paths, or last vs previous).
 * Alias command name: diff.
 */
export function cmdCompare(
  cwd: string,
  aArg?: string,
  bArg?: string,
  _opts: CompareOptions = {},
): number {
  let pathA: string;
  let pathB: string;

  if (aArg && bArg) {
    pathA = resolveReceiptPath(cwd, aArg);
    pathB = resolveReceiptPath(cwd, bArg);
  } else if (aArg && !bArg) {
    pathA = resolveReceiptPath(cwd, aArg);
    const prev = findPreviousReceipt(cwd, pathA);
    if (!prev) {
      throw new Error(
        'Only one receipt available — need two receipts to compare.\n' +
          'Capture another, or pass two explicit paths.',
      );
    }
    pathB = prev;
  } else {
    const latest = findLatestReceipt(cwd);
    if (!latest) {
      throw new Error(
        'No receipts found. Run `agent-receipt capture` first, or pass two paths.',
      );
    }
    const prev = findPreviousReceipt(cwd, latest);
    if (!prev) {
      throw new Error(
        'Only one receipt in outDir — capture another session, or pass two paths:\n' +
          '  agent-receipt compare <older.md> <newer.md>',
      );
    }
    pathA = latest;
    pathB = prev;
  }

  const newer = parseReceiptGlance(pathA);
  const older = parseReceiptGlance(pathB);

  console.log(color.bold('Receipt compare'));
  console.log(color.dim('A (newer/first):') + ` ${newer.path}`);
  console.log(color.dim('B (older/second):') + ` ${older.path}`);
  console.log('');

  // Session delta
  console.log(color.bold('Session'));
  const rows: Array<[string, string | undefined, string | undefined]> = [
    ['timestamp', newer.timestamp, older.timestamp],
    ['branch', newer.branch, older.branch],
    ['HEAD', newer.head, older.head],
    ['agent', newer.agent, older.agent],
    ['message', newer.message, older.message],
  ];
  for (const [label, a, b] of rows) {
    if (a === b) {
      console.log(`  ${label}: ${a ?? color.dim('(none)')}`);
    } else {
      console.log(`  ${label}:`);
      console.log(`    A: ${a ?? color.dim('(none)')}`);
      console.log(`    B: ${b ?? color.dim('(none)')}`);
    }
  }
  console.log('');

  // Summary metrics
  console.log(color.bold('Summary'));
  const metric = (
    label: string,
    a?: number,
    b?: number,
  ): void => {
    if (a === undefined && b === undefined) return;
    const av = a ?? 0;
    const bv = b ?? 0;
    const delta = av - bv;
    const sign = delta > 0 ? '+' : '';
    console.log(
      `  ${label}: A=${av}  B=${bv}` +
        (delta !== 0 ? color.dim(`  (Δ ${sign}${delta})`) : ''),
    );
  };
  metric('files', newer.fileCount ?? newer.files.length, older.fileCount ?? older.files.length);
  metric('insertions', newer.insertions, older.insertions);
  metric('deletions', newer.deletions, older.deletions);
  metric('risks', newer.riskTotal ?? newer.risks.length, older.riskTotal ?? older.risks.length);
  console.log('');

  // Files
  const files = setDiff(newer.files, older.files);
  console.log(color.bold('Files'));
  if (!files.onlyA.length && !files.onlyB.length) {
    console.log(color.dim('  (same file set)'));
  } else {
    for (const f of files.onlyA) console.log(color.green(`  + ${f}`) + color.dim('  (only in A)'));
    for (const f of files.onlyB) console.log(color.red(`  − ${f}`) + color.dim('  (only in B)'));
    if (files.both.length) {
      console.log(color.dim(`  = ${files.both.length} file(s) in both`));
    }
  }
  console.log('');

  // Risks
  const riskA = new Map(newer.risks.map((r) => [riskKey(r), r]));
  const riskB = new Map(older.risks.map((r) => [riskKey(r), r]));
  const onlyRiskA: typeof newer.risks = [];
  const onlyRiskB: typeof older.risks = [];
  for (const [k, r] of riskA) if (!riskB.has(k)) onlyRiskA.push(r);
  for (const [k, r] of riskB) if (!riskA.has(k)) onlyRiskB.push(r);

  console.log(color.bold('Risks'));
  if (!onlyRiskA.length && !onlyRiskB.length) {
    console.log(color.dim('  (same risk set)'));
  } else {
    for (const r of onlyRiskA) {
      console.log(color.green(`  + [${r.severity}] ${r.code}`) + ` — ${r.detail}`);
    }
    for (const r of onlyRiskB) {
      console.log(color.red(`  − [${r.severity}] ${r.code}`) + ` — ${r.detail}`);
    }
  }

  if (newer.sha && older.sha) {
    console.log('');
    console.log(
      color.dim(
        `integrity A: sha256:${newer.sha.slice(0, 16)}…  B: sha256:${older.sha.slice(0, 16)}…`,
      ),
    );
  }

  return 0;
}
