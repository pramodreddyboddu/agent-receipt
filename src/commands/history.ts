import { listReceipts, parseReceiptGlance, type ReceiptGlance } from './compare.js';
import { color, severityColor } from '../lib/color.js';
import { loadIndex, type ReceiptIndexEntry } from '../lib/receipt-index.js';

export interface HistoryOptions {
  /** Max rows (default 20). Applied after --agent, --uncommitted, and --failed. */
  limit?: number;
  /** Emit JSON array instead of the table. */
  json?: boolean;
  /**
   * Exact, case-sensitive match on `agent`.
   * `null` and a missing agent do not match. Undefined = no agent filter.
   */
  agent?: string;
  /** Keep receipts where `uncommitted === true`. */
  uncommitted?: boolean;
  /** Keep receipts that failed the gate. */
  failed?: boolean;
}

interface HistoryFilterable {
  agent?: string | null;
  uncommitted?: boolean;
}

function riskFromCounts(
  high: number,
  medium: number,
  low: number,
  total: number,
): string {
  if (total === 0 && high + medium + low === 0) return '—';
  const bits: string[] = [];
  if (high) bits.push(`${high}H`);
  if (medium) bits.push(`${medium}M`);
  if (low) bits.push(`${low}L`);
  if (!bits.length && total) bits.push(String(total));
  const text = bits.join(' ');
  if (high) return severityColor('high', text);
  if (medium) return severityColor('medium', text);
  return color.dim(text);
}

function riskCell(g: {
  risks: Array<{ severity: string }>;
  riskTotal?: number;
}): string {
  const high = g.risks.filter((r) => r.severity === 'high').length;
  const medium = g.risks.filter((r) => r.severity === 'medium').length;
  const low = g.risks.filter((r) => r.severity === 'low').length;
  const total = g.riskTotal ?? g.risks.length;
  return riskFromCounts(high, medium, low, total);
}

/** Visible badge when a receipt is an uncommitted working-tree snapshot. */
function uncommittedBadge(uncommitted: boolean): string {
  return uncommitted ? color.yellow('[uncommitted] ') : '';
}

/** Visible badge when the receipt failed the gate. */
function failedBadge(failed: boolean): string {
  return failed ? color.red('[failed] ') : '';
}

/**
 * Stored `failedOn` wins, including `false` on a high-risk row.
 * Pre-1.0.12 rows omit the field: high severity only (medium/low stay out).
 */
function indexRowFailed(entry: ReceiptIndexEntry): boolean {
  if (typeof entry.failedOn === 'boolean') return entry.failedOn;
  const risk = entry.risk;
  if (!risk) return false;
  return risk.high > 0 || risk.maxSeverity === 'high';
}

/** Scan path has no gate bit. A high-severity glance row counts; medium/low do not. */
function glanceRowFailed(risks: Array<{ severity: string }>): boolean {
  return risks.some((r) => r.severity === 'high');
}

function indexJsonRow(entry: ReceiptIndexEntry): ReceiptIndexEntry {
  return { ...entry, failedOn: indexRowFailed(entry) };
}

function shortSummary(g: { message?: string; fileCount?: number; files: string[] }): string {
  if (g.message) {
    const m = g.message.replace(/\s+/g, ' ').trim();
    return m.length > 56 ? m.slice(0, 55) + '…' : m;
  }
  const n = g.fileCount ?? g.files.length;
  return n ? `${n} file${n === 1 ? '' : 's'}` : '(no message)';
}

function pad(s: string, n: number): string {
  const visible = s.replace(/\u001b\[[0-9;]*m/g, '');
  if (visible.length >= n) return s.slice(0, n);
  return s + ' '.repeat(n - visible.length);
}

const NO_RECEIPTS =
  'No receipts found under the configured outDir.\n' +
  'Run `agent-receipt capture` first (or `watch` / install-hooks).';

/**
 * Load order is the caller's job (index when present, else scan).
 * This applies `--agent` → `--uncommitted` → `--failed`. `--limit` is a separate slice.
 */
function applyHistoryFilters<T extends HistoryFilterable>(
  rows: T[],
  opts: HistoryOptions,
  isFailed: (row: T) => boolean,
): T[] {
  let filtered = rows;
  if (opts.agent !== undefined) {
    const name = opts.agent;
    filtered = filtered.filter((row) => row.agent === name);
  }
  if (opts.uncommitted) {
    filtered = filtered.filter((row) => row.uncommitted === true);
  }
  if (opts.failed) {
    filtered = filtered.filter((row) => isFailed(row));
  }
  return filtered;
}

function filterLabel(opts: HistoryOptions): string {
  const parts: string[] = [];
  if (opts.agent !== undefined) parts.push(`agent=${opts.agent}`);
  if (opts.uncommitted) parts.push('uncommitted');
  if (opts.failed) parts.push('failed');
  return parts.join(', ');
}

function printHistoryTips(): void {
  console.log(color.dim('Tip: agent-receipt last    # glance the newest'));
  console.log(color.dim('     agent-receipt show    # full Markdown'));
  console.log(color.dim('     agent-receipt history --json'));
}

function printEmptyHistory(unfiltered: number, opts: HistoryOptions): void {
  console.log(color.bold('Recent receipts') + color.dim(' (0 of 0)'));
  console.log('');
  const other = `${unfiltered} other receipt${unfiltered === 1 ? '' : 's'}`;
  console.log(`No receipts match ${filterLabel(opts)} (${other}).`);
  console.log('');
  printHistoryTips();
}

function emitJson(rows: unknown[]): number {
  console.log(JSON.stringify(rows, null, 2));
  return 0;
}

/**
 * List recent receipts: time, agent, risk count, short summary.
 * Alias command name: ls.
 * With --json: machine-readable array (prefers `.agent-receipt/index.json` when present).
 *
 * Filter order: load receipts → `--agent` → `--uncommitted` → `--failed` → `--limit` (newest N).
 * An empty store still errors. A filter that matches nothing exits 0.
 */
export function cmdHistory(cwd: string, opts: HistoryOptions = {}): number {
  const limit = opts.limit && opts.limit > 0 ? opts.limit : 20;

  const idx = loadIndex(cwd);
  if (idx.receipts.length) {
    const filtered = applyHistoryFilters(idx.receipts, opts, indexRowFailed);
    const slice = filtered.slice(0, limit);
    if (opts.json) return emitJson(slice.map(indexJsonRow));
    if (!slice.length) {
      printEmptyHistory(idx.receipts.length, opts);
      return 0;
    }
    const rows = slice.map((e) => {
      const risk = e.risk ?? { high: 0, medium: 0, low: 0, total: 0 };
      return {
        path: e.path,
        time: e.timestamp ?? '?',
        agent: e.agent ?? '—',
        risk: riskFromCounts(risk.high, risk.medium, risk.low, risk.total),
        files: String(e.files ?? 0),
        summary: shortSummary({
          message: e.message ?? undefined,
          fileCount: e.files,
          files: [],
        }),
        uncommitted: e.uncommitted === true,
        failed: indexRowFailed(e),
      };
    });
    printHistoryTable(rows, filtered.length);
    return 0;
  }

  const all = listReceipts(cwd);
  if (!all.length) throw new Error(NO_RECEIPTS);

  const glances = all.map((p) => parseReceiptGlance(p));
  const filtered = applyHistoryFilters(glances, opts, (g) => glanceRowFailed(g.risks));
  const slice = filtered.slice(0, limit);
  if (opts.json) {
    return emitJson(slice.map((g) => glanceJsonRow(g)));
  }
  if (!slice.length) {
    printEmptyHistory(all.length, opts);
    return 0;
  }
  const rows = slice.map((g) => ({
    path: g.path,
    time: g.timestamp ?? '?',
    agent: g.agent ?? '—',
    risk: riskCell(g),
    files: String(g.fileCount ?? g.files.length),
    summary: shortSummary(g),
    uncommitted: g.uncommitted === true,
    failed: glanceRowFailed(g.risks),
  }));
  printHistoryTable(rows, filtered.length);
  return 0;
}

function glanceJsonRow(g: ReceiptGlance): Record<string, unknown> {
  const high = g.risks.filter((r) => r.severity === 'high').length;
  const medium = g.risks.filter((r) => r.severity === 'medium').length;
  const low = g.risks.filter((r) => r.severity === 'low').length;
  return {
    path: g.path,
    timestamp: g.timestamp ?? null,
    agent: g.agent ?? null,
    message: g.message ?? null,
    head: g.head ?? null,
    branch: g.branch ?? null,
    uncommitted: g.uncommitted === true,
    failedOn: glanceRowFailed(g.risks),
    files: g.fileCount ?? g.files.length,
    insertions: g.insertions ?? 0,
    deletions: g.deletions ?? 0,
    risk: {
      high,
      medium,
      low,
      total: g.riskTotal ?? g.risks.length,
      maxSeverity: high > 0 ? 'high' : medium > 0 ? 'medium' : low > 0 ? 'low' : null,
    },
    sha256: g.sha ?? null,
  };
}

function printHistoryTable(
  rows: Array<{
    path: string;
    time: string;
    agent: string;
    risk: string;
    files: string;
    summary: string;
    uncommitted: boolean;
    failed: boolean;
  }>,
  total: number,
): void {
  console.log(
    color.bold(`Recent receipts`) + color.dim(` (${rows.length} of ${total})`),
  );
  console.log('');
  const hdr =
    pad('TIME', 28) + pad('AGENT', 14) + pad('RISK', 10) + pad('FILES', 7) + 'SUMMARY';
  console.log(color.dim(hdr));
  for (const r of rows) {
    console.log(
      pad(r.time, 28) +
        pad(r.agent, 14) +
        pad(r.risk, 10) +
        pad(r.files, 7) +
        failedBadge(r.failed) +
        uncommittedBadge(r.uncommitted) +
        r.summary,
    );
  }
  console.log('');
  console.log(color.dim(`newest: ${rows[0].path}`));
  printHistoryTips();
}
