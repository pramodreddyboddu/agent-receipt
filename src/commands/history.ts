import { listReceipts, parseReceiptGlance } from './compare.js';
import { color, severityColor } from '../lib/color.js';
import { loadIndex } from '../lib/receipt-index.js';

export interface HistoryOptions {
  /** Max rows (default 20). */
  limit?: number;
  /** Emit JSON array instead of the table. */
  json?: boolean;
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

/**
 * List recent receipts: time, agent, risk count, short summary.
 * Alias command name: ls.
 * With --json: machine-readable array (prefers `.agent-receipt/index.json` when present).
 */
export function cmdHistory(cwd: string, opts: HistoryOptions = {}): number {
  const limit = opts.limit && opts.limit > 0 ? opts.limit : 20;

  if (opts.json) {
    const idx = loadIndex(cwd);
    if (idx.receipts.length) {
      const rows = idx.receipts.slice(0, limit);
      console.log(JSON.stringify(rows, null, 2));
      return 0;
    }
    // Fall back to scanning receipts dir
    const all = listReceipts(cwd);
    if (!all.length) {
      throw new Error(
        'No receipts found under the configured outDir.\n' +
          'Run `agent-receipt capture` first (or `watch` / install-hooks).',
      );
    }
    const rows = all.slice(0, limit).map((p) => {
      const g = parseReceiptGlance(p);
      const high = g.risks.filter((r) => r.severity === 'high').length;
      const medium = g.risks.filter((r) => r.severity === 'medium').length;
      const low = g.risks.filter((r) => r.severity === 'low').length;
      return {
        path: p,
        timestamp: g.timestamp ?? null,
        agent: g.agent ?? null,
        message: g.message ?? null,
        head: g.head ?? null,
        branch: g.branch ?? null,
        files: g.fileCount ?? g.files.length,
        insertions: g.insertions ?? 0,
        deletions: g.deletions ?? 0,
        risk: {
          high,
          medium,
          low,
          total: g.riskTotal ?? g.risks.length,
          maxSeverity:
            high > 0 ? 'high' : medium > 0 ? 'medium' : low > 0 ? 'low' : null,
        },
        sha256: g.sha ?? null,
      };
    });
    console.log(JSON.stringify(rows, null, 2));
    return 0;
  }

  // Prefer index for text too — it already carries `uncommitted` (same as --json).
  const idx = loadIndex(cwd);
  if (idx.receipts.length) {
    const slice = idx.receipts.slice(0, limit);
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
        uncommitted: Boolean(e.uncommitted),
      };
    });
    printHistoryTable(rows, idx.receipts.length);
    return 0;
  }

  const all = listReceipts(cwd);
  if (!all.length) {
    throw new Error(
      'No receipts found under the configured outDir.\n' +
        'Run `agent-receipt capture` first (or `watch` / install-hooks).',
    );
  }

  const rows = all.slice(0, limit).map((p) => {
    const g = parseReceiptGlance(p);
    return {
      path: p,
      time: g.timestamp ?? '?',
      agent: g.agent ?? '—',
      risk: riskCell(g),
      files: String(g.fileCount ?? g.files.length),
      summary: shortSummary(g),
      uncommitted: false,
    };
  });

  printHistoryTable(rows, all.length);
  return 0;
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
        uncommittedBadge(r.uncommitted) +
        r.summary,
    );
  }
  console.log('');
  console.log(color.dim(`newest: ${rows[0].path}`));
  console.log(color.dim('Tip: agent-receipt last    # glance the newest'));
  console.log(color.dim('     agent-receipt show    # full Markdown'));
  console.log(color.dim('     agent-receipt history --json'));
}
