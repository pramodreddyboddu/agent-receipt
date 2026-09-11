import { basename } from 'node:path';
import { listReceipts, parseReceiptGlance } from './compare.js';
import { color, severityColor } from '../lib/color.js';

export interface HistoryOptions {
  /** Max rows (default 20). */
  limit?: number;
}

function riskCell(g: {
  risks: Array<{ severity: string }>;
  riskTotal?: number;
}): string {
  const high = g.risks.filter((r) => r.severity === 'high').length;
  const medium = g.risks.filter((r) => r.severity === 'medium').length;
  const low = g.risks.filter((r) => r.severity === 'low').length;
  const total = g.riskTotal ?? g.risks.length;
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
 */
export function cmdHistory(cwd: string, opts: HistoryOptions = {}): number {
  const limit = opts.limit && opts.limit > 0 ? opts.limit : 20;
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
      file: basename(p),
      time: g.timestamp ?? '?',
      agent: g.agent ?? '—',
      risk: riskCell(g),
      files: String(g.fileCount ?? g.files.length),
      summary: shortSummary(g),
    };
  });

  console.log(
    color.bold(`Recent receipts`) + color.dim(` (${rows.length} of ${all.length})`),
  );
  console.log('');
  const hdr =
    pad('TIME', 28) + pad('AGENT', 14) + pad('RISK', 10) + pad('FILES', 7) + 'SUMMARY';
  console.log(color.dim(hdr));
  for (const r of rows) {
    console.log(
      pad(r.time, 28) + pad(r.agent, 14) + pad(r.risk, 10) + pad(r.files, 7) + r.summary,
    );
  }
  console.log('');
  console.log(color.dim(`newest: ${rows[0].path}`));
  console.log(color.dim('Tip: agent-receipt last    # glance the newest'));
  console.log(color.dim('     agent-receipt show    # full Markdown'));
  return 0;
}
