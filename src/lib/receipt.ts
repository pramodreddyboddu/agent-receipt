import { appendHashFooter, sha256Hex, canonicalBody } from './hash.js';
import type { FileStat } from './git.js';
import { summarizeRisks, type RiskHint } from './risk.js';
import { summarizeNotableChanges, formatDiffStatTable } from './summary.js';

export interface ReceiptData {
  version: string;
  timestamp: string;
  branch: string;
  head: string;
  remote: string | null;
  rangeLabel: string;
  base: string;
  agent?: string;
  session?: string;
  message?: string;
  commits: string[];
  files: FileStat[];
  diffs: Record<string, string>;
  risks: RiskHint[];
  cwd: string;
}

export interface FormatOptions {
  full?: boolean;
  /** Include git-style diff-stat block (default true). */
  diffStat?: boolean;
  /** Max risk rows in the findings table (default 20). */
  topRisks?: number;
}

function statusCounts(files: FileStat[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of files) {
    const s = f.status || '?';
    counts[s] = (counts[s] || 0) + 1;
  }
  return counts;
}

export function formatMarkdown(
  data: ReceiptData,
  opts: boolean | FormatOptions = false,
): string {
  const options: FormatOptions =
    typeof opts === 'boolean' ? { full: opts } : opts ?? {};
  const full = Boolean(options.full);
  const diffStat = options.diffStat !== false;
  const topRisks = options.topRisks ?? 20;

  const lines: string[] = [];
  const totalIns = data.files.reduce((a, f) => a + f.insertions, 0);
  const totalDel = data.files.reduce((a, f) => a + f.deletions, 0);
  const riskSum = summarizeRisks(data.risks);
  const statuses = statusCounts(data.files);
  const statusBits = Object.entries(statuses)
    .map(([k, v]) => `${v}${k}`)
    .join(' ');
  const notable = summarizeNotableChanges(data.files);

  lines.push('# Agent Receipt');
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  const riskLabel =
    riskSum.total === 0
      ? 'none'
      : `${riskSum.total} (high ${riskSum.high}, medium ${riskSum.medium}, low ${riskSum.low})`;
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Files | ${data.files.length}${statusBits ? ` (${statusBits})` : ''} |`);
  lines.push(`| Lines | +${totalIns} / −${totalDel} |`);
  lines.push(`| Commits | ${data.commits.length} |`);
  lines.push(`| Risk | ${riskLabel} |`);
  if (riskSum.maxSeverity) {
    lines.push(`| Max severity | **${riskSum.maxSeverity}** |`);
  }
  lines.push('');

  lines.push('## Session');
  lines.push('');
  lines.push(`- **Version**: ${data.version}`);
  lines.push(`- **Timestamp**: ${data.timestamp}`);
  lines.push(`- **Branch**: \`${data.branch}\``);
  lines.push(`- **HEAD**: \`${data.head}\``);
  if (data.remote) lines.push(`- **Remote**: ${data.remote}`);
  lines.push(
    `- **Range**: \`${data.rangeLabel}\` (\`${data.base.slice(0, 12)}\` → HEAD)`,
  );
  if (data.agent) lines.push(`- **Agent**: ${data.agent}`);
  if (data.session) lines.push(`- **Session**: ${data.session}`);
  if (data.message) lines.push(`- **Message**: ${data.message}`);
  lines.push(`- **Workspace**: \`${data.cwd}\``);
  lines.push('');

  if (notable.length) {
    lines.push('## Notable changes');
    lines.push('');
    for (const n of notable) {
      lines.push(`- **${n.kind}**: ${n.note} (\`${n.path}\`)`);
    }
    lines.push('');
  }

  if (data.commits.length) {
    lines.push('## Commits');
    lines.push('');
    for (const c of data.commits) lines.push(`- ${c}`);
    lines.push('');
  }

  lines.push('## Files changed');
  lines.push('');
  if (!data.files.length) {
    lines.push('_No file changes in range._');
    lines.push('');
  } else {
    lines.push('| Status | File | + | − | Binary |');
    lines.push('|--------|------|---|---|--------|');
    for (const f of data.files) {
      lines.push(
        `| ${f.status} | \`${f.path}\` | ${f.insertions} | ${f.deletions} | ${f.binary ? 'yes' : ''} |`,
      );
    }
    lines.push('');
    lines.push(`**Totals**: ${data.files.length} files, +${totalIns} / −${totalDel}`);
    lines.push('');
  }

  if (diffStat) {
    lines.push('## Diff stat');
    lines.push('');
    for (const l of formatDiffStatTable(data.files)) lines.push(l);
    lines.push('');
  }

  lines.push('## Risk findings');
  lines.push('');
  if (data.risks.length) {
    const order = { high: 0, medium: 1, low: 2 } as const;
    const sorted = [...data.risks].sort(
      (a, b) => order[a.severity] - order[b.severity],
    );
    const shown = sorted.slice(0, topRisks);
    lines.push('| Sev | Code | Detail |');
    lines.push('|-----|------|--------|');
    for (const r of shown) {
      const detail = r.message.replace(/\|/g, '\\|');
      lines.push(`| ${r.severity} | \`${r.code}\` | ${detail} |`);
    }
    if (sorted.length > shown.length) {
      lines.push('');
      lines.push(`_… ${sorted.length - shown.length} more risk hint(s) omitted._`);
    }
    lines.push('');
  } else {
    lines.push('_None detected._');
    lines.push('');
  }

  lines.push(`## Diff summaries${full ? ' (full)' : ''}`);
  lines.push('');
  const paths = Object.keys(data.diffs);
  if (!paths.length) {
    lines.push('_No diffs._');
    lines.push('');
  } else {
    for (const p of paths) {
      lines.push(`### \`${p}\``);
      lines.push('');
      lines.push('```diff');
      lines.push(data.diffs[p]);
      lines.push('```');
      lines.push('');
    }
  }

  return appendHashFooter(lines.join('\n'));
}

export function formatJson(data: ReceiptData, markdown: string): object {
  const body = canonicalBody(markdown);
  const totalIns = data.files.reduce((a, f) => a + f.insertions, 0);
  const totalDel = data.files.reduce((a, f) => a + f.deletions, 0);
  const riskSum = summarizeRisks(data.risks);
  return {
    version: data.version,
    timestamp: data.timestamp,
    branch: data.branch,
    head: data.head,
    remote: data.remote,
    range: { label: data.rangeLabel, base: data.base, head: data.head },
    agent: data.agent ?? null,
    session: data.session ?? null,
    message: data.message ?? null,
    workspace: data.cwd,
    summary: {
      files: data.files.length,
      insertions: totalIns,
      deletions: totalDel,
      commits: data.commits.length,
      risk: riskSum,
      notable: summarizeNotableChanges(data.files),
    },
    commits: data.commits,
    files: data.files,
    risks: data.risks,
    integrity: {
      algorithm: 'sha256',
      sha256: sha256Hex(body),
    },
  };
}

export function defaultReceiptFilename(ts: Date = new Date()): string {
  const iso = ts.toISOString().replace(/[:.]/g, '-');
  return `receipt-${iso}.md`;
}
