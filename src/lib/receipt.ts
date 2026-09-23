import { appendHashFooter, sha256Hex, canonicalBody } from './hash.js';
import type { FileStat } from './git.js';
import { summarizeRisks, sortRisks, type RiskHint } from './risk.js';
import { summarizeNotableChanges, formatDiffStatTable } from './summary.js';

/**
 * Prove one-pagers (`foo.prove.md`) sit beside receipts and are not receipts.
 * Receipt scanners skip them so a newer page does not become `last` or a prune target.
 */
export function isProveOnePagerName(filename: string): boolean {
  const base = filename.split(/[/\\]/).pop() ?? filename;
  return /\.prove\.md$/i.test(base);
}

/**
 * Portable share packages are directories named `<stem>.share`.
 * `last`, `history`, and `prune` skip those directories and anything inside them.
 * `manifest.json` and `receipt.md` in the package are not receipts.
 */
export function isSharePackageDirName(filename: string): boolean {
  const base = filename.split(/[/\\]/).pop() ?? filename;
  return /\.share$/i.test(base);
}

/**
 * True when any parent segment is a `*.share` package directory.
 * The file's own basename is not treated as a directory.
 */
export function isInsideSharePackage(filePath: string): boolean {
  const parts = filePath.replace(/\\/g, '/').split('/').filter((part) => part.length > 0);
  if (parts.length < 2) return false;
  return parts.slice(0, -1).some((part) => isSharePackageDirName(part));
}

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
  /** True when this receipt snapshots the dirty working tree (not commits). */
  uncommitted?: boolean;
}

export interface FormatOptions {
  full?: boolean;
  /** Include git-style diff-stat block (default true). */
  diffStat?: boolean;
  /** Max risk rows in the findings table (default 20). */
  topRisks?: number;
}

export interface ReviewItem {
  severity: 'high' | 'medium' | 'low' | 'notable';
  code: string;
  text: string;
  path?: string;
}

function statusCounts(files: FileStat[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of files) {
    const s = f.status || '?';
    counts[s] = (counts[s] || 0) + 1;
  }
  return counts;
}

/** Pull the one-line TL;DR blockquote out of a written receipt. */
export function extractTldr(markdown: string): string | null {
  const m = markdown.match(/> \*\*TL;DR\*\*\s+(.+)/);
  return m?.[1]?.trim() ?? null;
}

export function formatTldr(data: ReceiptData): string {
  const totalIns = data.files.reduce((a, f) => a + f.insertions, 0);
  const totalDel = data.files.reduce((a, f) => a + f.deletions, 0);
  const riskSum = summarizeRisks(data.risks);
  const shortHead = data.head.length > 12 ? data.head.slice(0, 12) : data.head;
  const agent = data.agent || 'agent';
  const riskBit =
    riskSum.total === 0
      ? 'risk none'
      : `risk ${riskSum.total} (${riskSum.high} high)`;
  const scope = data.uncommitted ? 'uncommitted' : shortHead;
  return (
    `${agent} · ${data.timestamp} · ${data.branch} @ ${scope}` +
    ` · ${data.files.length} files · +${totalIns}/−${totalDel} · ${riskBit}`
  );
}

/** High-signal review checklist: high/medium risks first, then notable files. */
export function buildReviewItems(data: ReceiptData, limit = 8): ReviewItem[] {
  const items: ReviewItem[] = [];
  const seenPaths = new Set<string>();
  const sorted = sortRisks(data.risks).filter((r) => r.severity !== 'low');
  for (const r of sorted) {
    if (items.length >= limit) break;
    items.push({
      severity: r.severity,
      code: r.code,
      text: r.message,
      path: r.path,
    });
    if (r.path) seenPaths.add(r.path);
  }
  if (items.length >= limit) return items;
  const notable = summarizeNotableChanges(data.files);
  for (const n of notable) {
    if (items.length >= limit) break;
    if (seenPaths.has(n.path)) continue;
    items.push({
      severity: 'notable',
      code: n.kind,
      text: n.note,
      path: n.path,
    });
    seenPaths.add(n.path);
  }
  return items;
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
  const tldr = formatTldr(data);
  const review = buildReviewItems(data);

  lines.push('# Agent Receipt');
  lines.push('');
  lines.push(`> **TL;DR** ${tldr}`);
  if (data.message) {
    lines.push('>');
    lines.push(`> ${data.message}`);
  }
  lines.push('');

  lines.push('## What to review');
  lines.push('');
  if (!review.length) {
    lines.push(
      '_Nothing flagged. Skim the file list if this session should have been a no-op._',
    );
    lines.push('');
  } else {
    let i = 1;
    for (const r of review) {
      const label = r.severity === 'notable' ? 'notable' : r.severity;
      lines.push(`${i}. **${label}** \`${r.code}\` — ${r.text}`);
      i++;
    }
    lines.push('');
  }

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
  if (data.uncommitted) {
    lines.push(`- **Range**: \`${data.rangeLabel}\` _(working tree; not committed)_`);
    lines.push(`- **Snapshot**: **uncommitted** (staged + unstaged + untracked)`);
  } else {
    lines.push(
      `- **Range**: \`${data.rangeLabel}\` (\`${data.base.slice(0, 12)}\` → HEAD)`,
    );
  }
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

  if (data.uncommitted) {
    lines.push('## Commits');
    lines.push('');
    lines.push('_Uncommitted working tree — no commits in this snapshot._');
    lines.push('');
  } else if (data.commits.length) {
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
    const sorted = sortRisks(data.risks);
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

export function formatJson(
  data: ReceiptData,
  markdown: string,
  failedOn = false,
): object {
  const body = canonicalBody(markdown);
  const totalIns = data.files.reduce((a, f) => a + f.insertions, 0);
  const totalDel = data.files.reduce((a, f) => a + f.deletions, 0);
  const riskSum = summarizeRisks(data.risks);
  const review = buildReviewItems(data);
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
    uncommitted: Boolean(data.uncommitted),
    failedOn: Boolean(failedOn),
    workspace: data.cwd,
    summary: {
      files: data.files.length,
      insertions: totalIns,
      deletions: totalDel,
      commits: data.commits.length,
      risk: riskSum,
      notable: summarizeNotableChanges(data.files),
      tldr: formatTldr(data),
      review,
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
