import { appendHashFooter, sha256Hex, canonicalBody } from './hash.js';
import type { ToolCallSection } from './adapters/tool-calls.js';
import { formatToolCallSection } from './adapters/tool-calls.js';
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

/**
 * Portable session packages are directories named `<id>.session`.
 * `last`, `history`, and `prune` skip those directories and anything inside them.
 * `session-manifest.json` and the packaged receipts are not local receipts.
 */
export function isSessionPackageDirName(filename: string): boolean {
  const base = filename.split(/[/\\]/).pop() ?? filename;
  return /\.session$/i.test(base);
}

/**
 * True when any parent segment is a `*.session` package directory.
 * The file's own basename is not treated as a directory.
 */
export function isInsideSessionPackage(filePath: string): boolean {
  const parts = filePath.replace(/\\/g, '/').split('/').filter((part) => part.length > 0);
  if (parts.length < 2) return false;
  return parts.slice(0, -1).some((part) => isSessionPackageDirName(part));
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
  /** Link id (`r-` + 16 hex). Omitted when this run is not linked. */
  id?: string;
  session?: string;
  /** Parent link id or sha256. Omitted when this run has no parent. */
  parent?: string;
  /** Host label. Omitted unless the user opted in. */
  host?: string;
  message?: string;
  commits: string[];
  files: FileStat[];
  diffs: Record<string, string>;
  risks: RiskHint[];
  cwd: string;
  /** True when this receipt snapshots the dirty working tree (not commits). */
  uncommitted?: boolean;
  /**
   * Parsed transcript. Omitted when no transcript was passed or it did not
   * parse. Present for a valid zero-call transcript.
   */
  toolCalls?: ToolCallSection;
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

const CONTROL_RE = /[\u0000-\u001f\u007f\u2028\u2029]/;

/**
 * Headings the link grammar counts across the whole file. The writer emits
 * each of these once. User content must not emit them again as their own line.
 */
export const STRUCTURAL_HEADING_LINES = new Set([
  '# Agent Receipt',
  '## What to review',
  '## Session',
]);

/**
 * Lines user content must not emit on their own. `## Tool calls` is not a
 * 1.0.28 structural heading (old receipts must still link). It is still
 * escaped so the writer emits that heading once.
 */
const USER_LINE_ESCAPE = new Set([...STRUCTURAL_HEADING_LINES, '## Tool calls']);

/**
 * Branch and Workspace are single-backtick spans (`[^`]*`). A raw backtick
 * ends the span and the receipt is treated as pre-1.0.28. Percent-encode
 * `%` and `` ` `` so the span matches and the value round-trips.
 */
export function encodeBacktickField(value: string): string {
  return value.replace(/%/g, '%25').replace(/`/g, '%60');
}

export function decodeBacktickField(value: string): string {
  return value.replace(/%60/g, '`').replace(/%25/g, '%');
}

/**
 * A line after `## Session` is outside the writer grammar. If it is exactly
 * a structural heading, the whole-file count is not one and the receipt
 * does not link. Prefix that line with a space. Git diff bodies already
 * start with `+`, `-`, or a space, so those lines are unchanged.
 */
function pushUserLines(lines: string[], text: string): void {
  for (const line of String(text).split('\n')) {
    lines.push(USER_LINE_ESCAPE.has(line) ? ` ${line}` : line);
  }
}

function rejectHeaderControl(kind: string, value: string | undefined): void {
  if (value && CONTROL_RE.test(value)) {
    throw new Error(
      `${kind} must be a single line. Newlines and control characters are rejected.`,
    );
  }
}

/** Split on every line break so each piece can be quoted or indented. */
function messagePhysicalLines(message: string): string[] {
  return message.replace(/\r\n/g, '\n').replace(/[\r\u2028\u2029]/g, '\n').split('\n');
}

/**
 * TL;DR quote. Every physical line is prefixed so a message cannot open a heading.
 * A one-line message stays `>` plus `> text`, matching earlier receipts.
 */
function pushQuotedMessage(lines: string[], message: string): void {
  lines.push('>');
  for (const line of messagePhysicalLines(message)) {
    lines.push(`> ${line}`);
  }
}

/**
 * Header message. The first line stays on the field. Later lines are indented
 * so they are not headings and not `- **Field**:` lines. One line is unchanged.
 */
function pushHeaderMessage(lines: string[], message: string): void {
  const parts = messagePhysicalLines(message);
  lines.push(`- **Message**: ${parts[0]}`);
  for (const extra of parts.slice(1)) {
    lines.push(`  ${extra}`);
  }
}

export function formatMarkdown(
  data: ReceiptData,
  opts: boolean | FormatOptions = false,
): string {
  rejectHeaderControl('agent', data.agent);
  rejectHeaderControl('session', data.session);
  rejectHeaderControl('parent', data.parent);
  rejectHeaderControl('host', data.host);
  rejectHeaderControl('id', data.id);
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
  if (data.message) pushQuotedMessage(lines, data.message);
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
      // One physical line. A newline is still inside the writer grammar.
      const text = r.text.replace(/[\r\n\u2028\u2029]+/g, ' ');
      lines.push(`${i}. **${label}** \`${r.code}\` — ${text}`);
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
  lines.push(`- **Branch**: \`${encodeBacktickField(data.branch)}\``);
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
  if (data.id) lines.push(`- **Id**: ${data.id}`);
  if (data.agent) lines.push(`- **Agent**: ${data.agent}`);
  if (data.session) lines.push(`- **Session**: ${data.session}`);
  if (data.parent) lines.push(`- **Parent**: ${data.parent}`);
  if (data.host) lines.push(`- **Host**: ${data.host}`);
  if (data.message) pushHeaderMessage(lines, data.message);
  lines.push(`- **Workspace**: \`${encodeBacktickField(data.cwd)}\``);
  lines.push('');

  if (notable.length) {
    lines.push('## Notable changes');
    lines.push('');
    for (const n of notable) {
      pushUserLines(lines, `- **${n.kind}**: ${n.note} (\`${n.path}\`)`);
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
    for (const c of data.commits) pushUserLines(lines, `- ${c}`);
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
      pushUserLines(
        lines,
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
    for (const l of formatDiffStatTable(data.files)) pushUserLines(lines, l);
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
      pushUserLines(lines, `| ${r.severity} | \`${r.code}\` | ${detail} |`);
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

  if (data.toolCalls) {
    const section = formatToolCallSection(data.toolCalls).replace(/\n$/, '');
    const [heading, ...rest] = section.split('\n');
    lines.push(heading);
    pushUserLines(lines, rest.join('\n'));
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
      pushUserLines(lines, `### \`${p}\``);
      lines.push('');
      lines.push('```diff');
      pushUserLines(lines, data.diffs[p]);
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
  policy?: { hits: unknown[]; denied: boolean } | null,
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
    ...(data.id ? { id: data.id } : {}),
    ...(data.parent ? { parent: data.parent } : {}),
    ...(data.host ? { host: data.host } : {}),
    message: data.message ?? null,
    uncommitted: Boolean(data.uncommitted),
    failedOn: Boolean(failedOn),
    ...(policy
      ? { policyPackHits: policy.hits, policyDenied: policy.denied }
      : {}),
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
    ...(data.toolCalls
      ? {
          toolCalls: {
            adapter: data.toolCalls.adapter,
            count: data.toolCalls.events.length,
            truncated: data.toolCalls.truncated,
            sha256: data.toolCalls.sha256,
            events: data.toolCalls.events,
          },
        }
      : {}),
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
