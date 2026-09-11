import { appendHashFooter, sha256Hex, canonicalBody } from './hash.js';
import type { FileStat } from './git.js';
import type { RiskHint } from './risk.js';

export interface ReceiptData {
  version: string;
  timestamp: string;
  branch: string;
  head: string;
  remote: string | null;
  rangeLabel: string;
  base: string;
  agent?: string;
  message?: string;
  commits: string[];
  files: FileStat[];
  diffs: Record<string, string>;
  risks: RiskHint[];
  cwd: string;
}

export function formatMarkdown(data: ReceiptData, full: boolean): string {
  const lines: string[] = [];
  lines.push('# Agent Receipt');
  lines.push('');
  lines.push(`- **Version**: ${data.version}`);
  lines.push(`- **Timestamp**: ${data.timestamp}`);
  lines.push(`- **Branch**: \`${data.branch}\``);
  lines.push(`- **HEAD**: \`${data.head}\``);
  if (data.remote) lines.push(`- **Remote**: ${data.remote}`);
  lines.push(`- **Range**: \`${data.rangeLabel}\` (\`${data.base.slice(0, 12)}\` → HEAD)`);
  if (data.agent) lines.push(`- **Agent**: ${data.agent}`);
  if (data.message) lines.push(`- **Message**: ${data.message}`);
  lines.push(`- **Workspace**: \`${data.cwd}\``);
  lines.push('');

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
    const totalIns = data.files.reduce((a, f) => a + f.insertions, 0);
    const totalDel = data.files.reduce((a, f) => a + f.deletions, 0);
    lines.push(`**Totals**: ${data.files.length} files, +${totalIns} / −${totalDel}`);
    lines.push('');
  }

  if (data.risks.length) {
    lines.push('## Risk hints');
    lines.push('');
    for (const r of data.risks) {
      lines.push(`- **[${r.severity.toUpperCase()}]** \`${r.code}\` — ${r.message}`);
    }
    lines.push('');
  } else {
    lines.push('## Risk hints');
    lines.push('');
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
  return {
    version: data.version,
    timestamp: data.timestamp,
    branch: data.branch,
    head: data.head,
    remote: data.remote,
    range: { label: data.rangeLabel, base: data.base, head: data.head },
    agent: data.agent ?? null,
    message: data.message ?? null,
    workspace: data.cwd,
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
