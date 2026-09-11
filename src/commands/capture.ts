import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import {
  isGitRepo,
  getBranch,
  getHead,
  getRemoteUrl,
  resolveRange,
  getChangedFiles,
  getFileDiffSummary,
  getCommitLog,
} from '../lib/git.js';
import { analyzeRisks } from '../lib/risk.js';
import { loadConfig, ensureOutDir } from '../lib/config.js';
import {
  formatMarkdown,
  formatJson,
  defaultReceiptFilename,
  type ReceiptData,
} from '../lib/receipt.js';

export interface CaptureOptions {
  since?: string;
  commits?: number;
  message?: string;
  agent?: string;
  out?: string;
  full?: boolean;
  json?: boolean;
}

export function cmdCapture(cwd: string, opts: CaptureOptions): string {
  if (!isGitRepo(cwd)) {
    throw new Error('Not a git repository. Run inside a git repo or git init first.');
  }

  const cfg = loadConfig(cwd);
  const commitsN = opts.commits ?? cfg.defaultCommits;
  const full = opts.full ?? cfg.fullDiffs;
  const agent = opts.agent ?? cfg.defaultAgent;

  const range = resolveRange(cwd, { since: opts.since, commits: commitsN });
  const files = getChangedFiles(cwd, range.base, range.head);
  const risks = analyzeRisks(files);
  const commits = getCommitLog(cwd, range.base, range.head);

  const diffs: Record<string, string> = {};
  for (const f of files) {
    if (f.binary) {
      diffs[f.path] = '(binary file — content omitted)';
      continue;
    }
    diffs[f.path] = getFileDiffSummary(
      cwd,
      range.base,
      range.head,
      f.path,
      full,
    );
  }

  const data: ReceiptData = {
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    branch: getBranch(cwd),
    head: getHead(cwd),
    remote: getRemoteUrl(cwd),
    rangeLabel: range.label,
    base: range.base,
    agent,
    message: opts.message,
    commits,
    files,
    diffs,
    risks,
    cwd: resolve(cwd),
  };

  const markdown = formatMarkdown(data, full);

  let outPath: string;
  if (opts.out) {
    outPath = resolve(cwd, opts.out);
    mkdirSync(dirname(outPath), { recursive: true });
  } else {
    const dir = ensureOutDir(cwd, cfg.outDir);
    outPath = join(dir, defaultReceiptFilename());
  }

  writeFileSync(outPath, markdown, 'utf8');

  if (opts.json) {
    const jsonPath = outPath.replace(/\.md$/i, '') + '.json';
    writeFileSync(
      jsonPath,
      JSON.stringify(formatJson(data, markdown), null, 2) + '\n',
      'utf8',
    );
    console.log(`Wrote JSON: ${jsonPath}`);
  }

  console.log(`Wrote receipt: ${outPath}`);
  console.log(
    `  ${files.length} files, ${risks.length} risk hint(s), range ${range.label}`,
  );
  return outPath;
}
