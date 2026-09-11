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
  getWorkingTreeFiles,
  getWorkingTreeDiff,
  isDirty,
  type FileStat,
} from '../lib/git.js';
import {
  analyzeRisks,
  summarizeRisks,
  meetsFailOn,
  type FailOnThreshold,
  type RiskSummary,
} from '../lib/risk.js';
import { loadConfig, ensureOutDir } from '../lib/config.js';
import { filterIgnored } from '../lib/ignore.js';
import {
  formatMarkdown,
  formatJson,
  defaultReceiptFilename,
  type ReceiptData,
} from '../lib/receipt.js';
import { updateIndexOnCapture } from '../lib/receipt-index.js';
import { VERSION } from '../lib/version.js';
import { color } from '../lib/color.js';

export interface CaptureOptions {
  since?: string;
  commits?: number;
  message?: string;
  agent?: string;
  session?: string;
  out?: string;
  full?: boolean;
  json?: boolean;
  diffStat?: boolean;
  topRisks?: number;
  /** Exit 2 after writing if max severity meets this threshold. */
  failOn?: FailOnThreshold;
  /**
   * Snapshot the dirty working tree (staged + unstaged + untracked) instead of
   * a commit range. Labeled **uncommitted** on the receipt.
   */
  uncommitted?: boolean;
}

export interface CaptureResult {
  path: string;
  riskSum: RiskSummary;
  failedOn: boolean;
  uncommitted: boolean;
}

export function cmdCapture(cwd: string, opts: CaptureOptions): CaptureResult {
  if (!isGitRepo(cwd)) {
    throw new Error(
      'Not a git repository. Run inside a git repo, or pass --cwd <path> to one.',
    );
  }

  const cfg = loadConfig(cwd);
  const commitsN = opts.commits ?? cfg.defaultCommits;
  const full = opts.full ?? cfg.fullDiffs;
  const agent = opts.agent ?? cfg.defaultAgent;
  const uncommitted = Boolean(opts.uncommitted);

  let files: FileStat[];
  let diffs: Record<string, string> = {};
  let commits: string[] = [];
  let rangeLabel: string;
  let base: string;
  let ignored: FileStat[] = [];

  if (uncommitted) {
    if (!isDirty(cwd)) {
      throw new Error(
        'Working tree is clean — nothing uncommitted to capture.\n' +
          'Make edits / stage files, or omit --uncommitted to capture commits.',
      );
    }
    const allFiles = getWorkingTreeFiles(cwd);
    const filtered = filterIgnored(allFiles, cfg.ignore);
    files = filtered.kept;
    ignored = filtered.ignored;
    rangeLabel = 'uncommitted (working tree)';
    base = 'uncommitted';
    commits = [];
    for (const f of files) {
      if (f.binary) {
        diffs[f.path] = '(binary file — content omitted)';
        continue;
      }
      diffs[f.path] = getWorkingTreeDiff(cwd, f.path, full);
    }
  } else {
    const range = resolveRange(cwd, { since: opts.since, commits: commitsN });
    const allFiles = getChangedFiles(cwd, range.base, range.head);
    const filtered = filterIgnored(allFiles, cfg.ignore);
    files = filtered.kept;
    ignored = filtered.ignored;
    rangeLabel = range.label;
    base = range.base;
    commits = getCommitLog(cwd, range.base, range.head);
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
  }

  const risks = analyzeRisks(files, diffs, cfg.riskAllowlist);
  const riskSum = summarizeRisks(risks);

  const data: ReceiptData = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    branch: getBranch(cwd),
    head: getHead(cwd),
    remote: getRemoteUrl(cwd),
    rangeLabel,
    base,
    agent,
    session: opts.session,
    message: opts.message,
    commits,
    files,
    diffs,
    risks,
    cwd: resolve(cwd),
    uncommitted,
  };

  const markdown = formatMarkdown(data, {
    full,
    diffStat: opts.diffStat,
    topRisks: opts.topRisks,
  });

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
    console.log(color.dim(`Wrote JSON:    ${jsonPath}`));
  }

  const ins = files.reduce((a, f) => a + f.insertions, 0);
  const del = files.reduce((a, f) => a + f.deletions, 0);

  try {
    updateIndexOnCapture(cwd, {
      outPath,
      timestamp: data.timestamp,
      agent: data.agent,
      message: data.message,
      head: data.head,
      branch: data.branch,
      uncommitted,
      files: files.length,
      insertions: ins,
      deletions: del,
      risks,
      markdown,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(color.dim(`  (index update skipped: ${msg})`));
  }

  console.log(color.green('✓') + ` Wrote receipt: ${outPath}`);
  const scope = uncommitted ? 'uncommitted' : rangeLabel;
  console.log(
    `  ${files.length} file(s), +${ins}/−${del}, ${risks.length} risk hint(s)` +
      (riskSum.maxSeverity ? ` [max: ${riskSum.maxSeverity}]` : '') +
      `, range ${scope}`,
  );
  if (uncommitted) {
    console.log(color.yellow('  ⚠ Snapshot is uncommitted (working tree, not HEAD).'));
  }
  if (ignored.length) {
    console.log(
      color.dim(
        `  ignored ${ignored.length} path(s) via config ignore globs (noise)`,
      ),
    );
  }
  if (cfg.riskAllowlist.length) {
    console.log(
      color.dim(
        `  riskAllowlist active (${cfg.riskAllowlist.length} rule(s))`,
      ),
    );
  }
  if (riskSum.high > 0) {
    console.log(
      color.yellow(
        `  ⚠ ${riskSum.high} high-severity risk hint(s) — review before trusting this session.`,
      ),
    );
  }

  const failedOn = Boolean(
    opts.failOn && meetsFailOn(riskSum.maxSeverity, opts.failOn),
  );
  if (failedOn && opts.failOn) {
    console.error(
      color.red('✗') +
        ` fail-on ${opts.failOn}: max severity is ${riskSum.maxSeverity}` +
        ` (${riskSum.high}H/${riskSum.medium}M/${riskSum.low}L) — receipt written, exiting 2`,
    );
  }

  return { path: outPath, riskSum, failedOn, uncommitted };
}
