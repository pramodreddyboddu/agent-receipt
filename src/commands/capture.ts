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
import { prepareRedactedBody } from '../lib/redact.js';
import { appendHashFooter, extractEmbeddedHash, verifyMarkdown } from '../lib/hash.js';
import { recordAuditEvent } from '../lib/audit.js';
import { VERSION } from '../lib/version.js';
import { color } from '../lib/color.js';
import {
  emitLine,
  failOnReason,
  finalizeGate,
  printGate,
  riskToGate,
} from '../lib/gate.js';

export interface CaptureOptions {
  since?: string;
  /** Summarize changes vs a base branch/ref (e.g. main); shows commits ahead. */
  base?: string;
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
  /** Mask high/secret findings in the written Markdown for safer sharing. */
  redact?: boolean;
  /** Send human progress to stderr (stdout reserved for a JSON gate). */
  quiet?: boolean;
  /**
   * Print one CI gate object on stdout. Implies quiet.
   * `json: true` still only means "also write the companion receipt .json"
   * unless this is set (the CLI sets both for `capture --json`).
   */
  emitGate?: boolean;
  /**
   * Append `.agent-receipt/audit.jsonl`. Default `capture`.
   * `false` when wrap records its own event. `watch` when watch is the
   * user-facing command (one line, not a second capture line).
   */
  audit?: false | 'capture' | 'watch';
}

export interface CaptureResult {
  path: string;
  riskSum: RiskSummary;
  failedOn: boolean;
  uncommitted: boolean;
  /** One-line TL;DR from the written receipt (pre-redaction summary when redacted). */
  tldr: string;
  redacted: boolean;
  ignored: number;
  jsonPath: string | null;
  sha256: string | null;
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

  if (uncommitted && (opts.base || opts.since)) {
    throw new Error(
      'Cannot combine --uncommitted with --base / --since.\n' +
        'Omit --uncommitted to capture commits vs a base, or omit --base/--since for a dirty-tree snapshot.',
    );
  }

  let commitsAhead: number | undefined;

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
    const range = resolveRange(cwd, {
      since: opts.since,
      commits: commitsN,
      base: opts.base,
    });
    const allFiles = getChangedFiles(cwd, range.base, range.head);
    const filtered = filterIgnored(allFiles, cfg.ignore);
    files = filtered.kept;
    ignored = filtered.ignored;
    rangeLabel = range.label;
    base = range.base;
    commitsAhead = range.commitsAhead;
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
  const failedOn = Boolean(
    opts.failOn && meetsFailOn(riskSum.maxSeverity, opts.failOn),
  );

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

  let markdown = formatMarkdown(data, {
    full,
    diffStat: opts.diffStat,
    topRisks: opts.topRisks,
  });
  const redacted = Boolean(opts.redact);
  if (redacted) {
    markdown = appendHashFooter(prepareRedactedBody(markdown));
  }
  const quiet = Boolean(opts.quiet || opts.emitGate);
  const say = (line: string) => emitLine(quiet, line);

  // TL;DR from the (possibly redacted) receipt blockquote
  const tldrMatch = markdown.match(/> \*\*TL;DR\*\*\s+(.+)/);
  const tldr =
    tldrMatch?.[1]?.trim() ||
    `${agent || 'agent'} · ${data.files.length} files · range ${rangeLabel}`;

  let outPath: string;
  if (opts.out) {
    outPath = resolve(cwd, opts.out);
    mkdirSync(dirname(outPath), { recursive: true });
  } else {
    const dir = ensureOutDir(cwd, cfg.outDir);
    outPath = join(dir, defaultReceiptFilename());
  }

  writeFileSync(outPath, markdown, 'utf8');

  let jsonPath: string | null = null;
  if (opts.json) {
    jsonPath = outPath.replace(/\.md$/i, '') + '.json';
    writeFileSync(
      jsonPath,
      JSON.stringify(formatJson(data, markdown, failedOn), null, 2) + '\n',
      'utf8',
    );
    say(color.dim(`Wrote JSON:    ${jsonPath}`));
  }

  const ins = files.reduce((a, f) => a + f.insertions, 0);
  const del = files.reduce((a, f) => a + f.deletions, 0);

  try {
    const indexed = updateIndexOnCapture(cwd, {
      outPath,
      timestamp: data.timestamp,
      agent: data.agent,
      message: data.message,
      head: data.head,
      branch: data.branch,
      uncommitted,
      failedOn,
      files: files.length,
      insertions: ins,
      deletions: del,
      risks,
      markdown,
    });
    if (!indexed && opts.out) {
      say(
        color.dim(
          '  (index unchanged: --out path is outside outDir, so history/newest stay on outDir receipts)',
        ),
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    say(color.dim(`  (index update skipped: ${msg})`));
  }

  say(color.green('✓') + ` Wrote receipt: ${outPath}`);
  const scope = uncommitted ? 'uncommitted' : rangeLabel;
  say(
    `  ${files.length} file(s), +${ins}/−${del}, ${risks.length} risk hint(s)` +
      (riskSum.maxSeverity ? ` [max: ${riskSum.maxSeverity}]` : '') +
      `, range ${scope}`,
  );
  if (typeof commitsAhead === 'number' && (opts.base || opts.since)) {
    say(
      `  ${commitsAhead} commit(s) ahead` +
        (opts.base || opts.since ? ` of ${opts.base || opts.since}` : ''),
    );
  }
  if (uncommitted) {
    say(color.yellow('  ⚠ Snapshot is uncommitted (working tree, not HEAD).'));
  }
  if (redacted) {
    say(color.yellow('  ⚠ Receipt redacted — high/secret findings masked.'));
  }
  if (ignored.length) {
    say(
      color.dim(
        `  ignored ${ignored.length} path(s) via config ignore globs (noise)`,
      ),
    );
  }
  if (cfg.riskAllowlist.length) {
    say(
      color.dim(
        `  riskAllowlist active (${cfg.riskAllowlist.length} rule(s))`,
      ),
    );
  }
  if (riskSum.high > 0) {
    say(
      color.yellow(
        `  ⚠ ${riskSum.high} high-severity risk hint(s) — review before trusting this session.`,
      ),
    );
  }

  if (failedOn && opts.failOn) {
    console.error(
      color.red('✗') +
        ` fail-on ${opts.failOn}: max severity is ${riskSum.maxSeverity}` +
        ` (${riskSum.high}H/${riskSum.medium}M/${riskSum.low}L) — receipt written, exiting 2`,
    );
  }

  const sha256 = extractEmbeddedHash(markdown);
  const verified = verifyMarkdown(markdown).ok;
  if (opts.audit !== false) {
    const exitCode = failedOn ? 2 : 0;
    recordAuditEvent(cwd, {
      event: opts.audit === 'watch' ? 'watch' : 'capture',
      path: outPath,
      sha256,
      agent,
      redacted,
      verified,
      failedOn,
      exitCode,
    });
  }
  if (opts.emitGate) {
    printGate(
      finalizeGate({
        command: 'capture',
        verified: null,
        failedOn,
        failOn: opts.failOn ?? null,
        redacted,
        uncommitted,
        path: outPath,
        jsonPath,
        htmlPath: null,
        markdownPath: null,
        tldr,
        sha256,
        risk: riskToGate(riskSum),
        ignored: ignored.length,
        reason: failedOn ? failOnReason(opts.failOn, riskSum.maxSeverity) : null,
      }),
    );
  }

  return {
    path: outPath,
    riskSum,
    failedOn,
    uncommitted,
    tldr,
    redacted,
    ignored: ignored.length,
    jsonPath,
    sha256,
  };
}
