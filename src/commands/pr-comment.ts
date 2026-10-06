/**
 * `pr-comment` runs a receipt gate and renders one Markdown summary.
 * `--dry-run` and `--out` print or write that summary. Otherwise it posts
 * the summary to the pull request, updating the sticky comment that carries
 * the HTML marker. Comment failures do not change the gate exit code.
 * The GitHub token is never printed.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { VERSION } from '../lib/version.js';
import { parseFailOn, type FailOnThreshold } from '../lib/risk.js';
import { scrubSecrets } from '../lib/pr-summary.js';
import {
  CommentPostError,
  evaluateGate,
  loadPolicyFile,
  publishComment,
  renderRedactedSummary,
  resolveCommentContext,
  shouldPostComment,
  writeStepSummary,
  type CommentMode,
  type CommentWhen,
  type PrCommandMode,
} from '../lib/pr-summary.js';

export interface PrCommentOptions {
  command: PrCommandMode;
  receipts?: string;
  failOn?: FailOnThreshold;
  policy?: string;
  requireSignature: boolean;
  certificateIdentity?: string;
  certificateIdentityRegexp?: string;
  certificateOidcIssuer?: string;
  trustedRoot?: string;
  comment: CommentWhen;
  commentMode: CommentMode;
  dryRun: boolean;
  out?: string;
  json: boolean;
  repo?: string;
  pr?: number;
  apiUrl?: string;
  eventPath?: string;
}

export function printPrCommentError(message: string): void {
  const reason = scrubSecrets(message, process.env.GITHUB_TOKEN);
  console.log(
    JSON.stringify({
      ok: false,
      command: 'pr-comment',
      version: VERSION,
      exitCode: 1,
      verdict: 'fail',
      reason,
      commentUrl: null,
      summary: null,
    }),
  );
}

function warn(message: string, token: string | undefined): void {
  console.error(`warn: ${scrubSecrets(message, token)}`);
}

export async function cmdPrComment(cwd: string, opts: PrCommentOptions): Promise<number> {
  const token = process.env.GITHUB_TOKEN;
  let failOn = opts.failOn;
  let requireSignature = opts.requireSignature;
  let policyPath: string | undefined;
  if (opts.policy) {
    const policy = loadPolicyFile(cwd, opts.policy);
    policyPath = policy.path;
    if (!failOn && policy.failOn) failOn = policy.failOn;
    if (policy.requireSignature) requireSignature = true;
  }
  if (opts.command === 'gate' && !failOn) failOn = parseFailOn('high');

  const summary = evaluateGate(cwd, {
    command: opts.command,
    receipts: opts.receipts,
    failOn: opts.command === 'attest-verify' ? undefined : failOn,
    policyPath,
    requireSignature,
    certificateIdentity: opts.certificateIdentity,
    certificateIdentityRegexp: opts.certificateIdentityRegexp,
    certificateOidcIssuer: opts.certificateOidcIssuer,
    trustedRoot: opts.trustedRoot,
  });
  if (opts.command === 'attest-verify' && failOn) summary.failOn = failOn;

  const markdown = renderRedactedSummary(summary, token);
  let exitCode: number = summary.exitCode;
  let commentUrl: string | null = null;
  let commentUpdated = false;
  let commentCreated = false;
  let warning: string | null = null;

  if (opts.out) {
    try {
      writeFileSync(resolve(cwd, opts.out), markdown.endsWith('\n') ? markdown : `${markdown}\n`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      warning = `could not write --out (${message})`;
      warn(warning, token);
      if (exitCode === 0) exitCode = 1;
    }
  }

  try {
    writeStepSummary(markdown);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    warning = warning || `could not write GITHUB_STEP_SUMMARY (${message})`;
    warn(warning, token);
  }

  if (shouldPostComment(opts.comment, summary.verdict, opts.dryRun)) {
    try {
      const ctx = resolveCommentContext(process.env, {
        repo: opts.repo,
        pr: opts.pr,
        apiUrl: opts.apiUrl,
        eventPath: opts.eventPath,
        token,
      });
      const posted = await publishComment(ctx, markdown, opts.commentMode);
      commentUrl = posted.url;
      commentUpdated = posted.updated;
      commentCreated = posted.created;
    } catch (err) {
      if (err instanceof CommentPostError && (err.status === 403 || err.status === 404)) {
        warning =
          `GitHub API returned ${err.status}. ` +
          'The token cannot comment on this pull request (fork PRs are often read-only). ' +
          'Wrote the summary to the step summary instead. The gate verdict is unchanged.';
        warn(warning, token);
      } else if (err instanceof CommentPostError) {
        warning = `${err.message}. The gate verdict is unchanged.`;
        warn(warning, token);
      } else {
        const message = err instanceof Error ? err.message : String(err);
        warning = scrubSecrets(message, token);
        console.error(`Error: ${warning}`);
        if (exitCode === 0) exitCode = 1;
      }
    }
  }

  const report = {
    ok: summary.ok && exitCode === 0,
    command: 'pr-comment',
    mode: summary.mode,
    version: VERSION,
    exitCode,
    verdict: summary.verdict,
    risk: summary.risk,
    receiptsCount: summary.receiptsCount,
    failedOn: summary.verdict === 'fail' && summary.exitCode === 2,
    failOn: summary.failOn,
    policy: summary.policyPath,
    policyHits: summary.policyHits,
    signature: summary.signature,
    hashChainHead: summary.hashChainHead,
    hashChainOk: summary.hashChainOk,
    sharePackages: summary.sharePackages,
    summaryPath: opts.out ? resolve(cwd, opts.out) : null,
    commentUrl,
    commentUpdated,
    commentCreated,
    warning,
    reason: summary.reason,
    summary: markdown,
  };

  if (opts.json) {
    console.log(JSON.stringify(report));
  } else if (opts.dryRun) {
    console.log(markdown);
  } else {
    console.log(`verdict ${summary.verdict}`);
    console.log(`receipts ${summary.receiptsCount}`);
    console.log(`risk ${summary.risk.maxSeverity ?? 'none'}`);
    if (commentUrl) console.log(`comment ${commentUrl}`);
  }
  return exitCode;
}
