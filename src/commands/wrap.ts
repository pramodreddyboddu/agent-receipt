import { cmdCapture } from './capture.js';
import { cmdVerify } from './verify.js';
import { isDirty, isGitRepo } from '../lib/git.js';
import { parseFailOn, type FailOnThreshold } from '../lib/risk.js';
import { color } from '../lib/color.js';
import {
  emitLine,
  failOnReason,
  finalizeGate,
  printGate,
  riskToGate,
} from '../lib/gate.js';

export interface WrapOptions {
  agent?: string;
  message?: string;
  failOn?: FailOnThreshold;
  /** Prefer commits vs this base when tree is clean. */
  base?: string;
  redact?: boolean;
  json?: boolean;
  full?: boolean;
  /** Force uncommitted even if also passing base (rejected by capture). */
  uncommitted?: boolean;
}

export interface WrapResult {
  path: string;
  tldr: string;
  verified: boolean;
  failedOn: boolean;
  uncommitted: boolean;
}

/**
 * One-shot end-of-session: capture (+ --uncommitted if dirty) → print TL;DR +
 * path → verify. Exit codes mirror capture/verify (2 on fail-on or verify fail).
 * `--json` writes the companion receipt JSON and prints one CI gate on stdout.
 */
export function cmdWrap(cwd: string, opts: WrapOptions = {}): WrapResult {
  if (!isGitRepo(cwd)) {
    throw new Error(
      'Not a git repository. Run inside a git repo, or pass --cwd <path> to one.',
    );
  }

  const quiet = Boolean(opts.json);
  const say = (line: string) => emitLine(quiet, line);

  const dirty = isDirty(cwd);
  // Explicit --base/--uncommitted wins. Otherwise dirty trees auto-use --uncommitted.
  const useUncommitted = opts.uncommitted
    ? true
    : opts.base
      ? false
      : dirty;

  if (opts.uncommitted && !dirty) {
    throw new Error(
      'wrap --uncommitted requires a dirty working tree (nothing to snapshot).',
    );
  }

  if (useUncommitted) {
    say(color.dim('wrap: working tree dirty → capture --uncommitted'));
  } else if (opts.base) {
    say(
      color.dim(
        `wrap: capture --base ${opts.base}` +
          (dirty ? ' (dirty tree ignored; --base set)' : ''),
      ),
    );
  } else {
    say(color.dim('wrap: clean tree → capture'));
  }

  const capture = cmdCapture(cwd, {
    uncommitted: useUncommitted,
    base: useUncommitted ? undefined : opts.base,
    agent: opts.agent ?? 'wrap',
    message: opts.message ?? 'session wrap',
    failOn: opts.failOn,
    redact: opts.redact,
    json: opts.json,
    full: opts.full,
    quiet,
    emitGate: false,
  });

  let tldr = capture.tldr;
  // TL;DR already read inside capture from the written body.
  if (!quiet) {
    console.log('');
    console.log(color.bold('TL;DR') + `  ${tldr}`);
    console.log(color.bold('path') + `   ${capture.path}`);
    console.log('');
  }

  const verifiedReport = cmdVerify(cwd, capture.path, { quiet });
  const verified = verifiedReport.ok;

  if (opts.json) {
    const reason = !verified
      ? verifiedReport.reason || 'verify failed'
      : capture.failedOn
        ? failOnReason(opts.failOn, capture.riskSum.maxSeverity)
        : null;
    printGate(
      finalizeGate({
        command: 'wrap',
        verified,
        failedOn: capture.failedOn,
        failOn: opts.failOn ?? null,
        redacted: capture.redacted,
        uncommitted: capture.uncommitted,
        path: capture.path,
        jsonPath: capture.jsonPath,
        htmlPath: null,
        markdownPath: null,
        tldr,
        sha256: verifiedReport.sha256 || capture.sha256,
        risk: riskToGate(capture.riskSum),
        ignored: capture.ignored,
        reason,
      }),
    );
  }

  return {
    path: capture.path,
    tldr,
    verified,
    failedOn: capture.failedOn,
    uncommitted: capture.uncommitted,
  };
}

/** Re-export for CLI convenience. */
export { parseFailOn };
