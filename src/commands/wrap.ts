import { readFileSync } from 'node:fs';
import { cmdCapture } from './capture.js';
import { cmdVerify } from './verify.js';
import { isDirty, isGitRepo } from '../lib/git.js';
import { parseFailOn, type FailOnThreshold } from '../lib/risk.js';
import { color } from '../lib/color.js';

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
 */
export function cmdWrap(cwd: string, opts: WrapOptions = {}): WrapResult {
  if (!isGitRepo(cwd)) {
    throw new Error(
      'Not a git repository. Run inside a git repo, or pass --cwd <path> to one.',
    );
  }

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
    console.log(color.dim('wrap: working tree dirty → capture --uncommitted'));
  } else if (opts.base) {
    console.log(
      color.dim(
        `wrap: capture --base ${opts.base}` +
          (dirty ? ' (dirty tree ignored; --base set)' : ''),
      ),
    );
  } else {
    console.log(color.dim('wrap: clean tree → capture'));
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
  });

  // Prefer TL;DR from written file (authoritative)
  let tldr = capture.tldr;
  try {
    const md = readFileSync(capture.path, 'utf8');
    const m = md.match(/> \*\*TL;DR\*\*\s+(.+)/);
    if (m?.[1]) tldr = m[1].trim();
  } catch {
    /* keep capture.tldr */
  }

  console.log('');
  console.log(color.bold('TL;DR') + `  ${tldr}`);
  console.log(color.bold('path') + `   ${capture.path}`);
  console.log('');

  const verified = cmdVerify(cwd, capture.path);
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
