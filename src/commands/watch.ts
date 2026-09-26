import {
  isGitRepo,
  getHead,
  getBranch,
  dirtyFingerprint,
  isDirty,
} from '../lib/git.js';
import { cmdCapture, type CaptureOptions, type CaptureResult } from './capture.js';
import { color } from '../lib/color.js';
import type { FailOnThreshold } from '../lib/risk.js';
import { maybeAutoPrune } from '../lib/auto-prune.js';

export interface WatchOptions {
  /** Poll interval in seconds (default 5, min 1, max 3600). */
  interval?: number;
  /** Capture once after the next change, then exit. */
  once?: boolean;
  agent?: string;
  message?: string;
  failOn?: FailOnThreshold;
  json?: boolean;
  /** Honor config / `--redact` on each auto-capture. */
  redact?: boolean;
  /**
   * Honor config `sign: true` / `--sign` / `--no-sign` on each auto-capture.
   * Missing keys tip inside capture and do not exit 2.
   */
  sign?: boolean;
  /**
   * After each successful capture, run trusted prune when retention is
   * enabled. The inner capture does not prune; this command calls
   * `maybeAutoPrune` once the watch audit line is written. A broken chain
   * warns and does not change the watch exit code. A fail-on match skips
   * prune. Off by default.
   */
  autoPrune?: boolean;
  /**
   * Only watch HEAD commits (v0.4 behavior). Default watches dirty tree
   * (staged/unstaged/untracked) as well as new commits.
   */
  commitsOnly?: boolean;
}

export function clampInterval(n: number | undefined): number {
  if (n === undefined || !Number.isFinite(n)) return 5;
  return Math.min(3600, Math.max(1, Math.round(n)));
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve();
      return;
    }
    const t = setTimeout(resolve, ms);
    const onAbort = () => {
      clearTimeout(t);
      resolve();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Poll git HEAD (and optionally the dirty working tree) and auto-capture.
 *
 * Defaults: interval 5s, watch commits + dirty tree until Ctrl+C.
 * `--commits-only`: restore v0.4 HEAD-only behavior.
 * `--once`: wait for the next change, capture, exit.
 */
export async function cmdWatch(cwd: string, opts: WatchOptions = {}): Promise<number> {
  if (!isGitRepo(cwd)) {
    throw new Error(
      'Not a git repository. Run inside a git repo, or pass --cwd <path> to one.',
    );
  }

  const interval = clampInterval(opts.interval);
  const commitsOnly = Boolean(opts.commitsOnly);
  const ac = new AbortController();
  const onSig = () => {
    if (!ac.signal.aborted) {
      console.log('\n' + color.dim('Stopped watching.'));
      ac.abort();
    }
  };
  process.on('SIGINT', onSig);
  process.on('SIGTERM', onSig);

  let baseline = getHead(cwd);
  let baselineDirty = commitsOnly ? '' : dirtyFingerprint(cwd);
  const branch = getBranch(cwd);
  const short = baseline === '(no commits)' ? baseline : baseline.slice(0, 12);

  const mode = commitsOnly
    ? 'commits only (--commits-only)'
    : 'commits + dirty tree';

  if (opts.once) {
    console.log(
      color.bold('Waiting for the next change') +
        color.dim(` (poll ${interval}s, then capture + exit; ${mode})`),
    );
  } else {
    console.log(
      color.bold('Watching') +
        color.dim(` every ${interval}s — ${mode} — Ctrl+C to stop`),
    );
  }
  console.log(color.dim(`baseline: ${short} on ${branch}`));
  if (!commitsOnly) {
    console.log(
      color.dim(
        baselineDirty
          ? 'dirty tree present at start — will capture on next dirty change'
          : 'dirty tree: clean',
      ),
    );
  }
  console.log(
    color.dim(
      'Cursor / agent wrap-up: `agent-receipt watch --once --agent cursor`',
    ),
  );

  const finishCapture = (result: CaptureResult): number | undefined => {
    if (opts.autoPrune) {
      // Human stdout stays (watch --json only writes the companion file).
      // A fail-on match is a failed capture: skip prune, delete nothing.
      maybeAutoPrune(cwd, { enabled: true, json: false, failedRun: result.failedOn });
    }
    if (opts.once) return result.failedOn ? 2 : 0;
    if (result.failedOn) {
      console.log(
        color.yellow(
          'fail-on matched — receipt written; continuing to watch (use --once to exit).',
        ),
      );
    }
    return undefined;
  };

  try {
    while (!ac.signal.aborted) {
      await sleep(interval * 1000, ac.signal);
      if (ac.signal.aborted) return 0;

      const head = getHead(cwd);
      const headChanged = head !== baseline && head !== '(no commits)';

      if (headChanged) {
        const from = baseline === '(no commits)' ? '∅' : baseline.slice(0, 7);
        console.log('');
        console.log(
          color.cyan('HEAD') + ` ${from} → ${head.slice(0, 7)} — capturing`,
        );

        const captureOpts: CaptureOptions = {
          agent: opts.agent ?? 'watch',
          message: opts.message ?? `watch ${head.slice(0, 7)}`,
          failOn: opts.failOn,
          json: opts.json,
          redact: opts.redact,
          sign: opts.sign,
          audit: 'watch',
        };
        if (baseline !== '(no commits)') {
          captureOpts.since = baseline;
        } else {
          captureOpts.commits = 1;
        }

        let result: CaptureResult;
        try {
          result = cmdCapture(cwd, captureOpts);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(color.red('capture failed:') + ` ${msg}`);
          if (opts.once) return 1;
          baseline = head;
          if (!commitsOnly) baselineDirty = dirtyFingerprint(cwd);
          continue;
        }

        baseline = head;
        if (!commitsOnly) baselineDirty = dirtyFingerprint(cwd);
        const done = finishCapture(result);
        if (done !== undefined) return done;
        continue;
      }

      if (commitsOnly) continue;

      const dirty = dirtyFingerprint(cwd);
      if (!dirty || dirty === baselineDirty) continue;
      if (!isDirty(cwd)) {
        baselineDirty = '';
        continue;
      }

      console.log('');
      console.log(
        color.cyan('DIRTY') + ' working tree changed — capturing uncommitted',
      );

      const captureOpts: CaptureOptions = {
        uncommitted: true,
        agent: opts.agent ?? 'watch',
        message: opts.message ?? 'watch uncommitted',
        failOn: opts.failOn,
        json: opts.json,
        redact: opts.redact,
        sign: opts.sign,
        audit: 'watch',
      };

      let result: CaptureResult;
      try {
        result = cmdCapture(cwd, captureOpts);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(color.red('capture failed:') + ` ${msg}`);
        if (opts.once) return 1;
        baselineDirty = dirtyFingerprint(cwd);
        continue;
      }

      baselineDirty = dirtyFingerprint(cwd);
      const done = finishCapture(result);
      if (done !== undefined) return done;
    }
    return 0;
  } finally {
    process.off('SIGINT', onSig);
    process.off('SIGTERM', onSig);
  }
}
