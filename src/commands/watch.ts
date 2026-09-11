import { isGitRepo, getHead, getBranch } from '../lib/git.js';
import { cmdCapture, type CaptureOptions, type CaptureResult } from './capture.js';
import { color } from '../lib/color.js';
import type { FailOnThreshold } from '../lib/risk.js';

export interface WatchOptions {
  /** Poll interval in seconds (default 5, min 1, max 3600). */
  interval?: number;
  /** Capture once after the next HEAD change, then exit. */
  once?: boolean;
  agent?: string;
  message?: string;
  failOn?: FailOnThreshold;
  json?: boolean;
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
 * Poll git HEAD and auto-capture when it changes.
 *
 * Defaults: interval 5s, keep watching until Ctrl+C.
 * `--once`: wait for the next commit, capture, exit (Cursor / agent "run after session").
 */
export async function cmdWatch(cwd: string, opts: WatchOptions = {}): Promise<number> {
  if (!isGitRepo(cwd)) {
    throw new Error(
      'Not a git repository. Run inside a git repo, or pass --cwd <path> to one.',
    );
  }

  const interval = clampInterval(opts.interval);
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
  const branch = getBranch(cwd);
  const short = baseline === '(no commits)' ? baseline : baseline.slice(0, 12);

  if (opts.once) {
    console.log(
      color.bold('Waiting for the next commit') +
        color.dim(` (poll ${interval}s, then capture + exit)`),
    );
  } else {
    console.log(
      color.bold('Watching git HEAD') +
        color.dim(` every ${interval}s — Ctrl+C to stop`),
    );
  }
  console.log(color.dim(`baseline: ${short} on ${branch}`));
  console.log(
    color.dim(
      'Cursor / agent wrap-up: `agent-receipt watch --once --agent cursor`',
    ),
  );

  try {
    while (!ac.signal.aborted) {
      await sleep(interval * 1000, ac.signal);
      if (ac.signal.aborted) return 0;

      const head = getHead(cwd);
      if (head === baseline) continue;
      if (head === '(no commits)') continue;

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
        continue;
      }

      baseline = head;
      if (opts.once) return result.failedOn ? 2 : 0;
      if (result.failedOn) {
        console.log(
          color.yellow(
            'fail-on matched — receipt written; continuing to watch (use --once to exit).',
          ),
        );
      }
    }
    return 0;
  } finally {
    process.off('SIGINT', onSig);
    process.off('SIGTERM', onSig);
  }
}
