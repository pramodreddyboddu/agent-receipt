import { color } from './color.js';
import { emitLine } from './gate.js';
import { cmdPrune, type PruneReport } from '../commands/prune.js';

/**
 * Why an attempted auto-prune deleted nothing, or null when trusted prune ran
 * (including a run that deleted zero receipts because nothing was over the limit).
 * `disabled` is not written onto the gate: callers omit the fields entirely.
 */
export type AutoPruneReason = 'disabled' | 'retention-off' | 'chain-broken' | 'error' | null;

export interface AutoPruneResult {
  /** True when this run called trusted prune. False when auto-prune was off. */
  attempted: boolean;
  /** Receipts actually deleted. Zero when skipped, off, or nothing matched. */
  pruned: number;
  reason: AutoPruneReason;
}

export interface AutoPruneOptions {
  /** Resolved for this run: `--no-prune` wins, then `--prune`, then config. */
  enabled: boolean;
  /**
   * When true, the short human line goes to stderr so stdout stays one JSON
   * object. Chain-break and error warnings always go to stderr.
   */
  json?: boolean;
}

/** Gate fields for capture / wrap `--json`. Omitted entirely when auto-prune was off. */
export function autoPruneGateFields(result: AutoPruneResult | undefined): {
  autoPrune?: boolean;
  pruned?: number;
  pruneReason?: string | null;
} {
  if (!result?.attempted) return {};
  return {
    autoPrune: true,
    pruned: result.pruned,
    pruneReason: result.reason,
  };
}

/**
 * After a successful capture, wrap, or watch write, run the same trusted
 * prune as `agent-receipt prune` (no `--force`, no dry-run).
 * Off, or on with no retention limit: deletes nothing and stays quiet.
 * A broken audit chain deletes nothing, warns on stderr, and does not throw.
 * Throws from prune (invalid retention, unsafe outDir, broken index) are
 * caught, warned, and do not fail the caller. Manual `prune` still exits 1.
 */
export function maybeAutoPrune(cwd: string, opts: AutoPruneOptions): AutoPruneResult {
  if (!opts.enabled) {
    return { attempted: false, pruned: 0, reason: 'disabled' };
  }
  const quiet = Boolean(opts.json);
  let report: PruneReport;
  try {
    report = cmdPrune(cwd, { silent: true, force: false, dryRun: false });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(
      color.yellow('warn:') +
        ` auto-prune failed (${msg}). The receipt just written is kept. Manual \`agent-receipt prune\` still exits 1.`,
    );
    return { attempted: true, pruned: 0, reason: 'error' };
  }
  if (!report.enabled) {
    return { attempted: true, pruned: 0, reason: 'retention-off' };
  }
  if (!report.ok || report.chainOk === false) {
    console.error(
      color.yellow('warn:') +
        ' auto-prune skipped (audit chain broken). Nothing was deleted. The receipt just written is kept. ' +
        'Fix the chain (`agent-receipt audit --verify`) or run `agent-receipt prune --force`.',
    );
    emitLine(quiet, 'pruned: skipped (audit chain broken)');
    return { attempted: true, pruned: 0, reason: 'chain-broken' };
  }
  const n = report.dryRun ? 0 : report.deleted.length;
  if (n > 0) {
    emitLine(quiet, `pruned: ${n} receipt${n === 1 ? '' : 's'}`);
  }
  return { attempted: true, pruned: n, reason: null };
}
