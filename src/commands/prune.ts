import { loadConfig } from '../lib/config.js';
import { color } from '../lib/color.js';
import { readIndexStrict, receiptsDir } from '../lib/receipt-index.js';
import {
  assertPruneOutDir,
  deletePlanned,
  formatBytes,
  listReceiptFiles,
  planRetention,
  policyLabel,
  receiptBytes,
  refreshIndexAfterPrune,
  resolveRetentionPolicy,
  staleIndexCount,
  type PruneCandidate,
} from '../lib/retention.js';

export interface PruneOptions {
  dryRun?: boolean;
  /** CLI override. Omit to use config. */
  maxCount?: number;
  maxAgeDays?: number;
  json?: boolean;
}

export interface PruneReport {
  ok: true;
  dryRun: boolean;
  enabled: boolean;
  maxCount: number | null;
  maxAgeDays: number | null;
  deleted: Array<{ path: string; reasons: string[]; bytes: number }>;
  kept: number;
  bytes: number;
  staleIndex: number;
  indexUpdated: boolean;
}

function toJsonDeleted(items: PruneCandidate[]): PruneReport['deleted'] {
  return items.map((d) => ({
    path: d.rel,
    reasons: [...d.reasons],
    bytes: d.bytes,
  }));
}

/**
 * Delete old receipts under outDir and refresh index.json.
 * Opt-in: with no maxCount / maxAgeDays, deletes nothing (exit 0).
 * `--dry-run` lists the plan and does not delete or rewrite the index.
 * Exit 0 ok, exit 1 (thrown) on invalid config, unsafe outDir, or a broken index.
 */
export function cmdPrune(cwd: string, opts: PruneOptions = {}): PruneReport {
  const cfg = loadConfig(cwd);
  if (cfg.retentionInvalid?.length) {
    throw new Error(cfg.retentionInvalid.join('; '));
  }
  const policy = resolveRetentionPolicy(cfg, {
    maxCount: opts.maxCount,
    maxAgeDays: opts.maxAgeDays,
  });
  const dryRun = Boolean(opts.dryRun);

  if (!policy.enabled) {
    const report: PruneReport = {
      ok: true,
      dryRun,
      enabled: false,
      maxCount: null,
      maxAgeDays: null,
      deleted: [],
      kept: 0,
      bytes: 0,
      staleIndex: 0,
      indexUpdated: false,
    };
    if (opts.json) {
      console.log(JSON.stringify(report));
    } else {
      console.log(color.bold('agent-receipt prune') + color.dim(dryRun ? ' (dry-run)' : ''));
      console.log('Retention is opt-in. Nothing deleted.');
      console.log(
        'Set maxCount and/or maxAgeDays in .agent-receipt.yml, or pass --max-count / --max-age-days.',
      );
      console.log(color.dim('Preview with: agent-receipt prune --dry-run'));
    }
    return report;
  }

  assertPruneOutDir(cwd, receiptsDir(cwd));
  const { index } = readIndexStrict(cwd);
  const files = listReceiptFiles(cwd, index);
  const plan = planRetention(files, policy);
  const stale = staleIndexCount(cwd, index);
  const bytes = plan.delete.reduce((n, d) => n + d.bytes, 0);

  if (dryRun) {
    const report: PruneReport = {
      ok: true,
      dryRun: true,
      enabled: true,
      maxCount: policy.maxCount,
      maxAgeDays: policy.maxAgeDays,
      deleted: toJsonDeleted(plan.delete),
      kept: plan.keep.length,
      bytes,
      staleIndex: stale,
      indexUpdated: false,
    };
    if (opts.json) {
      console.log(JSON.stringify(report));
    } else {
      console.log(color.bold('agent-receipt prune') + color.dim(' (dry-run)'));
      console.log(color.dim(policyLabel(policy)));
      if (!plan.delete.length) {
        console.log(`Would delete 0 receipt(s). ${plan.keep.length} kept (${formatBytes(receiptBytes(files))}).`);
      } else {
        console.log(
          `Would delete ${plan.delete.length} receipt(s), ${formatBytes(bytes)}:`,
        );
        for (const item of plan.delete) {
          const extra = item.jsonRel ? ' +json' : '';
          console.log(`  ${item.rel}${extra}  ${item.reasons.join('+')}`);
        }
        console.log(`Kept ${plan.keep.length}.`);
      }
      if (stale) {
        console.log(
          color.dim(
            `${stale} stale index entr${stale === 1 ? 'y' : 'ies'} would be dropped.`,
          ),
        );
      }
      console.log('Nothing deleted.');
    }
    return report;
  }

  deletePlanned(cwd, plan.delete);
  let removed = 0;
  try {
    removed = refreshIndexAfterPrune(cwd, index);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `receipts were deleted but index.json was not updated (${msg}). Re-run prune to refresh the index.`,
    );
  }

  const report: PruneReport = {
    ok: true,
    dryRun: false,
    enabled: true,
    maxCount: policy.maxCount,
    maxAgeDays: policy.maxAgeDays,
    deleted: toJsonDeleted(plan.delete),
    kept: plan.keep.length,
    bytes,
    staleIndex: stale,
    indexUpdated: removed > 0,
  };
  if (opts.json) {
    console.log(JSON.stringify(report));
  } else {
    console.log(color.bold('agent-receipt prune'));
    console.log(color.dim(policyLabel(policy)));
    if (!plan.delete.length) {
      console.log(`Deleted 0 receipt(s). ${plan.keep.length} kept.`);
    } else {
      console.log(
        color.green('✓') +
          ` Deleted ${plan.delete.length} receipt(s), ${formatBytes(bytes)}. Kept ${plan.keep.length}.`,
      );
    }
    if (removed > 0) {
      console.log(color.dim(`index.json updated (${removed} entr${removed === 1 ? 'y' : 'ies'} removed).`));
    } else {
      console.log(color.dim('index.json unchanged.'));
    }
  }
  return report;
}
