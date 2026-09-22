import { existsSync, readFileSync } from 'node:fs';
import { loadConfig } from '../lib/config.js';
import { color } from '../lib/color.js';
import { auditDisplayPath, recordAuditEvent } from '../lib/audit.js';
import { extractEmbeddedHash, verifyMarkdown } from '../lib/hash.js';
import { readIndexStrict, receiptsDir, type ReceiptIndex } from '../lib/receipt-index.js';
import { VERSION } from '../lib/version.js';
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

/** Identity fields shared with an audit line. No message and no diff body. */
export interface PruneIdentity {
  sha256: string | null;
  agent: string | null;
  redacted: boolean;
  verified: boolean | null;
  failedOn: false;
  exitCode: 0;
}

export interface PruneReport {
  ok: true;
  command: 'prune';
  version: string;
  exitCode: 0;
  dryRun: boolean;
  enabled: boolean;
  maxCount: number | null;
  maxAgeDays: number | null;
  deleted: Array<
    {
      path: string;
      reasons: string[];
      bytes: number;
    } & PruneIdentity
  >;
  kept: number;
  bytes: number;
  staleIndex: number;
  indexUpdated: boolean;
  /** Audit lines appended. Always 0 for dry-run and when nothing was deleted. */
  audited: number;
}

const EMPTY_IDENTITY: PruneIdentity = {
  sha256: null,
  agent: null,
  redacted: false,
  verified: null,
  failedOn: false,
  exitCode: 0,
};

function receiptIdentity(cwd: string, item: PruneCandidate, index: ReceiptIndex): PruneIdentity {
  const entry = index.receipts.find(
    (r) => r && typeof r.path === 'string' && auditDisplayPath(cwd, r.path) === item.rel,
  );
  const agent = typeof entry?.agent === 'string' && entry.agent ? entry.agent : null;
  const indexedHash = typeof entry?.sha256 === 'string' && entry.sha256 ? entry.sha256 : null;
  let text: string | null = null;
  try {
    if (existsSync(item.abs)) text = readFileSync(item.abs, 'utf8');
  } catch {
    text = null;
  }
  if (text == null) {
    return { ...EMPTY_IDENTITY, sha256: indexedHash, agent };
  }
  const embedded = extractEmbeddedHash(text);
  return {
    sha256: embedded || indexedHash,
    agent,
    redacted: text.includes('**Redacted**'),
    verified: verifyMarkdown(text).ok,
    failedOn: false,
    exitCode: 0,
  };
}

function toJsonDeleted(
  items: PruneCandidate[],
  meta: Map<string, PruneIdentity>,
): PruneReport['deleted'] {
  return items.map((d) => {
    const id = meta.get(d.rel) ?? EMPTY_IDENTITY;
    return {
      path: d.rel,
      reasons: [...d.reasons],
      bytes: d.bytes,
      sha256: id.sha256,
      agent: id.agent,
      redacted: id.redacted,
      verified: id.verified,
      failedOn: false,
      exitCode: 0,
    };
  });
}

/**
 * One audit line per receipt this run actually deletes.
 * The sibling `.json` is not a second event. Dry-run must not call this.
 */
function auditDeleted(
  cwd: string,
  items: PruneCandidate[],
  meta: Map<string, PruneIdentity>,
): number {
  let n = 0;
  for (const item of items) {
    const id = meta.get(item.rel) ?? EMPTY_IDENTITY;
    const wrote = recordAuditEvent(cwd, {
      event: 'prune',
      path: item.rel,
      sha256: id.sha256,
      agent: id.agent,
      redacted: id.redacted,
      verified: id.verified,
      failedOn: false,
      exitCode: 0,
    });
    if (wrote) n++;
  }
  return n;
}

/**
 * Delete old receipts under outDir and refresh index.json.
 * Opt-in: with no maxCount / maxAgeDays, deletes nothing (exit 0).
 * `--dry-run` lists the plan and does not delete, rewrite the index, or append audit.
 * An applied delete appends one `prune` line per receipt (not the sibling json).
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
      command: 'prune',
      version: VERSION,
      exitCode: 0,
      dryRun,
      enabled: false,
      maxCount: null,
      maxAgeDays: null,
      deleted: [],
      kept: 0,
      bytes: 0,
      staleIndex: 0,
      indexUpdated: false,
      audited: 0,
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
  const meta = new Map<string, PruneIdentity>();
  for (const item of plan.delete) meta.set(item.rel, receiptIdentity(cwd, item, index));

  if (dryRun) {
    const report: PruneReport = {
      ok: true,
      command: 'prune',
      version: VERSION,
      exitCode: 0,
      dryRun: true,
      enabled: true,
      maxCount: policy.maxCount,
      maxAgeDays: policy.maxAgeDays,
      deleted: toJsonDeleted(plan.delete, meta),
      kept: plan.keep.length,
      bytes,
      staleIndex: stale,
      indexUpdated: false,
      audited: 0,
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
  // Record deletes even if the index rewrite fails — the files are already gone.
  const audited = plan.delete.length ? auditDeleted(cwd, plan.delete, meta) : 0;
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
    command: 'prune',
    version: VERSION,
    exitCode: 0,
    dryRun: false,
    enabled: true,
    maxCount: policy.maxCount,
    maxAgeDays: policy.maxAgeDays,
    deleted: toJsonDeleted(plan.delete, meta),
    kept: plan.keep.length,
    bytes,
    staleIndex: stale,
    indexUpdated: removed > 0,
    audited,
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
    if (audited > 0) {
      console.log(
        color.dim(
          `audit.jsonl +${audited} prune event${audited === 1 ? '' : 's'} (no diff, no message).`,
        ),
      );
    }
  }
  return report;
}
