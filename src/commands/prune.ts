import { existsSync, readFileSync } from 'node:fs';
import { loadConfig } from '../lib/config.js';
import { color } from '../lib/color.js';
import { auditDisplayPath, auditLogPath, recordAuditEvent, verifyAuditChain } from '../lib/audit.js';
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
  /**
   * Skip the audit-chain trust gate. Deletes even when `.agent-receipt/audit.jsonl`
   * is present and `verifyAuditChain` fails.
   */
  force?: boolean;
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
  ok: boolean;
  command: 'prune';
  version: string;
  exitCode: 0 | 1;
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
  /** True when `.agent-receipt/audit.jsonl` exists. Absence is not a failure. */
  auditPresent: boolean;
  /**
   * Result of `verifyAuditChain` when the log exists. Null when the log is absent.
   * False refuses the delete unless `--force` was passed.
   */
  chainOk: boolean | null;
  /** Set when trusted prune refuses. Null when the run is allowed. */
  reason: string | null;
  /** True when `--force` skipped a broken audit chain and the run continued. */
  forced: boolean;
}

interface AuditTrust {
  auditPresent: boolean;
  chainOk: boolean | null;
  /** Short break description, set only when the chain is broken. */
  detail: string | null;
}

function auditTrust(cwd: string): AuditTrust {
  if (!existsSync(auditLogPath(cwd))) {
    return { auditPresent: false, chainOk: null, detail: null };
  }
  const chain = verifyAuditChain(cwd);
  if (chain.ok) return { auditPresent: true, chainOk: true, detail: null };
  const where = chain.brokenAt != null ? ` at line ${chain.brokenAt}` : '';
  const why = chain.reason ? ` (${chain.reason})` : '';
  return {
    auditPresent: true,
    chainOk: false,
    detail: `audit chain broken${where}${why}`,
  };
}

function refusalReason(detail: string): string {
  return `trusted prune refused: ${detail}. Nothing was deleted. Pass --force to delete anyway.`;
}

function emitReport(report: PruneReport, json: boolean | undefined, human: () => void): PruneReport {
  if (json) {
    console.log(JSON.stringify(report));
    if (!report.ok && report.reason) console.error(report.reason);
    else if (report.forced) {
      console.error('warn: --force skipped the audit trust gate (chain broken).');
    }
  } else {
    human();
  }
  return report;
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
 * Trusted prune: when `.agent-receipt/audit.jsonl` exists, `verifyAuditChain`
 * must pass before any delete. A broken chain exits 1, deletes nothing, and
 * appends no audit line (dry-run included). A missing log is fine.
 * `--force` skips that gate. `--dry-run` lists the plan and does not delete,
 * rewrite the index, or append audit.
 * An applied delete appends one `prune` line per receipt (not the sibling json).
 * Exit 0 ok, exit 1 on a broken audit chain, invalid config, unsafe outDir,
 * or a broken index.
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
  const trust = auditTrust(cwd);
  const skippedBroken = Boolean(opts.force) && trust.chainOk === false;

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
      auditPresent: trust.auditPresent,
      chainOk: trust.chainOk,
      reason: null,
      forced: false,
    };
    return emitReport(report, opts.json, () => {
      console.log(color.bold('agent-receipt prune') + color.dim(dryRun ? ' (dry-run)' : ''));
      console.log('Retention is opt-in. Nothing deleted.');
      console.log(
        'Set maxCount and/or maxAgeDays in .agent-receipt.yml, or pass --max-count / --max-age-days.',
      );
      console.log(color.dim('Preview with: agent-receipt prune --dry-run'));
    });
  }

  assertPruneOutDir(cwd, receiptsDir(cwd));
  const { index } = readIndexStrict(cwd);
  const files = listReceiptFiles(cwd, index);
  const plan = planRetention(files, policy);
  const stale = staleIndexCount(cwd, index);
  const bytes = plan.delete.reduce((n, d) => n + d.bytes, 0);
  const meta = new Map<string, PruneIdentity>();
  for (const item of plan.delete) meta.set(item.rel, receiptIdentity(cwd, item, index));

  if (trust.chainOk === false && !opts.force) {
    const report: PruneReport = {
      ok: false,
      command: 'prune',
      version: VERSION,
      exitCode: 1,
      dryRun,
      enabled: true,
      maxCount: policy.maxCount,
      maxAgeDays: policy.maxAgeDays,
      deleted: toJsonDeleted(plan.delete, meta),
      kept: plan.keep.length,
      bytes,
      staleIndex: stale,
      indexUpdated: false,
      audited: 0,
      auditPresent: true,
      chainOk: false,
      reason: refusalReason(trust.detail ?? 'audit chain broken'),
      forced: false,
    };
    return emitReport(report, opts.json, () => {
      const suffix = dryRun ? ' (dry-run)' : '';
      console.log(color.bold('agent-receipt prune') + color.dim(suffix));
      console.log(color.dim(policyLabel(policy)));
      console.log(color.red('✗') + ' ' + report.reason);
      if (plan.delete.length) {
        console.log('Plan (not applied — trust failed):');
        for (const item of plan.delete) {
          const extra = item.jsonRel ? ' +json' : '';
          console.log(`  ${item.rel}${extra}  ${item.reasons.join('+')}`);
        }
      } else {
        console.log('No receipts matched the limits. Trust still failed, so this is not a clean prune.');
      }
      console.log('Nothing deleted.');
    });
  }

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
      auditPresent: trust.auditPresent,
      chainOk: trust.chainOk,
      reason: null,
      forced: skippedBroken,
    };
    return emitReport(report, opts.json, () => {
      console.log(color.bold('agent-receipt prune') + color.dim(' (dry-run)'));
      console.log(color.dim(policyLabel(policy)));
      if (skippedBroken) {
        console.log(color.dim('warn: --force skipped the audit trust gate (chain broken).'));
      }
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
    });
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
    auditPresent: trust.auditPresent,
    chainOk: trust.chainOk,
    reason: null,
    forced: skippedBroken,
  };
  return emitReport(report, opts.json, () => {
    console.log(color.bold('agent-receipt prune'));
    console.log(color.dim(policyLabel(policy)));
    if (skippedBroken) {
      console.log(color.dim('warn: --force skipped the audit trust gate (chain broken).'));
    }
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
  });
}
