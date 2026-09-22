import {
  AUDIT_KINDS,
  auditLogPath,
  isAuditKind,
  loadAuditEvents,
  verifyAuditChain,
  type AuditEvent,
  type AuditKind,
} from '../lib/audit.js';
import { color } from '../lib/color.js';
import { VERSION } from '../lib/version.js';

export interface AuditOptions {
  json?: boolean;
  /**
   * Check the experimental hash chain. Exit 2 on mismatch.
   * Ignores --event, --agent, --failed, and --limit (whole file).
   */
  verify?: boolean;
  /** Newest N events of the filtered listing. Ignored by the chain check. */
  limit?: number;
  /**
   * Listing filter: capture | watch | wrap | share | export | prune.
   * Ignored by --verify (the chain check is the whole file).
   */
  event?: string;
  /**
   * Listing filter: exact, case-sensitive match on `agent`.
   * Events with `agent: null` do not match. Ignored by --verify.
   */
  agent?: string;
  /**
   * Listing filter: `failedOn === true` or `exitCode !== 0`.
   * Ignored by --verify.
   */
  failed?: boolean;
}

function requireAuditEvent(value: string | undefined): AuditKind | undefined {
  if (value === undefined) return undefined;
  if (isAuditKind(value)) return value;
  throw new Error(
    `--event must be one of: ${AUDIT_KINDS.join(', ')} (got ${JSON.stringify(value)}). ` +
      '--event filters the listing only; audit --verify always checks the whole chain.',
  );
}

function shortHash(value: string | null): string {
  if (!value) return '—';
  return value.slice(0, 12);
}

/**
 * Load order is the caller's job. This applies:
 * `--event` → `--agent` → `--failed` → `--limit` (newest N, file order kept).
 */
function applyAuditListingFilters(
  events: AuditEvent[],
  opts: { event?: AuditKind; agent?: string; failed?: boolean; limit?: number },
): AuditEvent[] {
  let filtered = events;
  if (opts.event) filtered = filtered.filter((ev) => ev.event === opts.event);
  if (opts.agent !== undefined) {
    const name = opts.agent;
    filtered = filtered.filter((ev) => ev.agent === name);
  }
  if (opts.failed) {
    filtered = filtered.filter((ev) => ev.failedOn === true || ev.exitCode !== 0);
  }
  if (opts.limit) filtered = filtered.slice(-opts.limit);
  return filtered;
}

function noteVerifyIgnoresFilters(
  event: AuditKind | undefined,
  agent: string | undefined,
  failed: boolean,
): void {
  if (event) {
    console.error(`--event ${event} is listing-only; --verify checks the whole chain.`);
  }
  if (agent !== undefined) {
    console.error(`--agent ${agent} is listing-only; --verify checks the whole chain.`);
  }
  if (failed) {
    console.error('--failed is listing-only; --verify checks the whole chain.');
  }
}

function limitScope(event: AuditKind | undefined, agent: string | undefined, failed: boolean): string {
  const parts: string[] = [];
  if (event) parts.push(event);
  if (agent !== undefined) parts.push(`agent=${agent}`);
  if (failed) parts.push('failed');
  return parts.length ? ` ${parts.join(' ')}` : '';
}

function emptyListingMessage(
  total: number,
  event: AuditKind | undefined,
  agent: string | undefined,
  failed: boolean,
): string {
  const other = `${total} other event${total === 1 ? '' : 's'} in the log`;
  if (event && agent === undefined && !failed) {
    return `No ${event} events (${other}).`;
  }
  const parts: string[] = [];
  if (event) parts.push(`event=${event}`);
  if (agent !== undefined) parts.push(`agent=${agent}`);
  if (failed) parts.push('failed');
  return `No events match ${parts.join(', ')} (${other}).`;
}

function formatEvent(ev: AuditEvent): string {
  const verified =
    ev.verified === true ? 'verified' : ev.verified === false ? 'UNVERIFIED' : 'verify=?';
  const redacted = ev.redacted ? 'redacted' : 'plain';
  const agent = ev.agent ? `  agent=${ev.agent}` : '';
  return (
    `${ev.ts}  ${ev.event.padEnd(7)}  exit=${ev.exitCode}  ${verified}  ${redacted}` +
    `  ${shortHash(ev.sha256)}  ${ev.path}${agent}`
  );
}

/**
 * Show or check `.agent-receipt/audit.jsonl`.
 * Exit 0 ok (including an empty filtered listing), 2 chain mismatch
 * (`--verify`), 1 unreadable log or a bad filter (thrown).
 *
 * Listing order: load → `--event` → `--agent` → `--failed` → `--limit`.
 */
export function cmdAudit(cwd: string, opts: AuditOptions = {}): number {
  const limit = opts.limit;
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) {
    throw new Error('--limit must be an integer >= 1');
  }
  const event = requireAuditEvent(opts.event);
  const agent = opts.agent;
  const failed = opts.failed === true;

  if (opts.verify) {
    noteVerifyIgnoresFilters(event, agent, failed);
    const chain = verifyAuditChain(cwd);
    if (opts.json) {
      console.log(
        JSON.stringify({
          ok: chain.ok,
          command: 'audit',
          version: VERSION,
          events: chain.events,
          brokenAt: chain.brokenAt,
          reason: chain.reason,
          experimental: true,
          path: auditLogPath(cwd),
        }),
      );
    } else if (chain.ok) {
      console.log(
        color.green('audit chain OK') +
          ` — ${chain.events} event${chain.events === 1 ? '' : 's'} in ${auditLogPath(cwd)}`,
      );
      console.log(
        color.dim(
          'experimental hash chain (prev = sha256 of the previous line). Not a signature.',
        ),
      );
    } else {
      const where = chain.brokenAt ? ` at line ${chain.brokenAt}` : '';
      console.error(color.red('audit chain broken') + `${where}: ${chain.reason}`);
    }
    return chain.ok ? 0 : 2;
  }

  const events = loadAuditEvents(cwd);
  const filtered = applyAuditListingFilters(events, { event, agent, failed });
  const shown = applyAuditListingFilters(events, { event, agent, failed, limit });

  if (opts.json) {
    console.log(JSON.stringify(shown));
    return 0;
  }

  console.log(color.bold('agent-receipt audit') + color.dim('  (experimental — not a signature)'));
  console.log(color.dim(auditLogPath(cwd)));
  if (event) {
    console.log(
      color.dim(`event filter: ${event} (listing only; --verify checks the whole chain)`),
    );
  }
  if (agent !== undefined) {
    console.log(
      color.dim(
        `agent filter: ${agent} (exact match; agent null does not match; listing only)`,
      ),
    );
  }
  if (failed) {
    console.log(
      color.dim(
        'failed filter: failedOn or nonzero exitCode (listing only; --verify checks the whole chain)',
      ),
    );
  }
  if (!shown.length) {
    if (!events.length) {
      console.log(
        'No audit events yet. `capture`, `watch`, `wrap`, `share`, `export`, and `prune` (when it deletes) append one line each.',
      );
    } else if (event || agent !== undefined || failed) {
      console.log(emptyListingMessage(events.length, event, agent, failed));
    }
    return 0;
  }
  if (limit && filtered.length > shown.length) {
    console.log(
      color.dim(
        `showing newest ${shown.length} of ${filtered.length}${limitScope(event, agent, failed)} (oldest → newest)`,
      ),
    );
  }
  for (const ev of shown) console.log(formatEvent(ev));
  console.log(color.dim('Check the chain: agent-receipt audit --verify'));
  return 0;
}
