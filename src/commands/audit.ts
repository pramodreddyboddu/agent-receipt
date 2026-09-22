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
  /** Check the experimental hash chain. Exit 2 on mismatch. Ignores --event and --limit. */
  verify?: boolean;
  /** Newest N events (listing). Ignored by the chain check itself. */
  limit?: number;
  /**
   * Listing filter: capture | watch | wrap | share | export | prune.
   * Ignored by --verify (the chain check is the whole file).
   */
  event?: string;
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
 * Exit 0 ok, 2 chain mismatch (`--verify`), 1 unreadable log (thrown).
 */
export function cmdAudit(cwd: string, opts: AuditOptions = {}): number {
  const limit = opts.limit;
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) {
    throw new Error('--limit must be an integer >= 1');
  }
  const event = requireAuditEvent(opts.event);

  if (opts.verify) {
    if (event) {
      console.error(
        `--event ${event} is listing-only; --verify checks the whole chain.`,
      );
    }
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
  const filtered = event ? events.filter((ev) => ev.event === event) : events;
  const shown = limit ? filtered.slice(-limit) : filtered;

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
  if (!shown.length) {
    if (!events.length) {
      console.log(
        'No audit events yet. `capture`, `watch`, `wrap`, `share`, `export`, and `prune` (when it deletes) append one line each.',
      );
    } else if (event) {
      console.log(
        `No ${event} events (${events.length} other event${events.length === 1 ? '' : 's'} in the log).`,
      );
    }
    return 0;
  }
  if (limit && filtered.length > shown.length) {
    const scope = event ? ` ${event}` : '';
    console.log(
      color.dim(`showing newest ${shown.length} of ${filtered.length}${scope} (oldest → newest)`),
    );
  }
  for (const ev of shown) console.log(formatEvent(ev));
  console.log(color.dim('Check the chain: agent-receipt audit --verify'));
  return 0;
}
