import { auditLogPath, loadAuditEvents, verifyAuditChain, type AuditEvent } from '../lib/audit.js';
import { color } from '../lib/color.js';

export interface AuditOptions {
  json?: boolean;
  /** Check the experimental hash chain. Exit 2 on mismatch. */
  verify?: boolean;
  /** Newest N events (listing). Ignored by the chain check itself. */
  limit?: number;
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
    `${ev.ts}  ${ev.event.padEnd(5)}  exit=${ev.exitCode}  ${verified}  ${redacted}` +
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

  if (opts.verify) {
    const chain = verifyAuditChain(cwd);
    if (opts.json) {
      console.log(
        JSON.stringify({
          ok: chain.ok,
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
  const shown = limit ? events.slice(-limit) : events;

  if (opts.json) {
    console.log(JSON.stringify(shown));
    return 0;
  }

  console.log(color.bold('agent-receipt audit') + color.dim('  (experimental — not a signature)'));
  console.log(color.dim(auditLogPath(cwd)));
  if (!shown.length) {
    console.log('No audit events yet. `wrap` and `share` append one line each.');
    return 0;
  }
  if (limit && events.length > shown.length) {
    console.log(color.dim(`showing newest ${shown.length} of ${events.length} (oldest → newest)`));
  }
  for (const ev of shown) console.log(formatEvent(ev));
  console.log(color.dim('Check the chain: agent-receipt audit --verify'));
  return 0;
}
