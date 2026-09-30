import { readFileSync } from 'node:fs';
import { VERSION } from '../lib/version.js';
import { verifyMarkdown } from '../lib/hash.js';
import {
  buildSessionNodes,
  formatSessionTree,
  indexLocalReceipts,
  listOutDirReceipts,
  parseLinkMeta,
  readLocalReceipt,
  validateLinkLabel,
  type SessionNode,
} from '../lib/link.js';

export interface SessionOptions {
  /** One JSON object on stdout. Human tree stays off. */
  json?: boolean;
}

export interface SessionReceipt {
  id: string;
  parent: string | null;
  agent: string | null;
  verified: boolean;
  /** 0 when this receipt verifies, 2 when it does not. Distinct from the command exit. */
  exitCode: 0 | 2;
  orphan: boolean;
  cycle: boolean;
  timestamp: string | null;
  status: 'pass' | 'fail';
  path: string;
}

export interface SessionReport {
  command: 'session';
  ok: boolean;
  version: string;
  /** 0 when every receipt verifies. 1 when any fails or the session is empty. */
  exitCode: 0 | 1;
  session: string;
  receipts: SessionReceipt[];
  reason: string | null;
}

function toReceipt(node: SessionNode): SessionReceipt {
  return {
    id: node.id,
    parent: node.parent,
    agent: node.agent,
    verified: node.verified,
    exitCode: node.exitCode,
    orphan: node.orphan,
    cycle: node.cycle,
    timestamp: node.timestamp,
    status: node.status,
    path: node.path,
  };
}

/**
 * List receipts in one session as a parent/child tree.
 * Scans the configured outDir only. A receipt written with `--out` outside
 * that directory is not included. Orphans and cycles are flagged and do not
 * by themselves change the exit code. Exit 1 when any receipt fails verify
 * or when no local receipt carries this session id.
 */
export function cmdSession(
  cwd: string,
  sessionId: string | undefined,
  opts: SessionOptions = {},
): number {
  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    throw new Error('session requires an id. Usage: agent-receipt session <id> [--json]');
  }
  const session = validateLinkLabel('session', sessionId);
  const local = indexLocalReceipts(cwd);
  const rows: Array<{
    id: string;
    parent: string | null;
    agent: string | null;
    verified: boolean;
    timestamp: string | null;
    path: string;
    aliases: string[];
  }> = [];

  for (const filePath of listOutDirReceipts(cwd)) {
    let text: string;
    try {
      text = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    const meta = parseLinkMeta(text);
    if (meta.session !== session) continue;
    const rec = readLocalReceipt(filePath);
    if (!rec) continue;
    rows.push({
      id: rec.id,
      parent: meta.parent,
      agent: meta.agent,
      verified: verifyMarkdown(text).ok,
      timestamp: meta.timestamp,
      path: filePath,
      aliases: rec.aliases,
    });
  }

  const nodes = buildSessionNodes(rows, local);
  const empty = nodes.length === 0;
  const anyFail = nodes.some((node) => !node.verified);
  const exitCode: 0 | 1 = empty || anyFail ? 1 : 0;
  const reason = empty
    ? `no receipts in session ${session}`
    : anyFail
      ? 'one or more receipts failed verify'
      : null;

  if (opts.json) {
    const report: SessionReport = {
      command: 'session',
      ok: exitCode === 0,
      version: VERSION,
      exitCode,
      session,
      receipts: nodes.map(toReceipt),
      reason,
    };
    console.log(JSON.stringify(report));
    return exitCode;
  }

  if (empty) {
    console.error(`Error: no receipts in session ${session}`);
    return 1;
  }

  const aliasToId = new Map<string, string>();
  for (const row of rows) {
    aliasToId.set(row.id, row.id);
    for (const alias of row.aliases) aliasToId.set(alias, row.id);
  }
  console.log(formatSessionTree(session, nodes, aliasToId));
  return exitCode;
}
