import { readFileSync, writeSync } from 'node:fs';
import { assertReadableSize } from '../lib/byte-limit.js';
import { provenanceForNodes } from '../lib/resign-provenance.js';
import { VERSION } from '../lib/version.js';
import {
  WARN_CROSS_SESSION,
  WARN_MISSING_SESSION,
  WARN_PARENT_UNVERIFIED,
  buildSessionNodes,
  indexLocalReceipts,
  listOutDirReceipts,
  parseLinkMeta,
  readLocalReceipt,
  receiptIntegrity,
  validateLegacySession,
  writeSessionTree,
  type ReadReceiptOptions,
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
  /**
   * `cross-session-parent` (warning), `parent-unverified` (exit 1),
   * `missing-session` (Session line absent; warning unless verify failed).
   */
  warnings: string[];
  timestamp: string | null;
  status: 'pass' | 'fail';
  path: string;
}

export interface SessionReport {
  command: 'session';
  ok: boolean;
  version: string;
  /**
   * 0 when every listed receipt verifies and no local parent fails verify.
   * 1 when any receipt fails verify, a local parent fails verify, or the session is empty.
   * Cross-session parents and a missing Session line are warnings only.
   */
  exitCode: 0 | 1;
  session: string;
  receipts: SessionReceipt[];
  reason: string | null;
}

const stdoutPause = new Int32Array(new SharedArrayBuffer(4));

function writeErrorCode(err: unknown): string {
  if (!err || typeof err !== 'object' || !('code' in err)) return '';
  const code = (err as { code?: unknown }).code;
  return typeof code === 'string' ? code : '';
}

/** `session id | head` closes stdout on purpose. That is not a command failure. */
function isBrokenPipe(err: unknown): boolean {
  const code = writeErrorCode(err);
  return code === 'EPIPE' || code === 'ERR_STREAM_DESTROYED';
}

/**
 * Blocking write so a large tree does not sit in the stdout buffer.
 * `writeSync` can return a short count or EAGAIN when the fd is non-blocking.
 * EPIPE stops the write and returns. The caller still uses the session exit
 * code. ENOSPC is a one-line error, not a stack from the bin wrapper.
 */
function writeStdoutChunk(chunk: string): void {
  const fd = process.stdout.fd;
  if (typeof fd !== 'number' || fd < 0) {
    try {
      process.stdout.write(chunk);
    } catch (err) {
      if (isBrokenPipe(err)) return;
      if (writeErrorCode(err) === 'ENOSPC') throw new Error('no space left on device');
      throw err;
    }
    return;
  }
  const buf = Buffer.from(chunk);
  let offset = 0;
  while (offset < buf.length) {
    try {
      const wrote = writeSync(fd, buf, offset, buf.length - offset);
      if (wrote > 0) {
        offset += wrote;
        continue;
      }
    } catch (err) {
      const code = writeErrorCode(err);
      if (code === 'EAGAIN' || code === 'EWOULDBLOCK' || code === 'EBUSY') {
        Atomics.wait(stdoutPause, 0, 0, 1);
        continue;
      }
      if (isBrokenPipe(err)) return;
      if (code === 'ENOSPC') throw new Error('no space left on device');
      throw err;
    }
    Atomics.wait(stdoutPause, 0, 0, 1);
  }
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
    warnings: node.warnings,
    timestamp: node.timestamp,
    status: node.status,
    path: node.path,
  };
}

export interface CollectedSession {
  session: string;
  nodes: SessionNode[];
  /** Maps a stored parent reference onto the canonical id inside this session. */
  aliasToId: Map<string, string>;
  empty: boolean;
  exitCode: 0 | 1;
  reason: string | null;
}

/**
 * Receipts `session` lists for one id: a Session line equal to the id, plus
 * a receipt with no Session line whose parent is in this session
 * (`missing-session`). Orphans and cycles are flagged. A local parent that
 * fails verify adds `parent-unverified`. A parent in another local session
 * adds `cross-session-parent`.
 */
export function collectSession(
  cwd: string,
  sessionId: string,
  opts?: ReadReceiptOptions,
): CollectedSession {
  const session = validateLegacySession(sessionId);
  const local = indexLocalReceipts(cwd, opts);
  const scanned: Array<{
    id: string;
    parent: string | null;
    agent: string | null;
    verified: boolean;
    timestamp: string | null;
    path: string;
    aliases: string[];
    session: string | null;
  }> = [];

  for (const filePath of listOutDirReceipts(cwd)) {
    if (opts?.maxBytes !== undefined) {
      assertReadableSize(filePath, opts.maxBytes, `receipt ${filePath}`, '--max-receipt-bytes');
    }
    let text: string;
    try {
      text = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    const meta = parseLinkMeta(text);
    const rec = readLocalReceipt(filePath, opts);
    if (!rec) continue;
    scanned.push({
      id: rec.id,
      parent: meta.parent,
      agent: meta.agent,
      verified: receiptIntegrity(text).ok,
      timestamp: meta.timestamp,
      path: filePath,
      aliases: rec.aliases,
      session: meta.session,
    });
  }

  const byAlias = new Map<string, (typeof scanned)[number]>();
  for (const row of scanned) {
    if (!byAlias.has(row.id)) byAlias.set(row.id, row);
    for (const alias of row.aliases) {
      if (!byAlias.has(alias)) byAlias.set(alias, row);
    }
  }

  const inSession = scanned.filter((row) => row.session === session);
  const missingSession = scanned.filter((row) => {
    if (row.session) return false;
    if (!row.parent) return false;
    const parent = byAlias.get(row.parent);
    return Boolean(parent && parent.session === session);
  });
  const missingPaths = new Set(missingSession.map((row) => row.path));
  const rows = [...inSession, ...missingSession];

  const nodes = buildSessionNodes(rows, local).map((node) => {
    const warnings: string[] = [];
    if (missingPaths.has(node.path)) warnings.push(WARN_MISSING_SESSION);
    if (node.parent) {
      const parent = byAlias.get(node.parent);
      if (parent) {
        if (!parent.verified) warnings.push(WARN_PARENT_UNVERIFIED);
        if (parent.session && parent.session !== session) warnings.push(WARN_CROSS_SESSION);
      }
    }
    return { ...node, warnings };
  });
  const empty = nodes.length === 0;
  const selfFail = nodes.some((node) => !node.verified);
  const parentFail = nodes.some((node) => node.warnings.includes(WARN_PARENT_UNVERIFIED));
  const anyFail = selfFail || parentFail;
  const exitCode: 0 | 1 = empty || anyFail ? 1 : 0;
  const reason = empty
    ? `no receipts in session ${session}`
    : selfFail
      ? 'one or more receipts failed verify'
      : parentFail
        ? 'a local parent failed verify'
        : null;

  const aliasToId = new Map<string, string>();
  for (const row of rows) {
    aliasToId.set(row.id, row.id);
    for (const alias of row.aliases) aliasToId.set(alias, row.id);
  }

  return { session, nodes, aliasToId, empty, exitCode, reason };
}

/**
 * List receipts in one session as a parent/child tree.
 * Scans the configured outDir only. A receipt written with `--out` outside
 * that directory is not included. Orphans and cycles are flagged and do not
 * by themselves change the exit code. Exit 1 when any receipt fails verify
 * or when no local receipt carries this session id. A local parent that
 * fails verify also exits 1. A parent that verifies in another session is
 * a warning. A receipt with no Session line whose parent is in this session
 * is listed with `missing-session` (warning, unless that receipt fails verify).
 */
export function cmdSession(
  cwd: string,
  sessionId: string | undefined,
  opts: SessionOptions = {},
): number {
  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    throw new Error('session requires an id. Usage: agent-receipt session <id> [--json]');
  }
  const collected = collectSession(cwd, sessionId);
  const { session, nodes, aliasToId, empty, exitCode, reason } = collected;

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
    // `session id --json | head` closes stdout. A thrown EPIPE is not a
    // session failure. The bin wrapper swallows the async stream error.
    try {
      console.log(JSON.stringify(report));
    } catch (err) {
      if (!isBrokenPipe(err)) throw err;
    }
    return exitCode;
  }

  if (empty) {
    console.error(`Error: no receipts in session ${session}`);
    return 1;
  }

  writeSessionTree(session, nodes, aliasToId, provenanceForNodes(cwd, nodes), writeStdoutChunk);
  return exitCode;
}
