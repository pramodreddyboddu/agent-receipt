/**
 * Local compliance log for wrap / share.
 *
 * `.agent-receipt/audit.jsonl` is an append-only hash chain: each line's
 * `prev` is the SHA-256 of the previous line (including its trailing newline),
 * or null for the first event. This is experimental tamper-evidence for the
 * log itself — not a signature, not PKI, and not a record of diff bodies.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { sha256Hex } from './hash.js';
import { VERSION } from './version.js';

export const AUDIT_REL = '.agent-receipt/audit.jsonl';

export type AuditKind = 'wrap' | 'share';

export interface AuditEvent {
  ts: string;
  event: AuditKind;
  version: string;
  /** Always true — the chain is not a cryptographic signature. */
  experimental: true;
  /** Repo-relative path when it stays inside cwd. */
  path: string;
  sha256: string | null;
  agent: string | null;
  redacted: boolean;
  verified: boolean | null;
  failedOn: boolean;
  exitCode: number;
  /** SHA-256 of the previous jsonl line, or null on the first event. */
  prev: string | null;
}

export interface AuditInput {
  event: AuditKind;
  path: string;
  sha256: string | null;
  agent?: string | null;
  redacted: boolean;
  verified: boolean | null;
  failedOn: boolean;
  exitCode: number;
}

export interface AuditChainResult {
  ok: boolean;
  events: number;
  /** 1-based jsonl line, when the chain is broken. */
  brokenAt: number | null;
  reason: string | null;
}

export function auditLogPath(cwd: string): string {
  return join(cwd, AUDIT_REL);
}

/** Prefer a repo-relative path so the log stays portable. */
export function auditDisplayPath(cwd: string, filePath: string): string {
  const abs = isAbsolute(filePath) ? filePath : join(cwd, filePath);
  const rel = relative(cwd, abs).replace(/\\/g, '/');
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) return abs;
  return rel;
}

export function readAuditRawLines(cwd: string): string[] {
  const p = auditLogPath(cwd);
  if (!existsSync(p)) return [];
  const text = readFileSync(p, 'utf8');
  if (!text) return [];
  const lines = text.split('\n');
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function hashLine(line: string): string {
  return sha256Hex(line + '\n');
}

function prevOf(lines: string[]): string | null {
  if (!lines.length) return null;
  return hashLine(lines[lines.length - 1]);
}

export function appendAuditEvent(cwd: string, input: AuditInput): AuditEvent {
  const lines = readAuditRawLines(cwd);
  const event: AuditEvent = {
    ts: new Date().toISOString(),
    event: input.event,
    version: VERSION,
    experimental: true,
    path: auditDisplayPath(cwd, input.path),
    sha256: input.sha256,
    agent: input.agent ?? null,
    redacted: input.redacted,
    verified: input.verified,
    failedOn: input.failedOn,
    exitCode: input.exitCode,
    prev: prevOf(lines),
  };
  const line = JSON.stringify(event);
  const p = auditLogPath(cwd);
  mkdirSync(dirname(p), { recursive: true });
  appendFileSync(p, line + '\n', 'utf8');
  return event;
}

/**
 * Best-effort append. A failure to write the log must not fail wrap/share;
 * the warning goes to stderr so `--json` stdout stays a single object.
 */
export function recordAuditEvent(cwd: string, input: AuditInput): void {
  try {
    appendAuditEvent(cwd, input);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`warn: audit log not written (${msg})`);
  }
}

export function verifyAuditChain(cwd: string): AuditChainResult {
  let lines: string[];
  try {
    lines = readAuditRawLines(cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, events: 0, brokenAt: null, reason: msg };
  }
  let prev: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) {
      return { ok: false, events: lines.length, brokenAt: i + 1, reason: 'blank line' };
    }
    let parsed: Partial<AuditEvent>;
    try {
      parsed = JSON.parse(line) as Partial<AuditEvent>;
    } catch {
      return { ok: false, events: lines.length, brokenAt: i + 1, reason: 'invalid JSON' };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, events: lines.length, brokenAt: i + 1, reason: 'not an object' };
    }
    if (parsed.prev !== prev) {
      return {
        ok: false,
        events: lines.length,
        brokenAt: i + 1,
        reason: 'prev mismatch',
      };
    }
    prev = hashLine(line);
  }
  return { ok: true, events: lines.length, brokenAt: null, reason: null };
}

export function loadAuditEvents(cwd: string): AuditEvent[] {
  const lines = readAuditRawLines(cwd);
  return lines.map((line, i) => {
    try {
      return JSON.parse(line) as AuditEvent;
    } catch {
      throw new Error(`audit log line ${i + 1} is not JSON (${auditLogPath(cwd)})`);
    }
  });
}
