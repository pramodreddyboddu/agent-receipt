import { VERSION } from './version.js';
import type { RiskSummary } from './risk.js';
import type { SignatureStatus } from './sign.js';

/**
 * One-line stdout object for CI. Human progress stays on stderr when --json
 * is set on capture / wrap / share / verify.
 *
 * Exit codes (also `exitCode` in the object):
 *   0  gate passed
 *   2  --fail-on matched and/or verify failed (artifact still written when capture/wrap/share got that far)
 *   1  usage or runtime error (see `reason`) — not a policy failure
 *
 * `verified: null` means this command did not run verify (capture).
 * Config `failOn` is not applied by verify unless the flag is explicit.
 *
 * `trailingIgnored` is a boolean when this command hashed a body (verify,
 * and wrap/share after they verify). It is null when trailing content was
 * not evaluated (capture, and usage errors).
 *
 * `signature` is set only by `verify --json --require-sig` after the hash
 * check passes. Other commands omit it. `sigPath` is set by `share --json`
 * (string when a Markdown sidecar was copied or re-signed, otherwise null).
 */
export interface GateRisk {
  high: number;
  medium: number;
  low: number;
  total: number;
  maxSeverity: string | null;
}

export interface GateReport {
  ok: boolean;
  command: string;
  version: string;
  exitCode: 0 | 1 | 2;
  verified: boolean | null;
  failedOn: boolean;
  failOn: string | null;
  redacted: boolean;
  uncommitted: boolean | null;
  path: string | null;
  jsonPath: string | null;
  htmlPath: string | null;
  markdownPath: string | null;
  tldr: string | null;
  sha256: string | null;
  risk: GateRisk | null;
  ignored: number | null;
  /**
   * True when content after `## Integrity` was ignored by the hash.
   * Null when this command did not evaluate trailing content.
   */
  trailingIgnored: boolean | null;
  reason: string | null;
  /**
   * Set by `verify --json` when `--require-sig` ran after a passing hash.
   * Omitted when the signature was not required.
   */
  signature?: SignatureStatus | null;
  /**
   * Set by `share --json`. Path of the sidecar copied or re-signed beside
   * published Markdown, or null when none was attached. Omitted otherwise.
   */
  sigPath?: string | null;
}

export type GateFields = Omit<GateReport, 'ok' | 'version' | 'exitCode' | 'trailingIgnored'> & {
  exitCode?: 0 | 1 | 2;
  trailingIgnored?: boolean | null;
};

export function riskToGate(sum: RiskSummary | null | undefined): GateRisk | null {
  if (!sum) return null;
  return {
    high: sum.high,
    medium: sum.medium,
    low: sum.low,
    total: sum.total,
    maxSeverity: sum.maxSeverity,
  };
}

/** Policy / verify outcome. Does not return 1 — callers pass exitCode 1 for usage errors. */
export function gateExitCode(verified: boolean | null, failedOn: boolean): 0 | 2 {
  if (failedOn || verified === false) return 2;
  return 0;
}

export function finalizeGate(fields: GateFields): GateReport {
  const exitCode = fields.exitCode ?? gateExitCode(fields.verified, fields.failedOn);
  return {
    ok: exitCode === 0,
    command: fields.command,
    version: VERSION,
    exitCode,
    verified: fields.verified,
    failedOn: fields.failedOn,
    failOn: fields.failOn,
    redacted: fields.redacted,
    uncommitted: fields.uncommitted,
    path: fields.path,
    jsonPath: fields.jsonPath,
    htmlPath: fields.htmlPath,
    markdownPath: fields.markdownPath,
    tldr: fields.tldr,
    sha256: fields.sha256,
    risk: fields.risk,
    ignored: fields.ignored,
    trailingIgnored: fields.trailingIgnored ?? null,
    reason: fields.reason,
    ...(fields.signature !== undefined ? { signature: fields.signature } : {}),
    ...(fields.sigPath !== undefined ? { sigPath: fields.sigPath } : {}),
  };
}

export function printGate(report: GateReport): void {
  console.log(JSON.stringify(report));
}

export function errorGate(command: string, reason: string): GateReport {
  return finalizeGate({
    command,
    exitCode: 1,
    verified: null,
    failedOn: false,
    failOn: null,
    redacted: false,
    uncommitted: null,
    path: null,
    jsonPath: null,
    htmlPath: null,
    markdownPath: null,
    tldr: null,
    sha256: null,
    risk: null,
    ignored: null,
    trailingIgnored: null,
    reason,
  });
}

export function failOnReason(
  failOn: string | undefined,
  maxSeverity: string | null | undefined,
): string {
  return `fail-on ${failOn}: max severity is ${maxSeverity ?? 'none'}`;
}

/** Human lines. With a JSON gate, send them to stderr so stdout stays one object. */
export function emitLine(quiet: boolean, line: string): void {
  if (quiet) console.error(line);
  else console.log(line);
}
