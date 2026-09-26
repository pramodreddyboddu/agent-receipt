import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { color } from '../lib/color.js';
import { VERSION } from '../lib/version.js';
import { extractTldr } from '../lib/receipt.js';
import {
  auditDisplayPath,
  auditLogPath,
  readAuditRawLines,
  verifyAuditChain,
} from '../lib/audit.js';
import { riskToGate, type GateRisk } from '../lib/gate.js';
import { findIndexEntry, failedOnFromIndex } from '../lib/receipt-index.js';
import { glanceRowFailed } from './history.js';
import { parseReceiptGlance } from './compare.js';
import { cmdVerify } from './verify.js';
import {
  ABSENT_SIGNATURE,
  inspectReceiptSignature,
  type SignatureStatus,
} from '../lib/sign.js';
import { applyTrust, loadTrustedFingerprints } from '../lib/trust.js';
import type { FailOnThreshold } from '../lib/risk.js';
import { renderProveHtml, type ProveHtmlSummary } from '../lib/prove-html.js';

export interface ProveOptions {
  /** One JSON object on stdout. Human banner stays off. */
  json?: boolean;
  /**
   * Explicit `--fail-on` only. Config `failOn` is not applied.
   * Prove stays an integrity check unless this flag is passed.
   */
  failOn?: FailOnThreshold;
  /** Extra known-key fingerprints for this invocation (`--trusted-key`). */
  trustedKeys?: string[];
  /**
   * Write a Markdown one-pager after the report is computed.
   * Does not change exit codes. Omitted means stdout only.
   */
  page?: boolean;
  /**
   * Write a self-contained offline HTML verification report (`foo.prove.html`).
   * Redacted by default. Does not change exit codes.
   */
  html?: boolean;
  /**
   * Destination file or directory for the one-pager and/or HTML report.
   * Requires `page` or `html`. Must be a directory when both are set.
   */
  out?: string;
}

export interface ProveAudit {
  present: boolean;
  chainOk: boolean | null;
  events: number;
  matched: boolean;
  reason: string | null;
}

export interface ProveReport {
  ok: boolean;
  command: 'prove';
  version: string;
  exitCode: 0 | 1 | 2;
  verified: boolean | null;
  trailingIgnored: boolean | null;
  failedOn: boolean;
  failOn: string | null;
  redacted: boolean;
  uncommitted: boolean | null;
  path: string | null;
  sha256: string | null;
  tldr: string | null;
  agent: string | null;
  risk: GateRisk | null;
  audit: ProveAudit;
  signature: SignatureStatus;
  reason: string | null;
  /**
   * Absolute path of the Markdown one-pager when `--page` wrote one.
   * Omitted when `--page` was not passed, so existing prove objects keep
   * their key set. Null is unused today: a write failure exits 1 instead.
   */
  pagePath?: string | null;
  /**
   * Absolute path of the HTML report when `--html` wrote one.
   * Omitted when `--html` was not passed.
   */
  htmlPath?: string | null;
}

const ABSENT_AUDIT: ProveAudit = {
  present: false,
  chainOk: null,
  events: 0,
  matched: false,
  reason: null,
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function readCompanion(mdPath: string): Record<string, unknown> | null {
  if (!/\.md$/i.test(mdPath)) return null;
  const jsonPath = mdPath.replace(/\.md$/i, '.json');
  if (!existsSync(jsonPath)) return null;
  try {
    return asRecord(JSON.parse(readFileSync(jsonPath, 'utf8')));
  } catch {
    return null;
  }
}

function companionFailedOn(raw: Record<string, unknown>): boolean | null {
  if (typeof raw.failedOn === 'boolean') return raw.failedOn;
  const summary = asRecord(raw.summary);
  const risk = summary ? asRecord(summary.risk) : null;
  if (!risk) return null;
  const high = Number(risk.high ?? 0);
  if (high > 0 || risk.maxSeverity === 'high') return true;
  return false;
}

function textOrNull(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

/**
 * failedOn: index row (stored boolean wins, else high-only), else companion
 * `.json`, else a high-severity glance. uncommitted follows the same preference.
 * Agent prefers the receipt body.
 */
function runMemory(cwd: string, mdPath: string): {
  agent: string | null;
  failedOn: boolean;
  uncommitted: boolean | null;
} {
  const glance = parseReceiptGlance(mdPath);
  const entry = findIndexEntry(cwd, mdPath);
  const companion = readCompanion(mdPath);

  const agent =
    textOrNull(glance.agent) ||
    (entry ? textOrNull(entry.agent) : null) ||
    (companion ? textOrNull(companion.agent) : null);

  let failedOn: boolean;
  const fromCompanion = companion ? companionFailedOn(companion) : null;
  if (entry) failedOn = failedOnFromIndex(entry);
  else if (fromCompanion !== null) failedOn = fromCompanion;
  else failedOn = glanceRowFailed(glance.risks);

  let uncommitted: boolean | null;
  if (entry && typeof entry.uncommitted === 'boolean') uncommitted = entry.uncommitted;
  else if (companion && typeof companion.uncommitted === 'boolean') {
    uncommitted = companion.uncommitted;
  } else if (glance.uncommitted === true) uncommitted = true;
  else if (glance.timestamp || glance.agent || glance.message) uncommitted = false;
  else uncommitted = null;

  return { agent, failedOn, uncommitted };
}

function auditMatched(cwd: string, receiptPath: string): boolean {
  const display = auditDisplayPath(cwd, receiptPath);
  const abs = resolve(receiptPath);
  let lines: string[] = [];
  try {
    lines = readAuditRawLines(cwd);
  } catch {
    return false;
  }
  for (const line of lines) {
    let parsed: { path?: unknown };
    try {
      parsed = JSON.parse(line) as { path?: unknown };
    } catch {
      continue;
    }
    if (typeof parsed.path !== 'string' || !parsed.path) continue;
    if (parsed.path === display || parsed.path === receiptPath || parsed.path === abs) {
      return true;
    }
    const eventAbs = isAbsolute(parsed.path) ? resolve(parsed.path) : resolve(cwd, parsed.path);
    if (eventAbs === abs) return true;
  }
  return false;
}

function readAudit(cwd: string, receiptPath: string): ProveAudit {
  if (!existsSync(auditLogPath(cwd))) return { ...ABSENT_AUDIT };
  const chain = verifyAuditChain(cwd);
  return {
    present: true,
    chainOk: chain.ok,
    events: chain.events,
    matched: auditMatched(cwd, receiptPath),
    reason: chain.ok ? null : chain.reason,
  };
}

function formatRisk(risk: GateRisk | null): string {
  if (!risk) return '(none)';
  if (!risk.total && !risk.maxSeverity) return 'none';
  const max = risk.maxSeverity ?? 'none';
  return `${risk.total} (high ${risk.high}, medium ${risk.medium}, low ${risk.low}), max ${max}`;
}

function formatAudit(audit: ProveAudit): string {
  if (!audit.present) return 'absent';
  const chain = audit.chainOk
    ? 'chain OK'
    : `chain broken${audit.reason ? ` (${audit.reason})` : ''}`;
  const events = `${audit.events} event${audit.events === 1 ? '' : 's'}`;
  const matched = audit.matched ? 'matched' : 'not matched';
  return `present, ${chain}, ${events}, ${matched}`;
}

function formatSignature(signature: SignatureStatus): string {
  if (!signature.present) return 'absent';
  const trust =
    signature.trusted === true ? ' trusted' : signature.trusted === false ? ' untrusted' : '';
  if (signature.ok) return `ok ${signature.fingerprint ?? ''}${trust}`.trim();
  return signature.reason ? `FAIL ${signature.reason}` : 'FAIL';
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

function tri(value: boolean | null): string {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return 'unknown';
}

function oneLine(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

/**
 * Sibling file name. `foo.md` → `foo.prove.md`. A name that does not end
 * in `.md` keeps its suffix and appends `.prove.md` (`notes.txt` →
 * `notes.txt.prove.md`) so it does not collide with a Markdown receipt
 * of the same stem.
 */
function provePageFileName(receiptPath: string, ext: 'md' | 'html' = 'md'): string {
  const base = basename(receiptPath);
  if (/\.md$/i.test(base)) return base.replace(/\.md$/i, `.prove.${ext}`);
  return `${base}.prove.${ext}`;
}

function defaultProvePagePath(receiptPath: string, ext: 'md' | 'html' = 'md'): string {
  return join(dirname(receiptPath), provePageFileName(receiptPath, ext));
}

/** True when `--out` names a directory (trailing slash or an existing dir). */
function outIsDirectory(cwd: string, out: string): boolean {
  if (/[/\\]$/.test(out)) return true;
  try {
    return statSync(resolve(cwd, out)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * `--out` file is used as-is. An existing directory, or a path that ends
 * with a slash, receives `<stem>.prove.md` inside it.
 */
function resolveProvePageOut(
  cwd: string,
  receiptPath: string,
  out?: string,
  ext: 'md' | 'html' = 'md',
): string {
  if (!out) return defaultProvePagePath(receiptPath, ext);
  const wantsDir = /[/\\]$/.test(out);
  const resolved = resolve(cwd, out);
  if (wantsDir) return join(resolved, provePageFileName(receiptPath, ext));
  try {
    if (statSync(resolved).isDirectory()) return join(resolved, provePageFileName(receiptPath, ext));
  } catch {
    // Missing path is a file. Parent directories are created at write time.
  }
  return resolved;
}

function formatSignaturePage(signature: SignatureStatus): string {
  if (!signature.present) {
    return 'present no; ok n/a; trusted n/a; fingerprint (none); reason (none)';
  }
  const ok = signature.ok === true ? 'yes' : signature.ok === false ? 'no' : 'unknown';
  const trusted =
    signature.trusted === true ? 'yes' : signature.trusted === false ? 'no' : 'n/a';
  const fp = signature.fingerprint ?? '(none)';
  const reason = signature.reason ? oneLine(signature.reason) : '(none)';
  return `present yes; ok ${ok}; trusted ${trusted}; fingerprint ${fp}; reason ${reason}`;
}

const PAGE_FOOTER =
  'The hash and the audit link are tamper-evident, not a cryptographic signature. The signature line reports a local Ed25519 sidecar when one is present. This is not a certificate authority and not access control. This one-pager is not itself signed.';

/** Plain-English one page. Not a dump of the receipt body, and not signed. */
function renderProvePage(report: ProveReport): string {
  const verdict = report.exitCode === 0 ? 'PROVED' : 'FAILED';
  const line = (label: string, value: string) => `- **${label}:** ${value}`;
  const lines = [
    '# Agent Receipt — Prove',
    '',
    `**Verdict:** ${verdict}`,
    '',
    line('path', report.path ?? '(none)'),
    line('sha256', report.sha256 ?? '(none)'),
    line('verified', tri(report.verified)),
    line('trailingIgnored', tri(report.trailingIgnored)),
    line('redacted', yesNo(report.redacted)),
    line('risk', formatRisk(report.risk)),
    line('tldr', oneLine(report.tldr ?? '(none)')),
    line('agent', oneLine(report.agent ?? '(none)')),
    line('uncommitted', report.uncommitted === null ? 'unknown' : yesNo(report.uncommitted)),
    line('failedOn', yesNo(report.failedOn)),
    line('audit', formatAudit(report.audit)),
    line('signature', formatSignaturePage(report.signature)),
  ];
  if (report.failOn) lines.push(line('failOn', report.failOn));
  if (report.reason) lines.push(line('reason', oneLine(report.reason)));
  lines.push('', '---', '', PAGE_FOOTER, '');
  return lines.join('\n');
}

function writeProvePage(cwd: string, report: ProveReport, out?: string): string {
  if (!report.path) {
    throw new Error('prove --page needs a receipt path.');
  }
  const dest = resolveProvePageOut(cwd, report.path, out);
  if (resolve(dest) === resolve(report.path)) {
    throw new Error(
      'prove --page must not overwrite the source receipt. Pass a different --out.',
    );
  }
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, renderProvePage(report), 'utf8');
  return dest;
}

function htmlSummary(cwd: string, receiptPath: string): ProveHtmlSummary {
  const glance = parseReceiptGlance(receiptPath);
  const rel = relative(cwd, receiptPath);
  const displayPath = rel && !rel.startsWith('..') && !isAbsolute(rel) ? rel : basename(receiptPath);
  return {
    displayPath,
    timestamp: glance.timestamp,
    branch: glance.branch,
    head: glance.head,
    message: glance.message,
    fileCount: glance.fileCount,
    insertions: glance.insertions,
    deletions: glance.deletions,
    files: glance.files,
    risks: glance.risks,
  };
}

function writeProveHtml(cwd: string, report: ProveReport, out?: string): string {
  if (!report.path) {
    throw new Error('prove --html needs a receipt path.');
  }
  const dest = resolveProvePageOut(cwd, report.path, out, 'html');
  if (resolve(dest) === resolve(report.path)) {
    throw new Error(
      'prove --html must not overwrite the source receipt. Pass a different --out.',
    );
  }
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, renderProveHtml(report, htmlSummary(cwd, report.path)), 'utf8');
  return dest;
}

function printHuman(report: ProveReport): void {
  const banner =
    report.exitCode === 0 ? color.green('PROVED') : color.red('FAILED');
  const lines = [
    `${banner}  ${report.path ?? ''}`,
    `  sha256: ${report.sha256 ?? ''}`,
    `  verified: ${report.verified ? 'yes' : 'no'}`,
    `  trailingIgnored: ${report.trailingIgnored ? 'yes' : 'no'}`,
    `  redacted: ${yesNo(report.redacted)}`,
    `  risk: ${formatRisk(report.risk)}`,
    `  tldr: ${report.tldr ?? '(none)'}`,
    `  agent: ${report.agent ?? '(none)'}`,
    `  uncommitted: ${report.uncommitted === null ? 'unknown' : yesNo(report.uncommitted)}`,
    `  failedOn: ${yesNo(report.failedOn)}`,
    `  audit: ${formatAudit(report.audit)}`,
    `  signature: ${formatSignature(report.signature)}`,
  ];
  if (report.failOn) lines.push(`  failOn: ${report.failOn}`);
  if (report.reason) lines.push(`  reason: ${report.reason}`);
  if (report.pagePath) lines.push(`  page: ${report.pagePath}`);
  if (report.htmlPath) lines.push(`  html: ${report.htmlPath}`);
  console.log(lines.join('\n'));
  console.log('');
  console.log(
    color.dim(
      'Tip: the hash and audit link are tamper-evident, not a cryptographic signature. The signature line reports a local Ed25519 sidecar when one is present.',
    ),
  );
}

export function printProve(report: ProveReport): void {
  console.log(JSON.stringify(report));
}

/** Usage / runtime error as the prove JSON object. stdout stays one object. */
export function printProveError(reason: string): void {
  printProve({
    ok: false,
    command: 'prove',
    version: VERSION,
    exitCode: 1,
    verified: null,
    trailingIgnored: null,
    failedOn: false,
    failOn: null,
    redacted: false,
    uncommitted: null,
    path: null,
    sha256: null,
    tldr: null,
    agent: null,
    risk: null,
    audit: { ...ABSENT_AUDIT },
    signature: { ...ABSENT_SIGNATURE },
    reason,
  });
}

/**
 * Thin prove-this-run: same Markdown hash as verify, plus an audit-log link
 * and optional Ed25519 sidecar status. Default `verify` stays hash-only.
 * `verify --require-sig` is the opt-in that fails when the sidecar is missing.
 * Exit 0 when the hash matches, the audit log is absent or intact, and any
 * sidecar is valid. Exit 2 when verify fails, the chain is broken, a present
 * sidecar is invalid, an active trust store rejects the fingerprint, or
 * `--fail-on` trips. A missing sidecar does not fail. An empty or absent
 * trust store leaves that rule unchanged.
 */
export function cmdProve(
  cwd: string,
  pathArg?: string,
  opts: ProveOptions = {},
): ProveReport {
  if (opts.page && opts.html && opts.out && !outIsDirectory(cwd, opts.out)) {
    throw new Error(
      'prove --out must be a directory (end it with /) when --page and --html are both passed.',
    );
  }
  const verified = cmdVerify(cwd, pathArg, { quiet: true, failOn: opts.failOn });
  const text = readFileSync(verified.path, 'utf8');
  const memory = runMemory(cwd, verified.path);
  const failOnTripped = verified.failedOn;
  const failedOn = failOnTripped ? true : memory.failedOn;
  const audit = readAudit(cwd, verified.path);
  const auditBroken = audit.present && audit.chainOk === false;
  const inspected = inspectReceiptSignature(verified.path, verified.sha256);
  const signature =
    inspected.present && inspected.ok === true
      ? applyTrust(
          inspected,
          loadTrustedFingerprints(cwd, { extra: opts.trustedKeys }),
        )
      : inspected;
  const signatureBad = signature.present && signature.ok === false;

  const reasons: string[] = [];
  if (!verified.ok && verified.reason) reasons.push(verified.reason);
  else if (failOnTripped && verified.reason) reasons.push(verified.reason);
  if (auditBroken) {
    reasons.push(
      audit.reason ? `audit chain broken: ${audit.reason}` : 'audit chain broken',
    );
  }
  if (signatureBad) {
    reasons.push(signature.reason ? `signature: ${signature.reason}` : 'signature invalid');
  }
  const reason = reasons.length ? reasons.join('; ') : null;
  const exitCode: 0 | 2 =
    !verified.ok || failOnTripped || auditBroken || signatureBad ? 2 : 0;

  const report: ProveReport = {
    ok: exitCode === 0,
    command: 'prove',
    version: VERSION,
    exitCode,
    verified: verified.ok,
    trailingIgnored: verified.trailingIgnored,
    failedOn,
    failOn: opts.failOn ?? null,
    redacted: verified.redacted,
    uncommitted: memory.uncommitted,
    path: verified.path,
    sha256: verified.sha256,
    tldr: extractTldr(text),
    agent: memory.agent,
    risk: riskToGate(verified.risk),
    audit,
    signature,
    reason,
  };

  if (opts.page) {
    report.pagePath = writeProvePage(cwd, report, opts.out);
  }
  if (opts.html) {
    report.htmlPath = writeProveHtml(cwd, report, opts.out);
  }

  if (opts.json) printProve(report);
  else printHuman(report);
  return report;
}
