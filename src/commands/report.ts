/**
 * Signed one-page HTML report.
 *
 * `report <receipt|last>` and `report --session <id>` (or a `*.session`
 * directory) write one offline HTML file beside outDir. The page is
 * `renderReportHtml(payload, signature)`. The Ed25519 signature covers the
 * canonical payload. Verify re-renders and requires those bytes.
 * Missing keys write an UNSIGNED report and exit 0. A receipt that fails
 * verify, or a present invalid receipt signature, still writes the page
 * and exits 2. A session whose root or any receipt fails verification is
 * FAILED, never VERIFIED.
 */

import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { auditLogPath, loadAuditEvents, verifyAuditChain } from '../lib/audit.js';
import { color } from '../lib/color.js';
import { loadConfig } from '../lib/config.js';
import { canonicalBody, extractEmbeddedHash, sha256Hex } from '../lib/hash.js';
import {
  buildSessionNodes,
  formatSessionTree,
  parseLinkMeta,
  parseSessionHeader,
  readLocalReceipt,
  receiptIntegrity,
  type SessionNode,
} from '../lib/link.js';
import { defangUrls } from '../lib/prove-html.js';
import { isHighSecretRiskCode, publishRedactedReceipt, redactSecretsInText } from '../lib/redact.js';
import { readIndexStrict, receiptsDir } from '../lib/receipt-index.js';
import { loadResignProvenance, type ResignClaim } from '../lib/resign-provenance.js';
import {
  assertRenderedPage,
  BOM_PAGE_MESSAGE,
  CR_PAGE_MESSAGE,
  CRLF_PAGE_MESSAGE,
  decideVerdict,
  INVALID_UTF8_MESSAGE,
  parseReportHtml,
  plainReportText,
  renderReportHtml,
  REPORT_PAYLOAD_MARKER,
  REPORT_RENDER_VERSION,
  reportBanner,
  reportPayloadHash,
  reportPills,
  reportTitle,
  reportUnredacted,
  ReportHtmlError,
  type ReportExposure,
  type ReportPayload,
  type ReportReceiptPayload,
  type ReportSignatureState,
  type ReportVerdict,
} from '../lib/report-html.js';
import {
  SESSION_MANIFEST_NAME,
  exportProtectedPaths,
  loadSessionManifest,
  locateSessionPackage,
  type SessionManifestReceipt,
} from '../lib/session-package.js';
import { assertProtectedOut, OutGuardError, resolveDirOrFileOut } from '../lib/out-guard.js';
import { sha256FileBytes } from '../lib/share-package.js';
import {
  createSignatureDocument,
  inspectReceiptSignature,
  loadKeys,
  privateKeyPath,
  publicKeyPath,
  signaturePathFor,
  verifySignature,
  writeSignatureDocument,
  type LoadedKeys,
  type SignatureDocument,
  type SignatureStatus,
} from '../lib/sign.js';
import { applyTrust, loadTrustedFingerprints, trustStoreActive, type TrustStore } from '../lib/trust.js';
import { VERSION } from '../lib/version.js';
import { findLatestReceipt } from './show.js';
import { collectSession } from './session.js';

const SAFE_STEM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$/;
const SAFE_DIR_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,200}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** Printed when --require-sig accepts a signature because no allowlist is configured. */
export const NO_TRUST_REQUIRE_SIG_NOTE =
  'no trust store: --require-sig accepts any valid self-signed page; use a trust allowlist (agent-receipt trust add --self)';

export interface ReportOptions {
  json?: boolean;
  out?: string;
  session?: string;
  includeHost?: boolean;
  noRedact?: boolean;
  trustedKeys?: string[];
}

export interface ReportVerifyOptions {
  json?: boolean;
  receiptsDir?: string;
  requireSig?: boolean;
  trustedKeys?: string[];
}

export interface ReportCommandResult {
  ok: boolean;
  command: 'report';
  version: string;
  exitCode: 0 | 1 | 2;
  verdict: ReportVerdict | null;
  htmlPath: string | null;
  sigPath: string | null;
  signed: boolean;
  fingerprint: string | null;
  redacted: boolean;
  exposure: ReportExposure | null;
  receiptCount: number;
  reason: string | null;
}

export type ReportVerifyVerdict = ReportVerdict | 'VERIFIED_PAYLOAD_ONLY';

export interface ReportVerifyResult {
  ok: boolean;
  command: 'report-verify';
  version: string;
  exitCode: 0 | 1 | 2;
  verdict: ReportVerifyVerdict | null;
  signed: boolean;
  fingerprint: string | null;
  trusted: boolean | null;
  receiptCount: number;
  checked: number;
  skipped: number;
  failed: number;
  /** Referenced receipts with no candidate and no store listing. */
  notChecked: number;
  reason: string | null;
  /** Set when a payload-only prune has no retention config and no recorded source. */
  warning: string | null;
}

interface BuiltReceipt {
  payload: ReportReceiptPayload;
  node: {
    id: string;
    parent: string | null;
    agent: string | null;
    verified: boolean;
    timestamp: string | null;
    path: string;
    aliases: string[];
  };
}

function tryLoadKeys(cwd: string): LoadedKeys | null {
  const priv = existsSync(privateKeyPath(cwd));
  const pub = existsSync(publicKeyPath(cwd));
  if (!priv && !pub) return null;
  return loadKeys(cwd);
}

function exposureOf(opts: ReportOptions): ReportExposure {
  if (opts.noRedact) return 'unredacted';
  if (opts.includeHost) return 'host';
  return 'redacted';
}

function displayMarkdown(markdown: string, exposure: ReportExposure): string {
  if (exposure === 'unredacted') return markdown;
  return publishRedactedReceipt(markdown, { maskHost: exposure !== 'host' });
}

function section(markdown: string, heading: string): string {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((line) => line === heading || line.startsWith(`${heading} `));
  if (start < 0) return '';
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^#{1,2}\s/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join('\n').trim();
}

function firstField(text: string, label: string): string {
  const match = text.match(new RegExp(`^- \\*\\*${label}\\*\\*:([^\\n]*)$`, 'm'));
  if (!match) return '';
  return match[1].replace(/^`|`$/g, '').trim();
}

function headerValue(header: Record<string, string>, text: string, label: string): string {
  return header[label] || firstField(text, label);
}

function filesFrom(text: string): string[] {
  const filesSection = text.split('## Files changed')[1]?.split(/^## /m)[0] || '';
  const files: string[] = [];
  for (const line of filesSection.split('\n')) {
    const match = line.match(/^\|\s*\w+\s*\|\s*`([^`]+)`\s*\|/);
    if (match) files.push(match[1]);
  }
  return files;
}

function risksFrom(text: string): Array<{ severity: string; code: string; detail: string }> {
  const riskSection = text.split('## Risk findings')[1]?.split(/^## /m)[0] || '';
  const risks: Array<{ severity: string; code: string; detail: string }> = [];
  for (const line of riskSection.split('\n')) {
    const match = line.match(/^\|\s*(\w+)\s*\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|$/);
    if (match && match[1] !== 'Sev') {
      risks.push({ severity: match[1], code: match[2], detail: match[3] });
    }
  }
  return risks;
}

function commandsFrom(text: string): string[] {
  const out: string[] = [];
  const listed = section(text, '## Commands');
  for (const line of listed.split('\n')) {
    const match = line.match(/^[-*]\s+`?(.+?)`?\s*$/);
    if (match) out.push(match[1]);
  }
  if (out.length) return out.slice(0, 20);
  const diffs = section(text, '## Diff summaries') || section(text, '## Diff summaries (full)');
  for (const line of diffs.split('\n')) {
    const match = line.match(/^(?:[+-])?\s*\$\s+(.+)$/);
    if (match) out.push(match[1]);
    if (out.length >= 20) break;
  }
  return out;
}

function claimFor(store: Map<string, ResignClaim>, sha: string): ResignClaim {
  return (
    store.get(sha) ?? {
      originalFingerprint: null,
      resignedBy: null,
      signedBy: null,
    }
  );
}

function signatureState(
  filePath: string,
  sha256: string,
  store: TrustStore,
): { state: ReportSignatureState; fingerprint: string | null; trusted: boolean | null } {
  const inspected = inspectReceiptSignature(filePath, sha256);
  if (!inspected.present) return { state: 'unsigned', fingerprint: null, trusted: null };
  const fingerprint = inspected.fingerprint;
  if (inspected.ok !== true) return { state: 'invalid', fingerprint, trusted: null };
  const trusted = applyTrust(
    {
      present: true,
      ok: true,
      alg: inspected.alg,
      fingerprint,
      reason: null,
      trusted: null,
    },
    store,
  ).trusted;
  return { state: 'valid', fingerprint, trusted };
}

/** Text the page will show. Secrets are masked unless exposure is unredacted. URLs are defanged. */
function shownField(value: string | null | undefined, exposure: ReportExposure, fallback = '(none)'): string {
  if (value === null || value === undefined || value === '') return fallback;
  const raw = exposure === 'unredacted' ? String(value) : redactSecretsInText(String(value));
  return defangUrls(raw);
}

/** Same publishRedactedReceipt path share and session export use. */
function redactedFormHash(markdown: string): string {
  return sha256Hex(canonicalBody(publishRedactedReceipt(markdown, { maskHost: true })));
}

function redactedCanonical(markdown: string, actual: string): string | null {
  const hash = redactedFormHash(markdown);
  return hash === actual ? null : hash;
}

/**
 * Canonical hash of the local same-id receipt, when a package report is
 * built while that file is still in this store. Prefer a hash that is not
 * the packaged hash so a later deletion is still listed.
 */
function knownOriginalSha256(cwd: string, id: string, packagedSha: string): string | null {
  const files: string[] = [];
  collectMarkdown(receiptsDir(cwd), files, 0);
  const same: string[] = [];
  for (const file of files) {
    const item = indexedReceipt(file);
    if (!item || !item.verified || item.id !== id) continue;
    same.push(item.sha256);
  }
  return same.find((hash) => hash !== packagedSha) ?? same[0] ?? null;
}

function buildOne(
  filePath: string,
  exposure: ReportExposure,
  store: TrustStore,
  provenance: Map<string, ResignClaim>,
  manifestEntry?: SessionManifestReceipt,
  cwd?: string,
): BuiltReceipt {
  const original = readFileSync(filePath, 'utf8');
  const integrity = receiptIntegrity(original);
  const ref = readLocalReceipt(filePath);
  const id = manifestEntry?.id || ref?.id || integrity.actual;
  const parent = manifestEntry?.parent ?? ref?.meta.parent ?? null;
  const agent = manifestEntry?.agent ?? ref?.meta.agent ?? null;
  const sig = signatureState(filePath, integrity.actual, store);
  const claim = manifestEntry
    ? {
        originalFingerprint: manifestEntry.originalFingerprint,
        resignedBy: manifestEntry.resignedBy,
        signedBy: manifestEntry.signedBy ?? null,
      }
    : claimFor(provenance, integrity.actual);
  const shown = displayMarkdown(original, exposure);
  const header = parseSessionHeader(shown);
  const meta = parseLinkMeta(original);
  const show = (value: string | null | undefined, fallback = '(none)') => shownField(value, exposure, fallback);
  let summary = plainReportText(section(shown, '## Summary'));
  if (exposure !== 'redacted') {
    const host = headerValue(header, shown, 'Host');
    if (host) summary = `Host: ${show(host, host)}\n${summary}`.trim();
  }
  const risks = risksFrom(shown).map((item) => ({
    severity: show(item.severity, item.severity),
    code: show(item.code, item.code),
    detail:
      exposure !== 'unredacted' && isHighSecretRiskCode(item.code)
        ? '[REDACTED]'
        : show(item.detail, item.detail),
  }));
  const identity = {
    verified: integrity.ok,
    signature: sig.state,
    trusted: sig.trusted,
  };
  const originalSha256 = manifestEntry && cwd ? knownOriginalSha256(cwd, id, integrity.actual) : null;
  const payload: ReportReceiptPayload = {
    id,
    sha256: integrity.actual,
    redactedSha256: redactedCanonical(original, integrity.actual),
    originalSha256,
    parent,
    agent,
    verified: identity.verified,
    signature: identity.signature,
    fingerprint: sig.fingerprint,
    trusted: identity.trusted,
    originalFingerprint: claim.originalFingerprint,
    resignedBy: claim.resignedBy,
    signedBy: claim.signedBy,
    pills: reportPills(identity),
    timestamp: show(meta.timestamp || headerValue(header, shown, 'Timestamp')),
    branch: show(headerValue(header, shown, 'Branch')),
    head: show(headerValue(header, shown, 'HEAD')),
    range: show(plainReportText(headerValue(header, shown, 'Range'))),
    message: show(headerValue(header, shown, 'Message')),
    summary: summary ? show(summary, summary) : '(none)',
    commands: commandsFrom(shown).map((command) => show(command, command)),
    files: filesFrom(shown).map((file) => show(file, file)),
    risks,
    review: show(section(shown, '## What to review')),
    commits: show(section(shown, '## Commits')),
    diffs: show(section(shown, '## Diff summaries').split('\n').slice(0, 40).join('\n')),
  };
  const toolBody = section(shown, '## Tool calls');
  const toolCalls = toolBody ? show(toolBody) : '';
  if (toolCalls) payload.toolCalls = toolCalls;
  return {
    payload,
    node: {
      id,
      parent,
      agent,
      verified: integrity.ok,
      timestamp: meta.timestamp,
      path: filePath,
      aliases: ref?.aliases ?? [id, integrity.actual],
    },
  };
}

function receiptFileName(filePath: string, sha256: string): string {
  const stem = basename(filePath).replace(/\.md$/i, '');
  if (SAFE_STEM.test(stem) && !stem.includes('..')) return `${stem}.report.html`;
  return `report-${sha256.slice(0, 12)}.report.html`;
}

function sessionFileName(sessionId: string): string {
  if (SAFE_DIR_ID.test(sessionId) && !sessionId.includes('..')) return `${sessionId}.report.html`;
  const digest = createHash('sha256').update(sessionId, 'utf8').digest('hex').slice(0, 12);
  return `session-${digest}.report.html`;
}

function resolveReportOut(cwd: string, fileName: string, out?: string): string {
  return resolveDirOrFileOut(cwd, out, fileName, dirname(receiptsDir(cwd)));
}

function verifyCommandsFor(
  htmlPath: string,
  subject: 'receipt' | 'session',
  receiptBases: string[],
  receiptsArg: string | null,
  packageBase: string | null,
): string[] {
  const htmlBase = basename(htmlPath);
  const commands = [`agent-receipt report verify ${htmlBase}`];
  if (receiptsArg) commands[0] = `${commands[0]} --receipts ${receiptsArg}`;
  for (const base of receiptBases) {
    commands.push(`agent-receipt verify ${base}`);
  }
  if (receiptBases[0]) commands.push(`agent-receipt verify --require-sig ${receiptBases[0]}`);
  if (subject === 'session' && packageBase) {
    commands.push(`agent-receipt session import ${packageBase} --dry-run`);
  }
  return commands;
}

function treeFrom(session: string, built: BuiltReceipt[]): string {
  const local = new Map<string, { id: string }>();
  for (const item of built) {
    for (const alias of item.node.aliases) local.set(alias, { id: item.node.id });
  }
  const nodes = buildSessionNodes(built.map((item) => item.node), local);
  const aliasToId = new Map<string, string>();
  for (const item of built) {
    aliasToId.set(item.node.id, item.node.id);
    for (const alias of item.node.aliases) aliasToId.set(alias, item.node.id);
  }
  const provenance = new Map<string, ResignClaim>();
  for (const item of built) {
    provenance.set(item.node.id, {
      originalFingerprint: item.payload.originalFingerprint,
      resignedBy: item.payload.resignedBy,
      signedBy: item.payload.signedBy,
    });
  }
  return formatSessionTree(session, nodes as SessionNode[], aliasToId, provenance);
}

function emptyResult(exitCode: 0 | 1 | 2, reason: string): ReportCommandResult {
  return {
    ok: false,
    command: 'report',
    version: VERSION,
    exitCode,
    verdict: null,
    htmlPath: null,
    sigPath: null,
    signed: false,
    fingerprint: null,
    redacted: true,
    exposure: null,
    receiptCount: 0,
    reason,
  };
}

function emitReport(result: ReportCommandResult, json: boolean): number {
  if (json) {
    console.log(JSON.stringify(result));
    return result.exitCode;
  }
  if (result.exitCode === 1 || !result.htmlPath || !result.verdict) {
    console.error(color.red('Error:') + ` ${result.reason ?? 'report failed'}`);
    return result.exitCode;
  }
  const paint =
    result.verdict === 'VERIFIED'
      ? color.green
      : result.verdict === 'FAILED'
        ? color.red
        : color.yellow;
  console.log(`${paint(result.verdict)}  ${result.htmlPath}`);
  console.log(`  signature: ${result.fingerprint ?? 'unsigned'}`);
  if (result.exposure && result.exposure !== 'redacted') {
    console.log('  UNREDACTED');
  }
  if (result.reason) console.error(result.reason);
  return result.exitCode;
}

function reportTrustedFor(keys: LoadedKeys | null, store: TrustStore): boolean | null {
  if (!keys) return null;
  const status: SignatureStatus = {
    present: true,
    ok: true,
    alg: 'ed25519',
    fingerprint: keys.fingerprint,
    reason: null,
    trusted: null,
  };
  return applyTrust(status, store).trusted;
}

function aliasesOf(built: BuiltReceipt[]): Set<string> {
  const aliases = new Set<string>();
  for (const item of built) {
    aliases.add(item.payload.id);
    aliases.add(item.payload.sha256);
    if (item.payload.redactedSha256) aliases.add(item.payload.redactedSha256);
    for (const alias of item.node.aliases) aliases.add(alias);
  }
  return aliases;
}

/**
 * Why this tree cannot be VERIFIED. Null when every receipt's hash and signature hold.
 * A one-receipt report says "receipt". "session root" is only for a session report.
 */
function verificationFailure(built: BuiltReceipt[], subject: 'receipt' | 'session'): string | null {
  const aliases = aliasesOf(built);
  const failed = built.filter((item) => !item.payload.verified || item.payload.signature === 'invalid');
  if (!failed.length) return null;
  const roots = failed.filter((item) => !item.payload.parent || !aliases.has(item.payload.parent));
  const focus = roots[0] ?? failed[0];
  const role = subject === 'session' && roots.length ? 'session root' : 'receipt';
  return `${role} ${focus.payload.id} failed verification`;
}

function writeReport(
  cwd: string,
  opts: ReportOptions,
  subject: 'receipt' | 'session',
  session: string | null,
  manifestSha256: string | null,
  built: BuiltReceipt[],
  fileName: string,
  receiptsArg: string | null,
  packageBase: string | null,
  sourcePaths: string[],
  sessionFailure: string | null = null,
): ReportCommandResult {
  if (!built.length) return emptyResult(1, 'report has no receipts');
  built.sort((a, b) => (a.payload.id < b.payload.id ? -1 : a.payload.id > b.payload.id ? 1 : 0));
  let htmlPath = '';
  try {
    htmlPath = resolveReportOut(cwd, fileName, opts.out);
    const inputs = sourcePaths.length ? sourcePaths : built.map((item) => item.node.path);
    assertProtectedOut(htmlPath, exportProtectedPaths(cwd, inputs, { companionJson: false }), 'export');
  } catch (err) {
    if (err instanceof OutGuardError) {
      if (err.message === 'refusing to write the export over the receipt') {
        return emptyResult(1, `refusing to overwrite the source receipt: ${htmlPath}`);
      }
      return emptyResult(1, err.message);
    }
    const message = err instanceof Error ? err.message : String(err);
    return emptyResult(1, message);
  }
  const exposure = exposureOf(opts);
  const store = loadTrustedFingerprints(cwd, { extra: opts.trustedKeys });
  const keys = tryLoadKeys(cwd);
  const reportTrusted = reportTrustedFor(keys, store);
  const receipts = built.map((item) => item.payload);
  const broken = verificationFailure(built, subject);
  const failure = broken ?? sessionFailure;
  const verdict = failure ? 'FAILED' : decideVerdict(keys !== null, reportTrusted, receipts);
  const verifyCommands = verifyCommandsFor(
    htmlPath,
    subject,
    built.map((item) => basename(item.node.path)),
    receiptsArg,
    packageBase,
  );
  const generatedAt = new Date().toISOString();
  const tree = subject === 'session' ? treeFrom(session ?? '', built) : null;
  const payload: ReportPayload = {
    kind: 'agent-receipt-report',
    version: 1,
    renderVersion: REPORT_RENDER_VERSION,
    cliVersion: VERSION,
    generatedAt,
    subject,
    session,
    manifestSha256,
    exposure,
    verdict,
    title: reportTitle(verdict),
    banner: reportBanner(verdict, keys !== null, reportTrusted, keys?.fingerprint ?? null),
    unredacted: reportUnredacted(exposure),
    verifyCommands,
    tree,
    receipts,
  };
  const signature = keys ? createSignatureDocument(reportPayloadHash(payload), keys) : null;
  const html = renderReportHtml(payload, signature);
  mkdirSync(dirname(htmlPath), { recursive: true });
  writeFileSync(htmlPath, html, 'utf8');
  let sigPath: string | null = null;
  if (signature) {
    sigPath = signaturePathFor(htmlPath);
    writeSignatureDocument(sigPath, signature);
  }
  const exitCode: 0 | 2 = verdict === 'FAILED' ? 2 : 0;
  return {
    ok: exitCode === 0,
    command: 'report',
    version: VERSION,
    exitCode,
    verdict,
    htmlPath,
    sigPath,
    signed: signature !== null,
    fingerprint: signature?.fingerprint ?? null,
    redacted: exposure === 'redacted',
    exposure,
    receiptCount: receipts.length,
    reason: exitCode === 2 ? failure ?? 'one or more receipts failed verify or had an invalid signature' : null,
  };
}

function sessionPackageReport(cwd: string, pathArg: string, opts: ReportOptions): ReportCommandResult {
  const located = locateSessionPackage(cwd, pathArg);
  if (!located.manifestExists) {
    return emptyResult(1, `session package not found: ${pathArg}`);
  }
  let manifest;
  try {
    manifest = loadSessionManifest(located.manifestPath);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return emptyResult(1, message);
  }
  const exposure = exposureOf(opts);
  const store = loadTrustedFingerprints(cwd, { extra: opts.trustedKeys });
  const built: BuiltReceipt[] = [];
  for (const entry of manifest.receipts) {
    const filePath = join(located.packageDir, entry.path);
    if (!existsSync(filePath)) {
      return emptyResult(1, `packaged receipt is missing: ${entry.path}`);
    }
    built.push(buildOne(filePath, exposure, store, new Map(), entry, cwd));
  }
  const manifestSha256 = sha256FileBytes(located.manifestPath);
  return writeReport(
    cwd,
    opts,
    'session',
    manifest.session,
    manifestSha256,
    built,
    sessionFileName(manifest.session),
    basename(located.packageDir),
    basename(located.packageDir),
    [],
  );
}

function localSessionReport(cwd: string, sessionId: string, opts: ReportOptions): ReportCommandResult {
  const collected = collectSession(cwd, sessionId);
  if (collected.empty) return emptyResult(1, collected.reason ?? `no receipts in session ${sessionId}`);
  const exposure = exposureOf(opts);
  const store = loadTrustedFingerprints(cwd, { extra: opts.trustedKeys });
  const provenance = loadResignProvenance(cwd);
  const built = collected.nodes.map((node) => buildOne(node.path, exposure, store, provenance));
  const outName = basename(receiptsDir(cwd));
  const sessionFailure = collected.exitCode !== 0 ? collected.reason ?? 'session verification failed' : null;
  return writeReport(
    cwd,
    opts,
    'session',
    collected.session,
    null,
    built,
    sessionFileName(collected.session),
    outName,
    null,
    collected.nodes.map((node) => node.path),
    sessionFailure,
  );
}

function oneReceiptReport(cwd: string, pathArg: string, opts: ReportOptions): ReportCommandResult {
  const target = pathArg === 'last' ? findLatestReceipt(cwd) : resolve(cwd, pathArg);
  if (!target || !existsSync(target) || !statSync(target).isFile()) {
    return emptyResult(1, pathArg === 'last' ? 'No receipt found under the configured outDir.' : `Receipt not found: ${pathArg}`);
  }
  const exposure = exposureOf(opts);
  const store = loadTrustedFingerprints(cwd, { extra: opts.trustedKeys });
  const provenance = loadResignProvenance(cwd);
  const built = buildOne(target, exposure, store, provenance);
  const session = parseLinkMeta(readFileSync(target, 'utf8')).session;
  return writeReport(
    cwd,
    opts,
    'receipt',
    session,
    null,
    [built],
    receiptFileName(target, built.payload.sha256),
    null,
    null,
    [target],
  );
}

function looksLikeSessionPackage(cwd: string, pathArg: string): boolean {
  const located = locateSessionPackage(cwd, pathArg);
  if (located.inputKind === 'manifest') return true;
  if (basename(resolve(cwd, pathArg)).endsWith('.session')) return true;
  return located.manifestExists && located.inputKind === 'directory';
}

/**
 * A `*.report.html` name, or any file that contains the payload block marker
 * (a report renamed to `.md` included). A missing `*.report.html` path is
 * still refused so the name alone cannot be wrapped into another report.
 */
function isReportInput(cwd: string, pathArg: string): boolean {
  if (/\.report\.html$/i.test(basename(pathArg))) return true;
  const abs = resolve(cwd, pathArg);
  let st;
  try {
    st = statSync(abs);
  } catch {
    return false;
  }
  if (!st.isFile()) return false;
  let text: string;
  try {
    text = readFileSync(abs, 'utf8');
  } catch {
    return false;
  }
  return text.includes(REPORT_PAYLOAD_MARKER);
}

/**
 * Write one self-contained HTML report.
 * Default path is the sibling of outDir: `.agent-receipt/<stem>.report.html`.
 * `--out` names the file, or a directory (existing, or a trailing slash)
 * that receives `<stem>.report.html`.
 */
export function cmdReport(
  cwd: string,
  pathArg: string | undefined,
  opts: ReportOptions = {},
): number {
  if (opts.session && pathArg) {
    return emitReport(emptyResult(1, 'pass a receipt path or --session, not both'), Boolean(opts.json));
  }
  if (pathArg && pathArg !== 'last' && isReportInput(cwd, pathArg)) {
    return emitReport(emptyResult(1, 'input is already a report; use report verify'), Boolean(opts.json));
  }
  let result: ReportCommandResult;
  if (opts.session) {
    result = localSessionReport(cwd, opts.session, opts);
  } else if (!pathArg) {
    result = emptyResult(1, 'report requires a receipt path, last, or --session <id>');
  } else if (pathArg !== 'last' && looksLikeSessionPackage(cwd, pathArg)) {
    result = sessionPackageReport(cwd, pathArg, opts);
  } else {
    result = oneReceiptReport(cwd, pathArg, opts);
  }
  return emitReport(result, Boolean(opts.json));
}

/** `.md` is case-insensitive. `.prove.md` is not a receipt. */
function isReceiptMarkdownName(name: string): boolean {
  return /\.md$/i.test(name) && !/\.prove\.md$/i.test(name);
}

/**
 * Markdown candidates for `report verify`. The depth cap of 4 means the
 * start directory is depth 0 and a directory four levels down is still read.
 * A file at depth 5 or deeper is not a candidate.
 * The same walk applies equally to pages from report last, verify, and session.
 * Directory symlinks are not followed. `node_modules`, `.git`, and `keys`
 * are skipped.
 */
function collectMarkdown(dir: string, out: string[], depth: number): void {
  if (depth > 4 || !existsSync(dir)) return;
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    return;
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    if (name === 'node_modules' || name === '.git' || name === 'keys') continue;
    const filePath = join(dir, name);
    let child;
    try {
      child = lstatSync(filePath);
    } catch {
      continue;
    }
    if (child.isSymbolicLink()) {
      if (isReceiptMarkdownName(name)) out.push(filePath);
      continue;
    }
    if (child.isDirectory()) collectMarkdown(filePath, out, depth + 1);
    else if (child.isFile() && isReceiptMarkdownName(name)) out.push(filePath);
  }
}

interface IndexedReceipt {
  path: string;
  id: string;
  /** Canonical hash of the file bytes. */
  sha256: string;
  /** Hash the footer still claims, when it is 64 hex. */
  embedded: string | null;
  verified: boolean;
  signature: ReportSignatureState;
  fingerprint: string | null;
  text: string;
  /** The path itself is a symlink. The target bytes are not trusted. */
  symlink: boolean;
}

function indexedReceipt(filePath: string): IndexedReceipt | null {
  let symlink = false;
  try {
    symlink = lstatSync(filePath).isSymbolicLink();
  } catch {
    return null;
  }
  let text: string;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
  const integrity = receiptIntegrity(text);
  const ref = readLocalReceipt(filePath);
  const sig = inspectReceiptSignature(filePath, integrity.actual);
  const signature: ReportSignatureState = !sig.present ? 'unsigned' : sig.ok === true ? 'valid' : 'invalid';
  const embeddedRaw = extractEmbeddedHash(text);
  const embedded = embeddedRaw && HEX64.test(embeddedRaw) ? embeddedRaw : null;
  return {
    path: filePath,
    id: ref?.id || integrity.actual,
    sha256: integrity.actual,
    embedded,
    verified: integrity.ok,
    signature,
    fingerprint: sig.fingerprint,
    text,
    symlink,
  };
}

interface LocalCheck {
  checked: number;
  skipped: number;
  failed: number;
  notChecked: number;
  reason: string | null;
  /** Payload-only note when a missing receipt has an honest unsigned prune. */
  note: string | null;
  /** Stderr warning when an unsigned prune is not backed by a command or retention config. */
  warning: string | null;
}

const PRUNE_ABSENT_NOTE = 'receipt absent; audit.jsonl (unsigned) records a prune';
const PRUNE_UNSIGNED_WARN =
  'audit.jsonl is unsigned; no retention config and no recorded prune command';
const PRUNE_RETENTION_CLAIMED = ' (retention source claimed but no retention config found)';
/**
 * A prune up to this long before a capture that exists in this log is clock
 * skew, not tampering. More than this exits 2.
 */
const PRUNE_BEFORE_CAPTURE_SKEW_MS = 5000;

/**
 * A session-package report records `manifestSha256`. Local-store reports leave
 * it null. Redact-then-hash (`publishRedactedReceipt`) is allowed only for the
 * package report. A raw sha256 equal to the recorded `redactedSha256` is a
 * byte match for both, because that hash is a signed value.
 */
function isPackageReport(payload: ReportPayload): boolean {
  return typeof payload.manifestSha256 === 'string' && HEX64.test(payload.manifestSha256);
}

function acceptedHashes(receipt: ReportReceiptPayload): Set<string> {
  const accepted = new Set<string>([receipt.sha256]);
  if (receipt.redactedSha256) accepted.add(receipt.redactedSha256);
  if (receipt.originalSha256) accepted.add(receipt.originalSha256);
  return accepted;
}

/**
 * Fingerprint a byte-match sidecar must carry. The receipt file's own
 * fingerprint wins. originalFingerprint is the pre-export key and is
 * required on the redact-then-hash path instead, so a same-key package
 * rewrite still matches the imported sidecar.
 */
function payloadSignedFingerprint(receipt: ReportReceiptPayload): string | null {
  if (receipt.fingerprint) return receipt.fingerprint;
  if (receipt.originalFingerprint) return receipt.originalFingerprint;
  return null;
}

/** Unsigned payload: a valid stray sidecar is ignored. Invalid already failed. */
function signedSidecarProblem(item: IndexedReceipt, required: string | null, where: string): string | null {
  if (!required) return null;
  if (item.signature !== 'valid' || (item.fingerprint ?? null) !== required) {
    return `${where} signature mismatch`;
  }
  return null;
}

/** Redacted body equals the packaged hash (`sha256`) or a recorded `redactedSha256`. */
function redactedFormMatches(item: IndexedReceipt, receipt: ReportReceiptPayload): boolean {
  const redacted = redactedFormHash(item.text);
  if (redacted === receipt.sha256) return true;
  return Boolean(receipt.redactedSha256 && redacted === receipt.redactedSha256);
}

/**
 * On the redact-then-hash path, a signed source names the sidecar that must
 * still be present. `signedBy` with a null `originalFingerprint` is an
 * unsigned source that export signed; an absent sidecar is allowed there.
 */
function requiredRedactedFingerprint(receipt: ReportReceiptPayload): string | null {
  if (receipt.originalFingerprint) return receipt.originalFingerprint;
  if (receipt.signedBy) return null;
  return receipt.fingerprint;
}

function unacceptableReason(
  item: IndexedReceipt,
  receipt: ReportReceiptPayload,
  packageReport: boolean,
): string | null {
  const where = `receipt ${receipt.id} at ${item.path}`;
  if (item.symlink) return `${where} is a symlink`;
  if (!item.verified) return `${where} fails integrity`;
  if (item.signature === 'invalid') return `${where} signature mismatch`;
  const required = payloadSignedFingerprint(receipt);
  const byteMatch =
    item.sha256 === receipt.sha256 ||
    Boolean(receipt.redactedSha256 && item.sha256 === receipt.redactedSha256);
  if (byteMatch) return signedSidecarProblem(item, required, where);
  if (packageReport && redactedFormMatches(item, receipt)) {
    const required = requiredRedactedFingerprint(receipt);
    if (required && (item.signature !== 'valid' || (item.fingerprint ?? null) !== required)) {
      return `${where} signature mismatch`;
    }
    return null;
  }
  return `${where} differs from the signed payload`;
}

function auditEventMatches(
  event: { sha256?: string | null; path?: string | null },
  receipt: ReportReceiptPayload,
  hashes: Set<string>,
): boolean {
  if (event.sha256 && hashes.has(event.sha256)) return true;
  return Boolean(event.path && event.path.includes(receipt.id));
}

function retentionConfigured(cwd: string): boolean {
  const cfg = loadConfig(cwd);
  return typeof cfg.maxCount === 'number' || typeof cfg.maxAgeDays === 'number' || cfg.autoPrune === true;
}

/**
 * No warning when this store has retention config, or the newest prune line
 * records `source: command`. `source: retention` keeps the warning unless
 * that config is actually present.
 */
function pruneWarning(cwd: string, source: string | undefined): string | null {
  if (retentionConfigured(cwd) || source === 'command') return null;
  if (source === 'retention') return PRUNE_UNSIGNED_WARN + PRUNE_RETENTION_CLAIMED;
  return PRUNE_UNSIGNED_WARN;
}

function eventTime(ts: string | undefined): number {
  const parsed = Date.parse(ts ?? '');
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

interface StoreCatalog {
  listed: boolean;
  pruned: boolean;
  unreadable: boolean;
  /** Exit 2. A prune timestamped too far before a capture that exists here. */
  pruneInvalid: string | null;
  /** Payload-only prune warning, or null when the prune is backed by a command or config. */
  pruneWarn: string | null;
}

/**
 * The newest matching audit event wins. A missing capture, wrap, or watch
 * event is not tampering: the prune is payload-only. Exit 2 only when one
 * of those events exists in this log and the prune is more than
 * PRUNE_BEFORE_CAPTURE_SKEW_MS before it. The log is unsigned, so a
 * payload-only prune is not proof the prune command ran.
 */
function storeCatalog(cwd: string, receipt: ReportReceiptPayload): StoreCatalog {
  const hashes = acceptedHashes(receipt);
  let indexListed = false;
  let unreadable = false;
  try {
    const { index, existed } = readIndexStrict(cwd);
    if (existed) {
      for (const entry of index.receipts) {
        if (!entry) continue;
        if (auditEventMatches(entry, receipt, hashes)) indexListed = true;
      }
    }
  } catch {
    unreadable = true;
  }
  let newest: { event: string } | null = null;
  let newestPrune: { ts?: string; source?: string } | null = null;
  let newestCapture: { ts?: string } | null = null;
  let sawPrune = false;
  if (existsSync(auditLogPath(cwd))) {
    try {
      for (const event of loadAuditEvents(cwd)) {
        if (!auditEventMatches(event, receipt, hashes)) continue;
        newest = event;
        if (event.event === 'prune') {
          sawPrune = true;
          newestPrune = event;
        } else if (event.event === 'capture' || event.event === 'wrap' || event.event === 'watch') {
          newestCapture = event;
        }
      }
    } catch {
      unreadable = true;
    }
  }
  const pruneExplains = newest?.event === 'prune' || (sawPrune && !indexListed);
  if (pruneExplains) {
    if (newestCapture) {
      const pruneTs = eventTime(newestPrune?.ts);
      const captureTs = eventTime(newestCapture.ts);
      if (!Number.isFinite(pruneTs) || !Number.isFinite(captureTs)) {
        return {
          listed: false,
          pruned: false,
          unreadable,
          pruneInvalid: `receipt ${receipt.id} prune timestamp is not a date`,
          pruneWarn: null,
        };
      }
      if (captureTs - pruneTs > PRUNE_BEFORE_CAPTURE_SKEW_MS) {
        return {
          listed: false,
          pruned: false,
          unreadable,
          pruneInvalid: `receipt ${receipt.id} prune is timestamped before its capture`,
          pruneWarn: null,
        };
      }
    }
    return {
      listed: false,
      pruned: true,
      unreadable,
      pruneInvalid: null,
      pruneWarn: pruneWarning(cwd, newestPrune?.source),
    };
  }
  return {
    listed: indexListed || newest !== null,
    pruned: false,
    unreadable,
    pruneInvalid: null,
    pruneWarn: null,
  };
}

/**
 * Every candidate for a payload receipt must be acceptable.
 * Candidates are every file in the search scope whose parsed id matches,
 * plus every file whose raw sha256 or embedded hash is in the accepted set.
 * Names, subdirectories, and sessions do not narrow the set. `.MD` counts.
 * A symlink candidate is never acceptable.
 * A raw sha256 match, and a raw sha256 equal to `redactedSha256`, both
 * require a valid sidecar when the payload records a fingerprint or
 * originalFingerprint. An unsigned payload ignores a valid stray sidecar.
 * Redact-then-hash is package-only, and a non-null original fingerprint
 * then requires that sidecar.
 * `--receipts` with no candidate exits 2. Without it, a receipt the store
 * index or audit log still lists exits 2 (deleted in place). A prune is
 * payload-only when this log has no capture, wrap, or watch event for that
 * receipt, and when such an event exists and the prune is at most 5 seconds
 * before it. The note is "receipt absent; audit.jsonl (unsigned) records a prune".
 * Every failure is recorded, not only the first.
 */
function checkLocalReceipts(
  cwd: string,
  payload: ReportPayload,
  dirs: string[],
  explicitReceipts: boolean,
): LocalCheck {
  const files: string[] = [];
  const seen = new Set<string>();
  for (const dir of dirs) {
    if (!dir || seen.has(dir)) continue;
    seen.add(dir);
    collectMarkdown(dir, files, 0);
  }
  const indexed: IndexedReceipt[] = [];
  const byId = new Map<string, IndexedReceipt[]>();
  for (const file of files) {
    const item = indexedReceipt(file);
    if (!item) continue;
    indexed.push(item);
    const idList = byId.get(item.id);
    if (idList) idList.push(item);
    else byId.set(item.id, [item]);
  }
  const packageReport = isPackageReport(payload);
  let checked = 0;
  let skipped = 0;
  let failed = 0;
  let notChecked = 0;
  let reason: string | null = null;
  let noteText: string | null = null;
  let warning: string | null = null;
  const note = (next: string): void => {
    reason = reason ? `${reason}; ${next}` : next;
  };
  for (const receipt of payload.receipts) {
    const accepted = acceptedHashes(receipt);
    const identity = new Map<string, IndexedReceipt>();
    for (const item of byId.get(receipt.id) ?? []) identity.set(item.path, item);
    for (const item of indexed) {
      if (accepted.has(item.sha256) || (item.embedded !== null && accepted.has(item.embedded))) {
        identity.set(item.path, item);
      }
    }
    const candidates = [...identity.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    if (!candidates.length) {
      if (explicitReceipts) {
        failed += 1;
        note(`receipt ${receipt.id} referenced by report not found in --receipts`);
        continue;
      }
      const catalog = storeCatalog(cwd, receipt);
      if (catalog.unreadable) {
        failed += 1;
        note(`receipt ${receipt.id} is missing and the store index or audit log could not be read`);
        continue;
      }
      if (catalog.pruneInvalid) {
        failed += 1;
        note(catalog.pruneInvalid);
        continue;
      }
      if (catalog.pruned) {
        skipped += 1;
        notChecked += 1;
        if (!noteText) noteText = PRUNE_ABSENT_NOTE;
        if (catalog.pruneWarn) warning = catalog.pruneWarn;
        continue;
      }
      if (catalog.listed) {
        failed += 1;
        note(`receipt ${receipt.id} is missing but the store index or audit log still lists it`);
        continue;
      }
      skipped += 1;
      notChecked += 1;
      continue;
    }
    const problems: string[] = [];
    for (const item of candidates) {
      const problem = unacceptableReason(item, receipt, packageReport);
      if (problem) problems.push(problem);
    }
    if (problems.length) {
      failed += 1;
      note(problems.join('; '));
      continue;
    }
    checked += 1;
  }
  return { checked, skipped, failed, notChecked, reason, note: noteText, warning };
}

/** A non-zero exit never reports VERIFIED. The page's claim is not a pass. */
function shownVerdict(result: ReportVerifyResult): ReportVerifyVerdict | null {
  if (
    result.exitCode !== 0 &&
    (result.verdict === 'VERIFIED' || result.verdict === 'VERIFIED_PAYLOAD_ONLY')
  ) {
    return 'FAILED';
  }
  return result.verdict;
}

function receiptCountLabel(count: number): string {
  return `${count} ${count === 1 ? 'receipt' : 'receipts'} not checked`;
}

function verdictLabel(
  verdict: ReportVerifyVerdict | null,
  notChecked: number,
  exitCode: 0 | 1 | 2,
): string {
  if (exitCode !== 0 && verdict === 'UNSIGNED') return 'FAILED (unsigned)';
  if (verdict === 'UNSIGNED' && exitCode === 0 && notChecked > 0) {
    return `UNSIGNED (${receiptCountLabel(notChecked)})`;
  }
  if (verdict === 'VERIFIED_PAYLOAD_ONLY') {
    return `VERIFIED (payload only; ${receiptCountLabel(notChecked)})`;
  }
  return verdict ?? 'FAILED';
}

function emitVerify(result: ReportVerifyResult, json: boolean): 0 | 1 | 2 {
  const verdict = shownVerdict(result);
  const warning = result.warning ?? null;
  const printed = { ...result, verdict, warning };
  if (json) {
    console.log(JSON.stringify(printed));
    return result.exitCode;
  }
  if (result.exitCode === 1) {
    console.error(color.red('Error:') + ` ${result.reason ?? 'report verify failed'}`);
    return 1;
  }
  const label = verdictLabel(verdict, result.notChecked, result.exitCode);
  const paint =
    result.exitCode === 0 && verdict === 'VERIFIED' ? color.green : result.exitCode === 0 ? color.yellow : color.red;
  console.log(`${paint(label)}  report verify`);
  if (result.fingerprint) console.log(`  fingerprint: ${result.fingerprint}`);
  if (warning) console.error(`warn: ${warning}`);
  if (result.reason) console.error(result.reason);
  const examined = result.checked + result.skipped + result.failed;
  if (examined > 0) {
    console.log(`  checked: ${result.checked}  skipped: ${result.skipped}  failed: ${result.failed}`);
  }
  return result.exitCode;
}

/** CRLF only when a CR is followed by LF. A bare CR is named on its own. */
function lineEndingError(bytes: Buffer): string | null {
  let crlf = false;
  let lone = false;
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== 0x0d) continue;
    if (i + 1 < bytes.length && bytes[i + 1] === 0x0a) {
      crlf = true;
      i += 1;
    } else {
      lone = true;
    }
  }
  if (lone && crlf) return `${CR_PAGE_MESSAGE}; ${CRLF_PAGE_MESSAGE}`;
  if (lone) return CR_PAGE_MESSAGE;
  if (crlf) return CRLF_PAGE_MESSAGE;
  return null;
}

function readSignatureFile(sigPath: string): { doc: SignatureDocument | null; reason: string | null } {
  if (!existsSync(sigPath)) return { doc: null, reason: null };
  let text: string;
  try {
    text = readFileSync(sigPath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { doc: null, reason: `unreadable detached signature (${detail})` };
  }
  try {
    return { doc: JSON.parse(text) as SignatureDocument, reason: null };
  } catch {
    return { doc: null, reason: 'detached signature is malformed JSON' };
  }
}

function sameSignature(a: SignatureDocument, b: SignatureDocument): boolean {
  return (
    a.alg === b.alg &&
    a.version === b.version &&
    a.sha256 === b.sha256 &&
    a.fingerprint === b.fingerprint &&
    a.signature === b.signature &&
    a.publicKey === b.publicKey
  );
}

function failedVerdictReason(payload: ReportPayload): string {
  const known = new Set<string>();
  for (const receipt of payload.receipts) {
    known.add(receipt.id);
    known.add(receipt.sha256);
    if (receipt.redactedSha256) known.add(receipt.redactedSha256);
  }
  const failed = payload.receipts.filter((receipt) => !receipt.verified || receipt.signature === 'invalid');
  const roots = failed.filter((receipt) => !receipt.parent || !known.has(receipt.parent));
  if (payload.subject === 'session' && roots[0]) return `session root ${roots[0].id} failed verification`;
  if (failed[0]) return `receipt ${failed[0].id} failed verification`;
  return 'report verdict is FAILED';
}

/**
 * `--receipts` must name a directory we can list. A missing or unreadable
 * path is usage (exit 1), not a failed proof.
 */
function receiptsDirError(cwd: string, dir: string | undefined): string | null {
  if (!dir) return null;
  const abs = resolve(cwd, dir);
  if (!existsSync(abs)) return `--receipts directory not found: ${dir}`;
  let st;
  try {
    st = statSync(abs);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return `--receipts directory is unreadable: ${dir} (${detail})`;
  }
  if (!st.isDirectory()) return `--receipts is not a directory: ${dir}`;
  try {
    readdirSync(abs);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return `--receipts directory is unreadable: ${dir} (${detail})`;
  }
  return null;
}

/**
 * Check one report file.
 *
 * 1. Exactly one payload block and one signature block, outside comments.
 * 2. Signature over the canonical payload (`--require-sig` and trust as now).
 * 3. Re-render and require the same bytes (one trailing newline may be absent).
 * 4. Exit 0 only for a valid signature, a matching page, and verdict VERIFIED,
 *    or, without `--require-sig`, an honestly UNSIGNED page that matches.
 *    Verdict FAILED always exits 2. UNTRUSTED always exits 2. UNSIGNED with
 *    `--require-sig` exits 2. The printed verdict is never VERIFIED on a
 *    non-zero exit.
 * Candidate files are outDir, or `--receipts` when that flag is set.
 * Every same-id file, and every file whose raw or embedded hash is recorded,
 * must pass. A raw sha256 equal to the recorded sha256 or redactedSha256
 * matches. Redact-then-hash is package-only and requires the recorded
 * original fingerprint when that claim is set. A symlink exits 2.
 * `--receipts` requires every referenced receipt. Without it, a receipt
 * the store index or audit log still lists exits 2, unless the newest
 * audit event is a prune. A missing capture is payload-only. A prune more
 * than 5 seconds before a capture, wrap, or watch event that exists in
 * this log exits 2. The payload-only reason is
 * "receipt absent; audit.jsonl (unsigned) records a prune". audit.jsonl
 * is not signed. A present `audit.jsonl` in the store being searched,
 * with a broken hash chain, exits 2 and counts as failed. A missing audit
 * file is not a chain failure. A receipt the store does not list is not
 * checked, and a VERIFIED page is reported as VERIFIED_PAYLOAD_ONLY.
 */
function verifyOneReport(cwd: string, pathArg: string, opts: ReportVerifyOptions): 0 | 1 | 2 {
  const json = Boolean(opts.json);
  const fail = (exitCode: 1 | 2, reason: string, extra: Partial<ReportVerifyResult> = {}): 0 | 1 | 2 =>
    emitVerify(
      {
        ok: false,
        command: 'report-verify',
        version: VERSION,
        exitCode,
        verdict: extra.verdict ?? null,
        signed: extra.signed ?? false,
        fingerprint: extra.fingerprint ?? null,
        trusted: extra.trusted ?? null,
        receiptCount: extra.receiptCount ?? 0,
        checked: extra.checked ?? 0,
        skipped: extra.skipped ?? 0,
        failed: extra.failed ?? 0,
        notChecked: extra.notChecked ?? 0,
        reason,
        warning: extra.warning ?? null,
      },
      json,
    );
  const htmlPath = resolve(cwd, pathArg);
  if (!existsSync(htmlPath) || !statSync(htmlPath).isFile()) {
    return fail(1, `report not found: ${pathArg}`);
  }
  let bytes: Buffer;
  try {
    bytes = readFileSync(htmlPath);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return fail(1, `unreadable report (${detail})`);
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return fail(2, BOM_PAGE_MESSAGE);
  }
  const endings = lineEndingError(bytes);
  if (endings) return fail(2, endings);
  let html: string;
  try {
    html = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return fail(2, INVALID_UTF8_MESSAGE);
  }
  let extracted;
  try {
    extracted = parseReportHtml(html);
  } catch (err) {
    if (err instanceof ReportHtmlError) return fail(err.exitCode, err.message);
    const detail = err instanceof Error ? err.message : String(err);
    return fail(2, detail);
  }
  const payload = extracted.payload;
  const signature = extracted.signature;
  const base = {
    verdict: payload.verdict,
    signed: signature !== null,
    fingerprint: signature?.fingerprint ?? null,
    receiptCount: payload.receipts.length,
  };
  if (signature) {
    const embedded = verifySignature(signature, extracted.payloadHash);
    if (!embedded.ok) {
      return fail(2, embedded.reason ?? 'embedded report signature is invalid', base);
    }
  }
  const detached = readSignatureFile(signaturePathFor(htmlPath));
  if (detached.reason) return fail(2, detached.reason, base);
  if (detached.doc) {
    if (!signature || !sameSignature(detached.doc, signature)) {
      return fail(2, 'detached signature does not match the embedded signature', base);
    }
    const check = verifySignature(detached.doc, extracted.payloadHash);
    if (!check.ok) {
      return fail(2, check.reason ?? 'detached report signature is invalid', base);
    }
  }
  try {
    assertRenderedPage(html, payload, signature);
  } catch (err) {
    if (err instanceof ReportHtmlError) return fail(err.exitCode, err.message, base);
    const detail = err instanceof Error ? err.message : String(err);
    return fail(2, detail, base);
  }
  const signed = signature !== null;
  let trusted: boolean | null = null;
  if (signed && signature) {
    const store = loadTrustedFingerprints(cwd, { extra: opts.trustedKeys });
    const applied = applyTrust(
      {
        present: true,
        ok: true,
        alg: signature.alg,
        fingerprint: signature.fingerprint,
        reason: null,
        trusted: null,
      },
      store,
    );
    trusted = applied.trusted;
    if (opts.requireSig && applied.ok !== true) {
      return fail(2, applied.reason ?? 'report signature is not trusted', { ...base, trusted });
    }
    if (opts.requireSig && applied.ok === true && !trustStoreActive(store)) {
      console.error(NO_TRUST_REQUIRE_SIG_NOTE);
    }
  }
  const explicitReceipts = Boolean(opts.receiptsDir);
  const dirs = explicitReceipts ? [resolve(cwd, opts.receiptsDir as string)] : [receiptsDir(cwd)];
  const local = checkLocalReceipts(cwd, payload, dirs, explicitReceipts);
  const chainRoot = auditRootForVerify(cwd, opts.receiptsDir, explicitReceipts);
  const chainError = chainRoot ? auditChainError(chainRoot) : null;
  const counts = {
    checked: local.checked,
    skipped: local.skipped,
    failed: local.failed + (chainError ? 1 : 0),
    notChecked: local.notChecked,
    trusted,
    warning: local.warning,
  };
  if (chainError || local.reason) {
    const reason = [chainError, local.reason].filter((item): item is string => Boolean(item)).join('; ');
    return fail(2, reason, { ...base, ...counts });
  }
  if (payload.verdict === 'FAILED') {
    return fail(2, failedVerdictReason(payload), { ...base, ...counts });
  }
  if (payload.verdict === 'UNTRUSTED') {
    return fail(2, 'report verdict is UNTRUSTED', { ...base, ...counts });
  }
  if (!signed || payload.verdict === 'UNSIGNED') {
    if (opts.requireSig || signed || payload.verdict !== 'UNSIGNED') {
      const reason = opts.requireSig && !signed
        ? 'signature required: report signature absent'
        : 'report verdict is not VERIFIED';
      return fail(2, reason, { ...base, ...counts, verdict: signed ? payload.verdict : 'UNSIGNED' });
    }
    return emitVerify(
      {
        ok: true,
        command: 'report-verify',
        version: VERSION,
        exitCode: 0,
        verdict: 'UNSIGNED',
        signed: false,
        fingerprint: null,
        trusted: null,
        receiptCount: payload.receipts.length,
        checked: local.checked,
        skipped: local.skipped,
        failed: counts.failed,
        notChecked: local.notChecked,
        reason: local.note,
        warning: local.warning,
      },
      json,
    );
  }
  if (payload.verdict !== 'VERIFIED') {
    return fail(2, 'report verdict is not VERIFIED', { ...base, ...counts });
  }
  const payloadOnly = local.notChecked > 0;
  return emitVerify(
    {
      ok: true,
      command: 'report-verify',
      version: VERSION,
      exitCode: 0,
      verdict: payloadOnly ? 'VERIFIED_PAYLOAD_ONLY' : 'VERIFIED',
      signed: true,
      fingerprint: signature?.fingerprint ?? null,
      trusted,
      receiptCount: payload.receipts.length,
      checked: local.checked,
      skipped: local.skipped,
      failed: counts.failed,
      notChecked: local.notChecked,
      reason: local.note,
      warning: local.warning,
    },
    json,
  );
}

/**
 * Chain root for this verify. The current repo is used when `--receipts`
 * is absent or names this repo's receipts directory. Another checkout's
 * `.agent-receipt/receipts` uses that checkout. A package directory or any
 * other directory does not consult an unrelated audit.jsonl in cwd.
 */
function auditRootForVerify(cwd: string, receiptsArg: string | undefined, explicit: boolean): string | null {
  if (!explicit || !receiptsArg) return cwd;
  const abs = resolve(cwd, receiptsArg);
  const local = resolve(receiptsDir(cwd));
  if (abs === local) return cwd;
  const parent = dirname(abs);
  if (
    basename(parent) === '.agent-receipt' &&
    basename(abs) === basename(local) &&
    existsSync(join(parent, 'audit.jsonl'))
  ) {
    return dirname(parent);
  }
  if (existsSync(join(abs, '.agent-receipt', 'audit.jsonl'))) return abs;
  return null;
}

/**
 * Same rule as `doctor --strict`. A missing audit file is not a failure.
 * An empty file is intact. A break exits 2 after receipt counts are known,
 * so deleting lines cannot fall through to payload-only. A chain-only
 * failure still increments `failed`.
 */
function auditChainError(cwd: string): string | null {
  if (!existsSync(auditLogPath(cwd))) return null;
  const chain = verifyAuditChain(cwd);
  if (chain.ok) return null;
  const where = chain.brokenAt ? ` at line ${chain.brokenAt}` : '';
  const why = chain.reason ? `: ${chain.reason}` : '';
  return `audit log hash chain is broken${where}${why} (agent-receipt audit --verify)`;
}

/**
 * Check one or more report files. The process exit code is the worst
 * of 0, 1, and 2. `--receipts` is checked once up front.
 */
export function cmdReportVerify(
  cwd: string,
  pathArg: string | string[] | undefined,
  opts: ReportVerifyOptions = {},
): number {
  const paths = (Array.isArray(pathArg) ? pathArg : pathArg ? [pathArg] : []).filter((item) => item.trim());
  const json = Boolean(opts.json);
  const usage = (reason: string): 0 | 1 | 2 =>
    emitVerify(
      {
        ok: false,
        command: 'report-verify',
        version: VERSION,
        exitCode: 1,
        verdict: null,
        signed: false,
        fingerprint: null,
        trusted: null,
        receiptCount: 0,
        checked: 0,
        skipped: 0,
        failed: 0,
        notChecked: 0,
        reason,
        warning: null,
      },
      json,
    );
  if (!paths.length) return usage('report verify requires an HTML file');
  const dirError = receiptsDirError(cwd, opts.receiptsDir);
  if (dirError) return usage(dirError);
  let worst: 0 | 1 | 2 = 0;
  for (const filePath of paths) {
    const code = verifyOneReport(cwd, filePath, opts);
    if (code > worst) worst = code;
  }
  return worst;
}

export { SESSION_MANIFEST_NAME };
