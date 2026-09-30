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
import { color } from '../lib/color.js';
import { canonicalBody, sha256Hex } from '../lib/hash.js';
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
import { receiptsDir } from '../lib/receipt-index.js';
import { loadResignProvenance, type ResignClaim } from '../lib/resign-provenance.js';
import {
  assertRenderedPage,
  decideVerdict,
  parseReportHtml,
  plainReportText,
  renderReportHtml,
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
  loadSessionManifest,
  locateSessionPackage,
  type SessionManifestReceipt,
} from '../lib/session-package.js';
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
import { applyTrust, loadTrustedFingerprints, type TrustStore } from '../lib/trust.js';
import { VERSION } from '../lib/version.js';
import { findLatestReceipt } from './show.js';
import { collectSession } from './session.js';

const SAFE_STEM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$/;
const SAFE_DIR_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,200}$/;

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

export interface ReportVerifyResult {
  ok: boolean;
  command: 'report-verify';
  version: string;
  exitCode: 0 | 1 | 2;
  verdict: ReportVerdict | null;
  signed: boolean;
  fingerprint: string | null;
  trusted: boolean | null;
  receiptCount: number;
  checked: number;
  skipped: number;
  reason: string | null;
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

function redactedCanonical(markdown: string, actual: string): string | null {
  const published = publishRedactedReceipt(markdown, { maskHost: true });
  const hash = sha256Hex(canonicalBody(published));
  return hash === actual ? null : hash;
}

function buildOne(
  filePath: string,
  exposure: ReportExposure,
  store: TrustStore,
  provenance: Map<string, ResignClaim>,
  manifestEntry?: SessionManifestReceipt,
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
  const payload: ReportReceiptPayload = {
    id,
    sha256: integrity.actual,
    redactedSha256: redactedCanonical(original, integrity.actual),
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
  if (!out) return join(dirname(receiptsDir(cwd)), fileName);
  const abs = resolve(cwd, out);
  const asDir =
    out.endsWith('/') ||
    out.endsWith('\\') ||
    (existsSync(abs) && statSync(abs).isDirectory());
  if (asDir) return join(abs, fileName);
  return abs;
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

/** Why this tree cannot be VERIFIED. Null when every receipt's hash and signature hold. */
function verificationFailure(built: BuiltReceipt[]): string | null {
  const aliases = aliasesOf(built);
  const failed = built.filter((item) => !item.payload.verified || item.payload.signature === 'invalid');
  if (!failed.length) return null;
  const roots = failed.filter((item) => !item.payload.parent || !aliases.has(item.payload.parent));
  const focus = roots[0] ?? failed[0];
  const role = roots.length ? 'session root' : 'receipt';
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
  const htmlPath = resolveReportOut(cwd, fileName, opts.out);
  for (const source of sourcePaths) {
    if (resolve(source) === resolve(htmlPath)) {
      return emptyResult(1, `refusing to overwrite the source receipt: ${htmlPath}`);
    }
  }
  const exposure = exposureOf(opts);
  const store = loadTrustedFingerprints(cwd, { extra: opts.trustedKeys });
  const keys = tryLoadKeys(cwd);
  const reportTrusted = reportTrustedFor(keys, store);
  const receipts = built.map((item) => item.payload);
  const broken = verificationFailure(built);
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
    built.push(buildOne(filePath, exposure, store, new Map(), entry));
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
  if (pathArg && pathArg !== 'last' && /\.report\.html$/i.test(basename(pathArg))) {
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
    if (child.isSymbolicLink()) continue;
    if (child.isDirectory()) collectMarkdown(filePath, out, depth + 1);
    else if (child.isFile() && name.endsWith('.md') && !name.endsWith('.prove.md')) out.push(filePath);
  }
}

interface HashedReceipt {
  path: string;
  id: string;
  sha256: string;
  verified: boolean;
  signature: ReportSignatureState;
}

function hashedReceipt(filePath: string): HashedReceipt | null {
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
  return {
    path: filePath,
    id: ref?.id || integrity.actual,
    sha256: integrity.actual,
    verified: integrity.ok,
    signature,
  };
}

function checkLocalReceipts(
  payload: ReportPayload,
  dirs: string[],
): { checked: number; skipped: number; reason: string | null } {
  const files: string[] = [];
  const seen = new Set<string>();
  for (const dir of dirs) {
    if (!dir || seen.has(dir)) continue;
    seen.add(dir);
    collectMarkdown(dir, files, 0);
  }
  const hashed = files
    .map((file) => hashedReceipt(file))
    .filter((item): item is HashedReceipt => item !== null);
  let checked = 0;
  let skipped = 0;
  for (const receipt of payload.receipts) {
    const accepted = new Set<string>([receipt.sha256]);
    if (receipt.redactedSha256) accepted.add(receipt.redactedSha256);
    const found = hashed.find((item) => accepted.has(item.sha256));
    if (!found) {
      skipped += 1;
      continue;
    }
    checked += 1;
    if (found.sha256 === receipt.sha256) {
      if (found.verified !== receipt.verified || found.signature !== receipt.signature) {
        return { checked, skipped, reason: `receipt ${receipt.id} no longer matches the signed payload` };
      }
      if (!found.verified || found.signature === 'invalid') {
        return { checked, skipped, reason: `receipt ${receipt.id} failed verify` };
      }
    } else if (!found.verified || found.signature === 'invalid') {
      return { checked, skipped, reason: `receipt ${receipt.id} redacted copy failed verify` };
    }
  }
  return { checked, skipped, reason: null };
}

/** A non-zero exit never reports VERIFIED. The page's claim is not a pass. */
function shownVerdict(result: ReportVerifyResult): ReportVerdict | null {
  if (result.exitCode !== 0 && result.verdict === 'VERIFIED') return 'FAILED';
  return result.verdict;
}

function emitVerify(result: ReportVerifyResult, json: boolean): 0 | 1 | 2 {
  const verdict = shownVerdict(result);
  const printed = { ...result, verdict };
  if (json) {
    console.log(JSON.stringify(printed));
    return result.exitCode;
  }
  if (result.exitCode === 1) {
    console.error(color.red('Error:') + ` ${result.reason ?? 'report verify failed'}`);
    return 1;
  }
  const label = verdict ?? 'FAILED';
  const paint = result.exitCode === 0 && label === 'VERIFIED' ? color.green : result.exitCode === 0 ? color.yellow : color.red;
  console.log(`${paint(label)}  report verify`);
  if (result.fingerprint) console.log(`  fingerprint: ${result.fingerprint}`);
  if (result.reason) console.error(result.reason);
  console.log(`  checked: ${result.checked}  skipped: ${result.skipped}`);
  return result.exitCode;
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
 * Receipts are re-hashed when a file under outDir or `--receipts` has the
 * recorded sha256 or redactedSha256. An id with different bytes is not a match.
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
        reason,
      },
      json,
    );
  const htmlPath = resolve(cwd, pathArg);
  if (!existsSync(htmlPath) || !statSync(htmlPath).isFile()) {
    return fail(1, `report not found: ${pathArg}`);
  }
  let html: string;
  try {
    html = readFileSync(htmlPath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return fail(1, `unreadable report (${detail})`);
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
  }
  const dirs = [receiptsDir(cwd)];
  if (opts.receiptsDir) dirs.unshift(resolve(cwd, opts.receiptsDir));
  const local = checkLocalReceipts(payload, dirs);
  const counts = { checked: local.checked, skipped: local.skipped, trusted };
  if (local.reason) return fail(2, local.reason, { ...base, ...counts });
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
        reason: null,
      },
      json,
    );
  }
  if (payload.verdict !== 'VERIFIED') {
    return fail(2, 'report verdict is not VERIFIED', { ...base, ...counts });
  }
  return emitVerify(
    {
      ok: true,
      command: 'report-verify',
      version: VERSION,
      exitCode: 0,
      verdict: 'VERIFIED',
      signed: true,
      fingerprint: signature?.fingerprint ?? null,
      trusted,
      receiptCount: payload.receipts.length,
      checked: local.checked,
      skipped: local.skipped,
      reason: null,
    },
    json,
  );
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
        reason,
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
