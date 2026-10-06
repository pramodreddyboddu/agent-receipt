/**
 * Pull-request summary for a receipt gate.
 *
 * Renders one Markdown comment, redacts it, and posts it with global fetch.
 * The GitHub token is never written into the summary, a log line, or an error.
 * 403/404 and network failures are reported to the caller so the gate exit
 * code can stay unchanged.
 */
import {
  appendFileSync,
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  statSync,
} from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { parseReceiptGlance } from '../commands/compare.js';
import { cmdAttestVerify, AttestUsageError } from '../commands/attest.js';
import { cmdVerify } from '../commands/verify.js';
import { loadConfig, parseSimpleYaml } from './config.js';
import { pathMatchesGlob } from './ignore.js';
import { redactSecretsInText } from './redact.js';
import {
  isProveOnePagerName,
  isSessionPackageDirName,
  isSharePackageDirName,
} from './receipt.js';
import { meetsFailOn, parseFailOn, type FailOnThreshold } from './risk.js';
import { inspectReceiptSignature } from './sign.js';
import { VERSION } from './version.js';

export const SUMMARY_MARKER = '<!-- agent-receipt:summary -->';

export type PrCommandMode = 'gate' | 'verify' | 'attest-verify';
export type CommentWhen = 'on' | 'off' | 'on-failure';
export type CommentMode = 'update' | 'create';

export interface PrSummaryOptions {
  command: PrCommandMode;
  receipts?: string;
  failOn?: FailOnThreshold;
  policyPath?: string;
  requireSignature: boolean;
  certificateIdentity?: string;
  certificateIdentityRegexp?: string;
  certificateOidcIssuer?: string;
  trustedRoot?: string;
}

export interface PolicyHit {
  severity: string;
  code: string;
  detail: string;
  receipt: string;
}

export interface ShareLink {
  path: string;
}

export interface SignatureLine {
  required: boolean;
  present: boolean | null;
  ok: boolean | null;
  alg: string | null;
  fingerprint: string | null;
  keyless: boolean;
  identity: string | null;
  issuer: string | null;
  reason: string | null;
}

export interface GateSummary {
  ok: boolean;
  exitCode: 0 | 2;
  verdict: 'pass' | 'fail';
  mode: PrCommandMode;
  failOn: string | null;
  policyPath: string | null;
  risk: {
    high: number;
    medium: number;
    low: number;
    total: number;
    maxSeverity: string | null;
  };
  receiptsCount: number;
  policyHits: PolicyHit[];
  signature: SignatureLine;
  hashChainHead: string | null;
  hashChainOk: boolean | null;
  sharePackages: string[];
  reason: string | null;
  receipts: Array<{ path: string; verdict: 'pass' | 'fail'; sha256: string | null; message: string | null }>;
}

const SKIP_DIRS = new Set(['node_modules', '.git']);
const MARKER = SUMMARY_MARKER;

export function scrubSecrets(text: string, token?: string): string {
  let out = text;
  if (token) out = out.split(token).join('[REDACTED]');
  return redactSecretsInText(out);
}

export function parseCommentWhen(value: string | boolean | undefined): CommentWhen {
  if (value === undefined || value === true) return 'on';
  const v = String(value).trim().toLowerCase();
  if (v === 'on' || v === 'off' || v === 'on-failure') return v;
  throw new Error('--comment must be on, off, or on-failure');
}

export function parseCommentMode(value: string | boolean | undefined): CommentMode {
  if (value === undefined) return 'update';
  if (value === true || String(value).trim() === '') {
    throw new Error('--comment-mode must be update or create');
  }
  const v = String(value).trim().toLowerCase();
  if (v === 'update' || v === 'create') return v;
  throw new Error('--comment-mode must be update or create');
}

export function parseMode(value: string | undefined): PrCommandMode {
  if (value === undefined || value === '') return 'gate';
  const v = value.trim().toLowerCase();
  if (v === 'gate' || v === 'verify' || v === 'attest-verify') return v;
  throw new Error('--command must be gate, verify, or attest-verify');
}

interface LoadedPolicy {
  failOn?: FailOnThreshold;
  requireSignature: boolean;
  path: string;
}

export function loadPolicyFile(cwd: string, policyPath: string): LoadedPolicy {
  const abs = resolve(cwd, policyPath);
  if (!existsSync(abs)) throw new Error(`policy file not found: ${displayPath(cwd, abs)}`);
  let text: string;
  try {
    const st = lstatSync(abs);
    if (st.isSymbolicLink() || !st.isFile()) {
      throw new Error(`policy file is not a regular file: ${displayPath(cwd, abs)}`);
    }
    text = readFileSync(abs, 'utf8');
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('policy file')) throw err;
    throw new Error(`policy file is unreadable: ${displayPath(cwd, abs)}`);
  }
  let parsed: ReturnType<typeof parseSimpleYaml>;
  try {
    parsed = parseSimpleYaml(text);
  } catch {
    throw new Error(`policy file is invalid: ${displayPath(cwd, abs)}`);
  }
  let failOn: FailOnThreshold | undefined;
  const rawFail = parsed.failOn;
  if (rawFail !== undefined && rawFail !== false && rawFail !== '') {
    if (typeof rawFail !== 'string' && typeof rawFail !== 'boolean') {
      throw new Error('policy failOn must be high, medium, or low');
    }
    try {
      failOn = parseFailOn(rawFail);
    } catch {
      throw new Error('policy failOn must be high, medium, or low');
    }
    if (!failOn) throw new Error('policy failOn must be high, medium, or low');
  }
  const rawReq = parsed.requireSignature ?? parsed['require-signature'] ?? parsed.requireSig;
  let requireSignature = false;
  if (rawReq !== undefined && rawReq !== false && rawReq !== 'false') {
    if (rawReq === true || rawReq === 'true') requireSignature = true;
    else throw new Error('policy requireSignature must be true or false');
  }
  return { failOn, requireSignature, path: displayPath(cwd, abs) };
}

function displayPath(cwd: string, filePath: string): string {
  const rel = relative(cwd, filePath).replace(/\\/g, '/');
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) return filePath;
  return rel;
}

function clip(value: string | null, max = 180): string | null {
  if (!value) return null;
  const flat = value.replace(/[\r\n\u2028\u2029\t|]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (!flat) return null;
  if (flat.length <= max) return flat;
  return `${flat.slice(0, max - 1)}…`;
}

function walkFiles(dir: string, out: string[]): void {
  if (out.length > 5000) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (out.length > 5000) return;
    if (ent.isSymbolicLink()) continue;
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      walkFiles(p, out);
    } else if (ent.isFile()) {
      out.push(p);
    }
  }
}

function isAttestationName(name: string): boolean {
  const base = name.split(/[/\\]/).pop() ?? name;
  return base.endsWith('.intoto.jsonl') || base.endsWith('.sigstore.json');
}

function isReceiptFile(filePath: string): boolean {
  const base = filePath.split(/[/\\]/).pop() ?? filePath;
  if (!base.endsWith('.md')) return false;
  if (isProveOnePagerName(base)) return false;
  if (isSharePackageDirName(base) || isSessionPackageDirName(base)) return false;
  const parts = filePath.replace(/\\/g, '/').split('/');
  if (parts.slice(0, -1).some((part) => isSharePackageDirName(part) || isSessionPackageDirName(part))) {
    return false;
  }
  return true;
}

/**
 * Receipts or attestation files for this run.
 * An explicit missing path is a usage error. A glob that matches nothing
 * returns an empty list so the gate can fail closed.
 */
export function collectInputs(cwd: string, mode: PrCommandMode, pattern?: string): string[] {
  if (pattern === undefined || pattern.trim() === '') {
    if (mode === 'attest-verify') {
      const dir = join(cwd, loadConfig(cwd).outDir);
      const found: string[] = [];
      if (existsSync(dir)) walkFiles(dir, found);
      return found.filter((file) => isAttestationName(file)).sort();
    }
    return listReceiptMd(cwd);
  }
  const spec = pattern.trim();
  const hasGlob = /[*?\[]/.test(spec);
  const abs = isAbsolute(spec) ? spec : resolve(cwd, spec);
  if (!hasGlob && existsSync(abs)) {
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) throw new Error(`receipts path is a symlink: ${displayPath(cwd, abs)}`);
    if (st.isFile()) return [abs];
    if (st.isDirectory()) {
      const found: string[] = [];
      walkFiles(abs, found);
      return filterForMode(found, mode);
    }
    throw new Error(`receipts path is not a file or directory: ${displayPath(cwd, abs)}`);
  }
  if (!hasGlob) throw new Error(`receipts path not found: ${spec}`);
  const found: string[] = [];
  walkFiles(cwd, found);
  const relPat = spec.replace(/\\/g, '/').replace(/^\.\//, '');
  return found.filter((file) => {
    const rel = relative(cwd, file).replace(/\\/g, '/');
    return pathMatchesGlob(rel, relPat) || pathMatchesGlob(file, relPat);
  }).filter((file) => (mode === 'attest-verify' ? isAttestationName(file) : isReceiptFile(file))).sort();
}

function listReceiptMd(cwd: string): string[] {
  const dir = join(cwd, loadConfig(cwd).outDir);
  if (!existsSync(dir)) return [];
  const found: string[] = [];
  walkFiles(dir, found);
  return filterForMode(found, 'gate');
}

function filterForMode(files: string[], mode: PrCommandMode): string[] {
  if (mode === 'attest-verify') return files.filter((file) => isAttestationName(file)).sort();
  return files.filter((file) => isReceiptFile(file)).sort();
}

function emptyRisk(): GateSummary['risk'] {
  return { high: 0, medium: 0, low: 0, total: 0, maxSeverity: null };
}

function addRisk(into: GateSummary['risk'], part: { high: number; medium: number; low: number }): void {
  into.high += part.high;
  into.medium += part.medium;
  into.low += part.low;
  into.total = into.high + into.medium + into.low;
  into.maxSeverity = into.high > 0 ? 'high' : into.medium > 0 ? 'medium' : into.low > 0 ? 'low' : null;
}

function findSharePackages(cwd: string, receipts: string[]): string[] {
  const found = new Set<string>();
  const consider = (dir: string): void => {
    if (!dir || !isSharePackageDirName(dir)) return;
    try {
      if (!existsSync(dir) || !statSync(dir).isDirectory()) return;
    } catch {
      return;
    }
    found.add(displayPath(cwd, dir));
  };
  for (const receipt of receipts) {
    consider(receipt.replace(/\.md$/i, '') + '.share');
  }
  const outDir = join(cwd, loadConfig(cwd).outDir);
  const roots = [outDir, cwd];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    let entries;
    try {
      entries = readdirSync(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (!ent.isDirectory() || ent.isSymbolicLink()) continue;
      if (isSharePackageDirName(ent.name)) consider(join(root, ent.name));
    }
  }
  // Sibling of each receipt's directory, one level.
  for (const receipt of receipts) {
    const parent = join(receipt, '..');
    let entries;
    try {
      entries = readdirSync(parent, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (ent.isDirectory() && !ent.isSymbolicLink() && isSharePackageDirName(ent.name)) {
        consider(join(parent, ent.name));
      }
    }
  }
  return [...found].sort();
}

interface AttestReport {
  ok?: boolean;
  exitCode?: number;
  signed?: boolean;
  keyless?: boolean;
  fingerprint?: string | null;
  certificateIdentity?: string | null;
  certificateIssuer?: string | null;
  hashChainOk?: boolean;
  reason?: string | null;
  subjects?: number;
}

function captureConsole(fn: () => number): { code: number; stdout: string; stderr: string } {
  const out: string[] = [];
  const err: string[] = [];
  const log = console.log;
  const error = console.error;
  console.log = (...args: unknown[]) => {
    out.push(args.map((part) => String(part)).join(' '));
  };
  console.error = (...args: unknown[]) => {
    err.push(args.map((part) => String(part)).join(' '));
  };
  try {
    const code = fn();
    return { code, stdout: out.join('\n'), stderr: err.join('\n') };
  } finally {
    console.log = log;
    console.error = error;
  }
}

function parseAttestStdout(stdout: string): AttestReport | null {
  const lines = stdout.split('\n').map((line) => line.trim()).filter((line) => line.startsWith('{'));
  if (!lines.length) return null;
  try {
    return JSON.parse(lines[lines.length - 1]) as AttestReport;
  } catch {
    return null;
  }
}

/**
 * Run gate, verify, or attest-verify over the selected files.
 * Exit 2 when the check fails, including when nothing matched.
 */
export function evaluateGate(cwd: string, opts: PrSummaryOptions): GateSummary {
  const files = collectInputs(cwd, opts.command, opts.receipts);
  const risk = emptyRisk();
  const hits: PolicyHit[] = [];
  const rows: GateSummary['receipts'] = [];
  let reason: string | null = null;
  let failed = files.length === 0;
  if (files.length === 0) {
    reason = opts.command === 'attest-verify' ? 'no attestation files matched' : 'no receipts matched';
  }
  let hashChainHead: string | null = null;
  let hashChainOk: boolean | null = null;
  const signature: SignatureLine = {
    required: opts.requireSignature,
    present: null,
    ok: null,
    alg: null,
    fingerprint: null,
    keyless: opts.command === 'attest-verify',
    identity: opts.certificateIdentity ?? null,
    issuer: opts.certificateOidcIssuer ?? null,
    reason: null,
  };

  if (opts.command === 'attest-verify') {
    for (const file of files) {
      let captured: { code: number; stdout: string; stderr: string };
      try {
        captured = captureConsole(() =>
          cmdAttestVerify(cwd, file, {
            json: true,
            certificateIdentity: opts.certificateIdentity,
            certificateIdentityRegexp: opts.certificateIdentityRegexp,
            certificateOidcIssuer: opts.certificateOidcIssuer,
            trustedRoot: opts.trustedRoot,
          }),
        );
      } catch (err) {
        if (err instanceof AttestUsageError) throw err;
        const message = err instanceof Error ? err.message : String(err);
        throw new Error(message);
      }
      if (captured.stderr.trim()) console.error(scrubSecrets(captured.stderr));
      const report = parseAttestStdout(captured.stdout);
      const ok = captured.code === 0 && report?.ok !== false;
      if (report?.hashChainOk === false) hashChainOk = false;
      else if (report?.hashChainOk === true && hashChainOk !== false) hashChainOk = true;
      if (!ok) {
        failed = true;
        const why = report?.reason || captured.stderr || `attest --verify failed (${captured.code})`;
        reason = reason ? `${reason}; ${why}` : why;
      }
      if (report?.keyless) signature.keyless = true;
      if (report?.certificateIdentity) signature.identity = report.certificateIdentity;
      if (report?.certificateIssuer) signature.issuer = report.certificateIssuer;
      if (report?.fingerprint) signature.fingerprint = report.fingerprint;
      signature.present = report?.signed === true || signature.present === true;
      if (report?.signed === false) signature.ok = false;
      else if (ok && signature.ok !== false) signature.ok = true;
      if (!ok && report?.reason) signature.reason = report.reason;
      rows.push({
        path: displayPath(cwd, file),
        verdict: ok ? 'pass' : 'fail',
        sha256: null,
        message: null,
      });
    }
  } else {
    let newestMtime = -1;
    for (const file of files) {
      let result;
      try {
        result = cmdVerify(cwd, file, {
          quiet: true,
          failOn: opts.failOn,
          requireSig: opts.requireSignature,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        failed = true;
        reason = reason ? `${reason}; ${message}` : message;
        rows.push({ path: displayPath(cwd, file), verdict: 'fail', sha256: null, message: null });
        continue;
      }
      if (result.exitCode !== 0) {
        failed = true;
        if (result.reason) reason = reason ? `${reason}; ${result.reason}` : result.reason;
      }
      if (result.risk) addRisk(risk, result.risk);
      const glance = parseReceiptGlance(file);
      const threshold = opts.failOn;
      for (const hit of glance.risks) {
        const sev = hit.severity === 'high' || hit.severity === 'medium' || hit.severity === 'low'
          ? hit.severity
          : null;
        if (threshold && sev && !meetsFailOn(sev, threshold)) continue;
        if (!threshold && !sev) continue;
        hits.push({
          severity: hit.severity,
          code: hit.code,
          detail: clip(hit.detail) || '',
          receipt: displayPath(cwd, file),
        });
      }
      let mtime = 0;
      try {
        mtime = statSync(file).mtimeMs;
      } catch {
        mtime = 0;
      }
      if (result.sha256 && mtime >= newestMtime) {
        newestMtime = mtime;
        hashChainHead = result.sha256;
      }
      const inspected = result.signature
        ? result.signature
        : result.sha256
          ? inspectReceiptSignature(file, result.sha256)
          : null;
      if (inspected) {
        if (signature.present !== true) signature.present = inspected.present;
        if (inspected.present) signature.present = true;
        if (inspected.ok === false) signature.ok = false;
        else if (inspected.ok === true && signature.ok !== false) signature.ok = true;
        if (inspected.fingerprint) signature.fingerprint = inspected.fingerprint;
        if (inspected.alg) signature.alg = inspected.alg;
        if (inspected.reason && opts.requireSignature && inspected.ok !== true) {
          signature.reason = inspected.reason;
        }
      }
      rows.push({
        path: displayPath(cwd, file),
        verdict: result.exitCode === 0 ? 'pass' : 'fail',
        sha256: result.sha256 || null,
        message: clip(glance.message ?? null),
      });
    }
  }

  const exitCode: 0 | 2 = failed ? 2 : 0;
  return {
    ok: exitCode === 0,
    exitCode,
    verdict: exitCode === 0 ? 'pass' : 'fail',
    mode: opts.command,
    failOn: opts.failOn ?? null,
    policyPath: opts.policyPath ?? null,
    risk,
    receiptsCount: files.length,
    policyHits: hits.slice(0, 20),
    signature,
    hashChainHead,
    hashChainOk,
    sharePackages: findSharePackages(cwd, files.filter((file) => file.endsWith('.md'))),
    reason: reason ? clip(reason, 500) : null,
    receipts: rows,
  };
}

function signatureMarkdown(sig: SignatureLine): string {
  if (sig.keyless) {
    const id = sig.identity || '(identity unset)';
    const issuer = sig.issuer || '(issuer unset)';
    if (sig.ok === true) return `keyless ok · \`${id}\` · issuer \`${issuer}\``;
    if (sig.ok === false) return `keyless failed · \`${id}\` · issuer \`${issuer}\``;
    return `keyless · \`${id}\` · issuer \`${issuer}\``;
  }
  if (!sig.required && sig.present !== true) return 'not required';
  if (sig.required && sig.present === false) return 'required, absent';
  const bits = [
    sig.required ? 'required' : 'present',
    sig.alg || 'ed25519',
    sig.fingerprint ? `\`${sig.fingerprint}\`` : null,
    sig.ok === true ? 'ok' : sig.ok === false ? 'failed' : null,
  ].filter(Boolean);
  return bits.join(' ');
}

function riskMarkdown(risk: GateSummary['risk']): string {
  if (!risk.maxSeverity || risk.total === 0) return 'none';
  return `${risk.maxSeverity} (high ${risk.high}, medium ${risk.medium}, low ${risk.low})`;
}

/** Concise Markdown comment. The caller redacts the returned text. */
export function renderSummaryMarkdown(summary: GateSummary): string {
  const lines: string[] = [];
  lines.push(MARKER);
  lines.push('## Agent receipt');
  lines.push('');
  lines.push(`**Verdict:** ${summary.verdict}`);
  lines.push(`**Mode:** ${summary.mode}`);
  lines.push(`**Risk:** ${riskMarkdown(summary.risk)}`);
  lines.push(`**Receipts checked:** ${summary.receiptsCount}`);
  if (summary.failOn) lines.push(`**Fail-on:** \`${summary.failOn}\``);
  if (summary.policyPath) lines.push(`**Policy:** \`${summary.policyPath}\``);
  lines.push(`**Signature:** ${signatureMarkdown(summary.signature)}`);
  if (summary.mode === 'attest-verify') {
    const head = summary.hashChainOk === false ? 'mismatch' : summary.hashChainOk === true ? 'matches' : 'not checked';
    lines.push(`**Hash-chain head:** ${head}`);
  } else if (summary.hashChainHead) {
    lines.push(`**Hash-chain head:** \`${summary.hashChainHead}\``);
  } else {
    lines.push('**Hash-chain head:** none');
  }
  if (summary.reason) lines.push(`**Reason:** ${summary.reason}`);
  lines.push('');
  lines.push('### Receipts');
  lines.push('');
  if (!summary.receipts.length) {
    lines.push('_None._');
  } else {
    lines.push('| Receipt | Verdict | Message |');
    lines.push('|---------|---------|---------|');
    for (const row of summary.receipts.slice(0, 20)) {
      lines.push(`| \`${row.path}\` | ${row.verdict} | ${row.message || ''} |`);
    }
  }
  lines.push('');
  lines.push('### Policy hits');
  lines.push('');
  if (!summary.policyHits.length) {
    lines.push('_None._');
  } else {
    lines.push('| Sev | Code | Receipt | Detail |');
    lines.push('|-----|------|---------|--------|');
    for (const hit of summary.policyHits) {
      lines.push(`| ${hit.severity} | \`${hit.code}\` | \`${hit.receipt}\` | ${hit.detail} |`);
    }
  }
  lines.push('');
  lines.push('### Share packages');
  lines.push('');
  if (!summary.sharePackages.length) {
    lines.push('_None._');
  } else {
    for (const pkg of summary.sharePackages) {
      lines.push(`- [\`${pkg}\`](${pkg})`);
    }
  }
  lines.push('');
  lines.push(`_agent-receipt ${VERSION}_`);
  lines.push('');
  return lines.join('\n');
}

export function renderRedactedSummary(summary: GateSummary, token?: string): string {
  return scrubSecrets(renderSummaryMarkdown(summary), token);
}

export interface CommentContext {
  repo: string;
  owner: string;
  name: string;
  pr: number;
  api: string;
  token: string;
}

export function readPullRequestNumber(eventPath: string): number | null {
  let text: string;
  try {
    text = readFileSync(eventPath, 'utf8');
  } catch {
    throw new Error(`GITHUB_EVENT_PATH is not readable: ${eventPath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('GITHUB_EVENT_PATH is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const event = parsed as Record<string, unknown>;
  const pr = event.pull_request;
  if (pr && typeof pr === 'object') {
    const num = (pr as Record<string, unknown>).number;
    if (typeof num === 'number' && Number.isInteger(num) && num > 0) return num;
  }
  const issue = event.issue;
  if (issue && typeof issue === 'object' && (issue as Record<string, unknown>).pull_request) {
    const num = (issue as Record<string, unknown>).number;
    if (typeof num === 'number' && Number.isInteger(num) && num > 0) return num;
  }
  if (typeof event.number === 'number' && Number.isInteger(event.number) && event.number > 0) {
    return event.number;
  }
  return null;
}

export function resolveCommentContext(
  env: NodeJS.ProcessEnv,
  flags: { repo?: string; pr?: number; apiUrl?: string; eventPath?: string; token?: string },
): CommentContext {
  const repo = (flags.repo || env.GITHUB_REPOSITORY || '').trim();
  if (!repo) {
    throw new Error('no pull request repository. Set GITHUB_REPOSITORY or pass --repo owner/name.');
  }
  const parts = repo.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1] || /\s/.test(repo)) {
    throw new Error('--repo must be owner/name');
  }
  let pr = flags.pr;
  if (pr === undefined) {
    const eventPath = flags.eventPath || env.GITHUB_EVENT_PATH;
    if (!eventPath) {
      throw new Error(
        'no pull request number. Set GITHUB_EVENT_PATH or pass --pr <number>.',
      );
    }
    if (!existsSync(eventPath)) {
      throw new Error(`GITHUB_EVENT_PATH does not exist: ${eventPath}`);
    }
    const fromEvent = readPullRequestNumber(eventPath);
    if (fromEvent === null) {
      throw new Error('GITHUB_EVENT_PATH has no pull request number. Pass --pr <number>.');
    }
    pr = fromEvent;
  }
  if (!Number.isInteger(pr) || pr < 1) throw new Error('--pr must be an integer >= 1');
  const api = (flags.apiUrl || env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  let apiUrl: URL;
  try {
    apiUrl = new URL(api);
  } catch {
    throw new Error('--api-url must be an http or https URL');
  }
  if (apiUrl.protocol !== 'http:' && apiUrl.protocol !== 'https:') {
    throw new Error('--api-url must be an http or https URL');
  }
  const token = flags.token || env.GITHUB_TOKEN || '';
  if (!token) throw new Error('no GitHub token. Set GITHUB_TOKEN. The token is never printed.');
  return { repo, owner: parts[0], name: parts[1], pr, api, token };
}

export class CommentPostError extends Error {
  readonly kind: 'http' | 'network' | 'protocol';
  readonly status: number | null;
  constructor(kind: 'http' | 'network' | 'protocol', message: string, status: number | null = null) {
    super(message);
    this.name = 'CommentPostError';
    this.kind = kind;
    this.status = status;
  }
}

interface GhComment {
  id: number;
  body: string;
  url: string;
}

function nextLink(header: string | null, api: string): string | null {
  if (!header) return null;
  for (const part of header.split(',')) {
    const match = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (!match) continue;
    const url = match[1];
    if (url.startsWith(api)) return url.slice(api.length);
    try {
      const parsed = new URL(url);
      return `${parsed.pathname}${parsed.search}`;
    } catch {
      return null;
    }
  }
  return null;
}

async function gh(
  api: string,
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: unknown; link: string | null }> {
  const url = path.startsWith('http') ? path : `${api}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'agent-receipt',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new CommentPostError('network', scrubSecrets(message, token));
  }
  const text = await res.text();
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  if (res.status === 403 || res.status === 404) {
    throw new CommentPostError(
      'http',
      `GitHub API returned ${res.status}`,
      res.status,
    );
  }
  if (res.status < 200 || res.status >= 300) {
    throw new CommentPostError('http', `GitHub API returned ${res.status}`, res.status);
  }
  return { status: res.status, json, link: res.headers.get('link') };
}

async function listComments(ctx: CommentContext): Promise<GhComment[]> {
  const all: GhComment[] = [];
  let path = `/repos/${ctx.owner}/${ctx.name}/issues/${ctx.pr}/comments?per_page=100`;
  for (let page = 0; page < 10; page++) {
    const res = await gh(ctx.api, ctx.token, 'GET', path);
    if (!Array.isArray(res.json)) {
      throw new CommentPostError('protocol', 'GitHub API returned an unexpected comment list');
    }
    for (const item of res.json) {
      if (!item || typeof item !== 'object') continue;
      const rec = item as Record<string, unknown>;
      if (typeof rec.id !== 'number') continue;
      all.push({
        id: rec.id,
        body: typeof rec.body === 'string' ? rec.body : '',
        url: typeof rec.html_url === 'string' ? rec.html_url : '',
      });
    }
    const next = nextLink(res.link, ctx.api);
    if (!next) break;
    path = next;
  }
  return all;
}

export interface PostedComment {
  url: string | null;
  updated: boolean;
  created: boolean;
}

/** Create a comment, or update the first sticky comment that carries the marker. */
export async function publishComment(
  ctx: CommentContext,
  markdown: string,
  mode: CommentMode,
): Promise<PostedComment> {
  const body = scrubSecrets(markdown, ctx.token);
  if (mode === 'update') {
    const existing = await listComments(ctx);
    const sticky = existing.find((comment) => comment.body.includes(MARKER));
    if (sticky) {
      const res = await gh(
        ctx.api,
        ctx.token,
        'PATCH',
        `/repos/${ctx.owner}/${ctx.name}/issues/comments/${sticky.id}`,
        { body },
      );
      const url = commentUrl(res.json) || sticky.url || null;
      return { url, updated: true, created: false };
    }
  }
  const res = await gh(
    ctx.api,
    ctx.token,
    'POST',
    `/repos/${ctx.owner}/${ctx.name}/issues/${ctx.pr}/comments`,
    { body },
  );
  return { url: commentUrl(res.json), updated: false, created: true };
}

function commentUrl(json: unknown): string | null {
  if (!json || typeof json !== 'object') return null;
  const url = (json as Record<string, unknown>).html_url;
  return typeof url === 'string' && url ? url : null;
}

export function writeStepSummary(markdown: string, env: NodeJS.ProcessEnv = process.env): void {
  const path = env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  const text = markdown.endsWith('\n') ? markdown : `${markdown}\n`;
  appendFileSync(path, text);
}

/** True when this run should call the GitHub API. */
export function shouldPostComment(comment: CommentWhen, verdict: 'pass' | 'fail', dryRun: boolean): boolean {
  if (dryRun || comment === 'off') return false;
  if (comment === 'on-failure') return verdict === 'fail';
  return true;
}
