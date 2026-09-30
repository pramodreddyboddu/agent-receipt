/**
 * Signed one-page HTML report.
 *
 * The page is one file: inline CSS, no images, no fonts, no network.
 * `style-src 'unsafe-inline'` is required because the stylesheet lives in
 * the file. There is no external CSS to hash, and a style hash would have
 * to be rewritten on every CSS edit without adding a boundary the opened
 * file does not already have. `script-src 'none'` blocks executable script.
 * The `<script type="application/json">` blocks are data, not script.
 *
 * The Ed25519 signature covers the canonical JSON payload (see
 * `canonicalReportJson`), not the HTML bytes. Receipt bodies are not in
 * the payload; `report verify` re-hashes them when the files are local.
 * Narrative sections (summary, diffs, review text) are redacted and escaped
 * for display and are not signed. Covered visible fields are bound to the
 * payload with `data-covered` / `data-*` and must match or verify exits 2.
 */

import { escapeHtml, OFFLINE_HTML_CSP } from './html.js';
import { sha256Hex } from './hash.js';
import { defangUrls } from './prove-html.js';
import { isHighSecretRiskCode, redactSecretsInText } from './redact.js';
import type { SignatureDocument } from './sign.js';

export const REPORT_PAYLOAD_KIND = 'agent-receipt-report';
export const REPORT_PAYLOAD_VERSION = 1;
export const REPORT_SCRIPT_ID = 'agent-receipt-report';
export const REPORT_SIG_SCRIPT_ID = 'agent-receipt-report-sig';

export type ReportVerdict = 'VERIFIED' | 'FAILED' | 'UNSIGNED' | 'UNTRUSTED';
export type ReportExposure = 'redacted' | 'host' | 'unredacted';
export type ReportSignatureState = 'valid' | 'invalid' | 'unsigned';

export interface ReportReceiptPayload {
  id: string;
  sha256: string;
  parent: string | null;
  agent: string | null;
  verified: boolean;
  signature: ReportSignatureState;
  fingerprint: string | null;
  trusted: boolean | null;
  originalFingerprint: string | null;
  resignedBy: string | null;
  signedBy: string | null;
}

/**
 * Canonical report payload. The signature is over the UTF-8 hex SHA-256 of
 * `canonicalReportJson(payload)`, the same SignatureDocument pattern as
 * `sign` (the hex string, not the HTML).
 */
export interface ReportPayload {
  kind: typeof REPORT_PAYLOAD_KIND;
  version: typeof REPORT_PAYLOAD_VERSION;
  cliVersion: string;
  generatedAt: string;
  subject: 'receipt' | 'session';
  session: string | null;
  /** SHA-256 of the raw `session-manifest.json` bytes, or null. */
  manifestSha256: string | null;
  exposure: ReportExposure;
  verdict: ReportVerdict;
  /** Exact offline commands shown on the page. Basenames, not absolute paths. */
  verifyCommands: string[];
  receipts: ReportReceiptPayload[];
}

export interface ReportReceiptView {
  payload: ReportReceiptPayload;
  summary: string;
  message: string;
  branch: string;
  head: string;
  range: string;
  timestamp: string;
  commands: string[];
  files: string[];
  risks: Array<{ severity: string; code: string; detail: string }>;
  review: string;
  commits: string;
  /** Capped diff excerpt. Display only. Not signed. */
  diffs: string;
}

export interface ReportView {
  payload: ReportPayload;
  /** Null when local keys did not load. The page then says UNSIGNED. */
  signature: SignatureDocument | null;
  /** Report signer's trust at generation. Null when unsigned or allowlist inactive. */
  reportTrusted: boolean | null;
  receipts: ReportReceiptView[];
  /** Plain text from `formatSessionTree`. Null for a single-receipt report. */
  tree: string | null;
}

export function decideVerdict(
  reportSigned: boolean,
  reportTrusted: boolean | null,
  receipts: ReportReceiptPayload[],
): ReportVerdict {
  if (receipts.some((r) => !r.verified || r.signature === 'invalid')) return 'FAILED';
  if (reportTrusted === false || receipts.some((r) => r.trusted === false)) return 'UNTRUSTED';
  if (!reportSigned) return 'UNSIGNED';
  return 'VERIFIED';
}

/** Stable JSON: sorted object keys, no whitespace. Arrays keep their order. */
export function canonicalReportJson(payload: ReportPayload): string {
  return stableStringify(payload);
}

export function reportPayloadHash(payload: ReportPayload): string {
  return sha256Hex(canonicalReportJson(payload));
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(',')}}`;
}

/** Embed JSON in a script block without letting the text close the tag. */
export function embedJson(value: unknown): string {
  const json = typeof value === 'string' ? value : JSON.stringify(value);
  return json
    .replace(/&/g, '\\u0026')
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function text(value: string | null | undefined, redact = true, fallback = '(none)'): string {
  if (value === null || value === undefined || value === '') return escapeHtml(fallback);
  const raw = redact ? redactSecretsInText(String(value)) : String(value);
  return escapeHtml(defangUrls(raw));
}

function noneHex(value: string | null): string {
  return value ?? 'none';
}

function trustLabel(trusted: boolean | null, signed: boolean): string {
  if (!signed) return 'unsigned';
  if (trusted === true) return 'trusted';
  if (trusted === false) return 'untrusted';
  return 'no trust store';
}

const STYLE = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0 auto;padding:24px;max-width:960px;color:#1f2328;background:#fff}
h1{font-size:22px;margin:0 0 8px}
h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #d0d7de;padding-bottom:4px}
h3{font-size:15px;margin:18px 0 6px}
code,pre{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:#f6f8fa;padding:1px 4px;border-radius:4px;word-break:break-all}
pre{background:#f6f8fa;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.banner{border-radius:8px;padding:16px 20px;margin:0 0 12px;color:#fff}
.banner.verified{background:#1a7f37}
.banner.failed{background:#cf222e}
.banner.unsigned,.banner.untrusted{background:#9a6700}
.banner .verdict{font-size:28px;font-weight:700;letter-spacing:1px}
.banner.unredacted{background:#fff8c5;color:#7d4e00;border:2px solid #9a6700}
table{border-collapse:collapse;width:100%}
th,td{padding:6px 8px;border-top:1px solid #eaeef2;text-align:left;vertical-align:top}
th{color:#57606a;font-weight:600;width:180px}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:1px 8px;border-radius:10px}
.pill.ok{background:#dafbe1;color:#116329}
.pill.bad{background:#ffebe9;color:#a40e26}
.pill.mid{background:#fff8c5;color:#7d4e00}
.muted{color:#57606a}
ul,ol{margin:8px 0;padding-left:20px}
footer{margin-top:32px;font-size:13px;color:#57606a;border-top:1px solid #d0d7de;padding-top:12px}
article{margin:16px 0;padding-top:4px}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}code,pre{background:#161b22}h2,footer{border-color:#30363d}th,td{border-color:#21262d}.muted,th,footer{color:#8b949e}.banner.unredacted{background:#2d2410;color:#f0d58c}}
@media print{.banner{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
`.trim();

function row(label: string, valueHtml: string): string {
  return `<tr><th scope="row">${escapeHtml(label)}</th><td>${valueHtml}</td></tr>`;
}

function pill(kind: 'ok' | 'bad' | 'mid', label: string): string {
  return `<span class="pill ${kind}">${escapeHtml(label)}</span>`;
}

function receiptArticle(view: ReportReceiptView, redact = true): string {
  const show = (value: string | null | undefined, fallback = '(none)') => text(value, redact, fallback);
  const r = view.payload;
  const sig =
    r.signature === 'valid' ? pill('ok', 'VALID') : r.signature === 'invalid' ? pill('bad', 'INVALID') : pill('mid', 'UNSIGNED');
  const trust =
    r.trusted === true ? pill('ok', 'TRUSTED') : r.trusted === false ? pill('bad', 'UNTRUSTED') : pill('mid', trustLabel(r.trusted, r.signature !== 'unsigned').toUpperCase());
  const files = view.files.slice(0, 50).map((f) => `<li><code>${show(f)}</code></li>`).join('');
  const moreFiles = view.files.length > 50 ? `<li class="muted">+${view.files.length - 50} more</li>` : '';
  const risks = view.risks.slice(0, 50).map((item) => {
    const detail = redact && isHighSecretRiskCode(item.code) ? '[REDACTED]' : show(item.detail);
    return `<li>${show(item.severity)} <code>${show(item.code)}</code> ${detail}</li>`;
  }).join('');
  const commands = view.commands.length
    ? view.commands.map((c) => `<li><code>${show(c)}</code></li>`).join('')
    : '<li class="muted">(none)</li>';
  const attrs = [
    `data-id="${escapeHtml(r.id)}"`,
    `data-sha256="${escapeHtml(r.sha256)}"`,
    `data-signature="${r.signature}"`,
    `data-fingerprint="${escapeHtml(noneHex(r.fingerprint))}"`,
    `data-trusted="${r.trusted === null ? 'none' : String(r.trusted)}"`,
    `data-original-fingerprint="${escapeHtml(noneHex(r.originalFingerprint))}"`,
    `data-resigned-by="${escapeHtml(noneHex(r.resignedBy))}"`,
    `data-signed-by="${escapeHtml(noneHex(r.signedBy))}"`,
    `data-verified="${r.verified ? 'true' : 'false'}"`,
  ].join(' ');
  return [
    `<article ${attrs}>`,
    `<h3><code>${show(r.id)}</code></h3>`,
    '<table><tbody>',
    row('SHA-256', `<code data-covered="sha256">${escapeHtml(r.sha256)}</code>`),
    row('Verified', r.verified ? pill('ok', 'yes') : pill('bad', 'no')),
    row('Agent', show(r.agent)),
    row('Parent', r.parent ? `<code>${show(r.parent)}</code>` : '(none)'),
    row('Timestamp', show(view.timestamp)),
    row('Branch', `<code>${show(view.branch)}</code>`),
    row('HEAD', view.head ? `<code>${show(view.head)}</code>` : '(none)'),
    row('Range', `<code>${show(view.range)}</code>`),
    row('Message', show(view.message)),
    row('Summary', show(view.summary)),
    row('Signature', `${sig} ${r.fingerprint ? `<code>${escapeHtml(r.fingerprint)}</code>` : 'no sidecar'}`),
    row('Trust', trust),
    row('originalFingerprint', r.originalFingerprint ? `<code>${escapeHtml(r.originalFingerprint)}</code>` : 'null'),
    row('resignedBy', r.resignedBy ? `<code>${escapeHtml(r.resignedBy)}</code>` : 'null'),
    row('signedBy', r.signedBy ? `<code>${escapeHtml(r.signedBy)}</code>` : 'null'),
    '</tbody></table>',
    '<h2>Commands</h2>',
    `<ul>${commands}</ul>`,
    '<h2>Files touched</h2>',
    files ? `<ul>${files}${moreFiles}</ul>` : '<p class="muted">No file rows in the receipt.</p>',
    '<h2>Risk flags</h2>',
    risks ? `<ul>${risks}</ul>` : '<p class="muted">No risk findings.</p>',
    '<h2>What to review</h2>',
    `<pre>${show(view.review)}</pre>`,
    '<h2>Commits</h2>',
    `<pre>${show(view.commits)}</pre>`,
    '<h2>Diff lines</h2>',
    `<pre>${show(view.diffs)}</pre>`,
    '</article>',
  ].join('\n');
}

const COVERAGE_NOTE =
  'The Ed25519 signature covers the canonical JSON payload (kind, version, cliVersion, generatedAt, subject, session, manifestSha256, exposure, verdict, verifyCommands, and each receipt id, sha256, parent, agent, verified, signature, fingerprint, trusted, originalFingerprint, resignedBy, signedBy). It is the UTF-8 hex SHA-256 of that JSON, signed with the same SignatureDocument as agent-receipt sign. It does not cover CSS, this sentence, or other HTML. Summary, diff, and review text are display-only and redacted. Re-hash the receipt files to check their bodies. originalFingerprint, resignedBy, and signedBy are the manifest signer\'s claims when they come from a session package. This is not a certificate authority.';

/** Render the complete HTML document. Pure: no I/O. */
export function renderReportHtml(view: ReportView): string {
  const payload = view.payload;
  const verdict = payload.verdict;
  const klass = verdict.toLowerCase();
  const signed = view.signature !== null;
  const fp = signed ? view.signature?.fingerprint ?? '' : 'unsigned';
  const trust = trustLabel(view.reportTrusted, signed);
  const commands = payload.verifyCommands
    .map((cmd) => `<li>${escapeHtml(cmd)}</li>`)
    .join('');
  const unredacted =
    payload.exposure === 'redacted'
      ? ''
      : `<div class="banner unredacted" role="status"><strong>UNREDACTED</strong> — ${
          payload.exposure === 'host'
            ? 'host is included. Secrets and nested receipt bodies are still masked.'
            : 'redaction is off. Secrets, host, and nested bodies are shown.'
        }</div>`;
  const tree = view.tree
    ? `<h2>Session tree</h2>\n<pre>${escapeHtml(view.tree)}</pre>`
    : '';
  const canonical = embedJson(canonicalReportJson(payload));
  const sigBlock = view.signature
    ? `<script type="application/json" id="${REPORT_SIG_SCRIPT_ID}">${embedJson(view.signature)}</script>`
    : '';
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="${OFFLINE_HTML_CSP}">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    `<title>Agent Receipt report — ${escapeHtml(verdict)}</title>`,
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    '<!-- style-src unsafe-inline: the stylesheet is in this file so it opens offline. script-src none: the JSON blocks are data, not script. No remote sources. -->',
    `<div class="banner ${klass}" role="status">`,
    `<div class="verdict"><span data-covered="verdict">${escapeHtml(verdict)}</span></div>`,
    `<p>Report signature: ${signed ? 'present' : 'absent'} (${escapeHtml(trust)})</p>`,
    `<p>Fingerprint: <span data-covered="reportFingerprint">${escapeHtml(fp)}</span></p>`,
    '</div>',
    unredacted,
    '<h1>Agent Receipt — signed report</h1>',
    `<p class="muted">CLI <span data-covered="cliVersion">${escapeHtml(payload.cliVersion)}</span> · generated <span data-covered="generatedAt">${escapeHtml(payload.generatedAt)}</span></p>`,
    '<table><tbody>',
    row('Subject', `<span data-covered="subject">${escapeHtml(payload.subject)}</span>`),
    row('Session', `<span data-covered="session">${escapeHtml(payload.session ?? 'none')}</span>`),
    row('Manifest SHA-256', `<span data-covered="manifestSha256">${escapeHtml(payload.manifestSha256 ?? 'none')}</span>`),
    row('Exposure', `<span data-covered="exposure">${escapeHtml(payload.exposure)}</span>`),
    '</tbody></table>',
    '<h2>What the agent did</h2>',
    view.receipts.map((item) => receiptArticle(item, payload.exposure !== 'unredacted')).join('\n'),
    tree,
    '<h2>Re-verify offline</h2>',
    `<ol data-covered="verifyCommands">${commands}</ol>`,
    `<footer><p>${escapeHtml(COVERAGE_NOTE)}</p></footer>`,
    `<script type="application/json" id="${REPORT_SCRIPT_ID}">${canonical}</script>`,
    sigBlock,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

export interface ExtractedReport {
  payload: ReportPayload;
  signature: SignatureDocument | null;
  /** Canonical JSON bytes that were hashed. */
  canonical: string;
  payloadHash: string;
}

export class ReportHtmlError extends Error {
  readonly exitCode: 1 | 2;
  constructor(exitCode: 1 | 2, message: string) {
    super(message);
    this.name = 'ReportHtmlError';
    this.exitCode = exitCode;
  }
}

function extractScript(html: string, id: string): string | null {
  const re = new RegExp(
    `<script type="application/json" id="${id}">([\\s\\S]*?)</script>`,
  );
  const match = html.match(re);
  return match ? match[1] : null;
}

function decodeHtml(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

function coveredText(html: string, name: string): string | null {
  const re = new RegExp(`data-covered="${name}">([^<]*)<`);
  const match = html.match(re);
  return match ? decodeHtml(match[1]) : null;
}

function attr(tag: string, name: string): string | null {
  const re = new RegExp(`\\s${name}="([^"]*)"`);
  const match = tag.match(re);
  return match ? decodeHtml(match[1]) : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function parseReportHtml(html: string): ExtractedReport {
  const raw = extractScript(html, REPORT_SCRIPT_ID);
  if (raw === null) {
    throw new ReportHtmlError(1, 'report is missing the embedded payload (script#agent-receipt-report)');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ReportHtmlError(1, 'embedded report payload is malformed JSON');
  }
  const payload = parsePayload(parsed);
  const canonical = canonicalReportJson(payload);
  const payloadHash = sha256Hex(canonical);
  const sigRaw = extractScript(html, REPORT_SIG_SCRIPT_ID);
  let signature: SignatureDocument | null = null;
  if (sigRaw !== null) {
    try {
      signature = JSON.parse(sigRaw) as SignatureDocument;
    } catch {
      throw new ReportHtmlError(1, 'embedded report signature is malformed JSON');
    }
  }
  return { payload, signature, canonical, payloadHash };
}

function parsePayload(value: unknown): ReportPayload {
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(1, 'report payload must be an object');
  if (doc.kind !== REPORT_PAYLOAD_KIND) {
    throw new ReportHtmlError(1, 'report payload kind is not agent-receipt-report');
  }
  if (doc.version !== REPORT_PAYLOAD_VERSION) {
    throw new ReportHtmlError(1, 'unsupported report payload version');
  }
  if (typeof doc.cliVersion !== 'string' || !doc.cliVersion) {
    throw new ReportHtmlError(1, 'report payload cliVersion is missing');
  }
  if (typeof doc.generatedAt !== 'string' || !doc.generatedAt) {
    throw new ReportHtmlError(1, 'report payload generatedAt is missing');
  }
  if (doc.subject !== 'receipt' && doc.subject !== 'session') {
    throw new ReportHtmlError(1, 'report payload subject is invalid');
  }
  if (doc.session !== null && typeof doc.session !== 'string') {
    throw new ReportHtmlError(1, 'report payload session is invalid');
  }
  if (doc.manifestSha256 !== null && (typeof doc.manifestSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(doc.manifestSha256))) {
    throw new ReportHtmlError(1, 'report payload manifestSha256 is invalid');
  }
  if (doc.exposure !== 'redacted' && doc.exposure !== 'host' && doc.exposure !== 'unredacted') {
    throw new ReportHtmlError(1, 'report payload exposure is invalid');
  }
  if (doc.verdict !== 'VERIFIED' && doc.verdict !== 'FAILED' && doc.verdict !== 'UNSIGNED' && doc.verdict !== 'UNTRUSTED') {
    throw new ReportHtmlError(1, 'report payload verdict is invalid');
  }
  if (!Array.isArray(doc.verifyCommands) || doc.verifyCommands.some((c) => typeof c !== 'string')) {
    throw new ReportHtmlError(1, 'report payload verifyCommands is invalid');
  }
  if (!Array.isArray(doc.receipts) || doc.receipts.length < 1) {
    throw new ReportHtmlError(1, 'report payload receipts is empty');
  }
  const receipts = doc.receipts.map((item, index) => parseReceipt(item, index));
  return {
    kind: REPORT_PAYLOAD_KIND,
    version: REPORT_PAYLOAD_VERSION,
    cliVersion: doc.cliVersion,
    generatedAt: doc.generatedAt,
    subject: doc.subject,
    session: doc.session,
    manifestSha256: doc.manifestSha256,
    exposure: doc.exposure,
    verdict: doc.verdict,
    verifyCommands: doc.verifyCommands,
    receipts,
  };
}

function hexOrNull(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)) return value;
  throw new ReportHtmlError(1, `report payload ${label} is invalid`);
}

function parseReceipt(value: unknown, index: number): ReportReceiptPayload {
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(1, `report payload receipts[${index}] must be an object`);
  if (typeof doc.id !== 'string' || !doc.id) {
    throw new ReportHtmlError(1, `report payload receipts[${index}].id is missing`);
  }
  if (typeof doc.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(doc.sha256)) {
    throw new ReportHtmlError(1, `report payload receipts[${index}].sha256 is invalid`);
  }
  if (doc.parent !== null && typeof doc.parent !== 'string') {
    throw new ReportHtmlError(1, `report payload receipts[${index}].parent is invalid`);
  }
  if (doc.agent !== null && typeof doc.agent !== 'string') {
    throw new ReportHtmlError(1, `report payload receipts[${index}].agent is invalid`);
  }
  if (typeof doc.verified !== 'boolean') {
    throw new ReportHtmlError(1, `report payload receipts[${index}].verified is invalid`);
  }
  if (doc.signature !== 'valid' && doc.signature !== 'invalid' && doc.signature !== 'unsigned') {
    throw new ReportHtmlError(1, `report payload receipts[${index}].signature is invalid`);
  }
  if (doc.trusted !== null && typeof doc.trusted !== 'boolean') {
    throw new ReportHtmlError(1, `report payload receipts[${index}].trusted is invalid`);
  }
  return {
    id: doc.id,
    sha256: doc.sha256,
    parent: doc.parent,
    agent: doc.agent,
    verified: doc.verified,
    signature: doc.signature,
    fingerprint: hexOrNull(doc.fingerprint, `receipts[${index}].fingerprint`),
    trusted: doc.trusted,
    originalFingerprint: hexOrNull(doc.originalFingerprint, `receipts[${index}].originalFingerprint`),
    resignedBy: hexOrNull(doc.resignedBy, `receipts[${index}].resignedBy`),
    signedBy: hexOrNull(doc.signedBy, `receipts[${index}].signedBy`),
  };
}

/**
 * Visible fields that the payload covers must match the payload.
 * A mismatch is tampering (exit 2), even when the JSON was left intact.
 */
export function assertCoveredVisible(html: string, payload: ReportPayload, signature: SignatureDocument | null): void {
  const expect = (name: string, value: string): void => {
    const got = coveredText(html, name);
    if (got === null) {
      throw new ReportHtmlError(2, `visible ${name} is missing`);
    }
    if (got !== value) {
      throw new ReportHtmlError(2, `visible ${name} does not match the signed payload`);
    }
  };
  expect('verdict', payload.verdict);
  expect('cliVersion', payload.cliVersion);
  expect('generatedAt', payload.generatedAt);
  expect('subject', payload.subject);
  expect('session', payload.session ?? 'none');
  expect('manifestSha256', payload.manifestSha256 ?? 'none');
  expect('exposure', payload.exposure);
  expect('reportFingerprint', signature ? signature.fingerprint : 'unsigned');
  if (payload.exposure !== 'redacted' && !html.includes('UNREDACTED')) {
    throw new ReportHtmlError(2, 'visible unredacted marker is missing');
  }
  if (payload.exposure === 'redacted' && html.includes('UNREDACTED')) {
    throw new ReportHtmlError(2, 'visible unredacted marker is not in the signed payload');
  }
  const list = html.match(/<ol data-covered="verifyCommands">([\s\S]*?)<\/ol>/);
  if (!list) throw new ReportHtmlError(2, 'visible verify commands are missing');
  const items = [...list[1].matchAll(/<li>([^<]*)<\/li>/g)].map((m) => decodeHtml(m[1]));
  if (items.length !== payload.verifyCommands.length || items.some((item, i) => item !== payload.verifyCommands[i])) {
    throw new ReportHtmlError(2, 'visible verify commands do not match the signed payload');
  }
  const articles = [...html.matchAll(/<article\b([^>]*)>([\s\S]*?)<\/article>/g)];
  if (articles.length !== payload.receipts.length) {
    throw new ReportHtmlError(2, 'visible receipt count does not match the signed payload');
  }
  for (const receipt of payload.receipts) {
    const article = articles.find((block) => attr(block[1], 'data-id') === receipt.id);
    if (!article) throw new ReportHtmlError(2, `visible receipt ${receipt.id} is missing`);
    const tag = article[1];
    const body = article[2];
    const sha = body.match(/data-covered="sha256">([^<]*)</);
    if (!sha || decodeHtml(sha[1]) !== receipt.sha256) {
      throw new ReportHtmlError(2, `visible sha256 for ${receipt.id} does not match the signed payload`);
    }
    const check = (name: string, expected: string): void => {
      const got = attr(tag, name);
      if (got !== expected) {
        throw new ReportHtmlError(2, `visible ${name} for ${receipt.id} does not match the signed payload`);
      }
    };
    check('data-sha256', receipt.sha256);
    check('data-signature', receipt.signature);
    check('data-fingerprint', noneHex(receipt.fingerprint));
    check('data-trusted', receipt.trusted === null ? 'none' : String(receipt.trusted));
    check('data-original-fingerprint', noneHex(receipt.originalFingerprint));
    check('data-resigned-by', noneHex(receipt.resignedBy));
    check('data-signed-by', noneHex(receipt.signedBy));
    check('data-verified', receipt.verified ? 'true' : 'false');
  }
}
