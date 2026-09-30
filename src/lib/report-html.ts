/**
 * Signed one-page HTML report.
 *
 * `renderReportHtml(payload, signature)` is a pure function. Every string
 * the page shows lives in the canonical payload. The signature document is
 * not part of that payload (signing it would be circular). It is inserted
 * at a fixed place after the payload block. `report verify` re-renders and
 * requires the same bytes. A missing final newline is the only difference
 * that is ignored.
 *
 * The page is one file: inline CSS, no images, no fonts, no network.
 * `style-src 'unsafe-inline'` is required because the stylesheet lives in
 * the file. `script-src 'none'` blocks executable script. The
 * `<script type="application/json">` blocks are data, not script.
 */

import { escapeHtml, OFFLINE_HTML_CSP } from './html.js';
import { sha256Hex } from './hash.js';
import type { SignatureDocument } from './sign.js';

export const REPORT_PAYLOAD_KIND = 'agent-receipt-report';
export const REPORT_PAYLOAD_VERSION = 1;
/** HTML template id. The next template is a new renderer; this one stays. */
export const REPORT_RENDER_VERSION = 1;
export const REPORT_SCRIPT_ID = 'agent-receipt-report';
export const REPORT_SIG_SCRIPT_ID = 'agent-receipt-report-sig';
/** Opening tag of the signed payload block. `report` refuses any file that contains it. */
export const REPORT_PAYLOAD_MARKER = `<script type="application/json" id="${REPORT_SCRIPT_ID}">`;

/** Human and JSON reason when the file is not the re-rendered page. */
export const PAGE_MISMATCH_MESSAGE = 'page content does not match signed payload';

/**
 * A checkout with core.autocrlf=true rewrites the page. Verify names that
 * and still exits 2. The CR bytes are not normalized away.
 */
export const CRLF_PAGE_MESSAGE =
  'page has CRLF line endings — was it checked out with core.autocrlf? add `*.report.html -text` to .gitattributes';

/** A bare CR. CRLF (`\r\n`) keeps CRLF_PAGE_MESSAGE. */
export const CR_PAGE_MESSAGE = 'page has CR line endings';

/** Leading EF BB BF. TextDecoder is created with ignoreBOM so this is not stripped. */
export const BOM_PAGE_MESSAGE = 'page starts with a UTF-8 BOM';

export const INVALID_UTF8_MESSAGE = 'report page is not valid UTF-8';

export type ReportVerdict = 'VERIFIED' | 'FAILED' | 'UNSIGNED' | 'UNTRUSTED';
export type ReportExposure = 'redacted' | 'host' | 'unredacted';
export type ReportSignatureState = 'valid' | 'invalid' | 'unsigned';
export type ReportBannerClass = 'verified' | 'failed' | 'unsigned' | 'untrusted';

export interface ReportBanner {
  className: ReportBannerClass;
  /** Same word as `verdict`. This is the banner text. */
  verdict: ReportVerdict;
  /** Exact line, e.g. "Report signature: present (trusted)". */
  signatureStatus: string;
  /** Signer fingerprint, or "unsigned". */
  fingerprint: string;
}

export interface ReportUnredacted {
  marker: 'UNREDACTED';
  detail: string;
}

export interface ReportPills {
  verified: 'yes' | 'no';
  signature: 'VALID' | 'INVALID' | 'UNSIGNED';
  trust: string;
}

export interface ReportRisk {
  severity: string;
  code: string;
  detail: string;
}

/**
 * One receipt as the page shows it, plus the hashes verify may re-check.
 * `sha256` is the canonical hash of the file the report was built from.
 * `redactedSha256` is the canonical hash of the default redacted body when
 * that hash differs. A file whose raw sha256 equals `sha256` or
 * `redactedSha256` matches in a local store and in a package. Only a
 * session-package report may also accept a redact-then-hash of the body,
 * and then a non-null originalFingerprint requires that sidecar.
 */
export interface ReportReceiptPayload {
  id: string;
  sha256: string;
  redactedSha256: string | null;
  parent: string | null;
  agent: string | null;
  verified: boolean;
  signature: ReportSignatureState;
  fingerprint: string | null;
  trusted: boolean | null;
  originalFingerprint: string | null;
  resignedBy: string | null;
  signedBy: string | null;
  pills: ReportPills;
  timestamp: string;
  branch: string;
  head: string;
  range: string;
  message: string;
  summary: string;
  commands: string[];
  files: string[];
  risks: ReportRisk[];
  review: string;
  commits: string;
  diffs: string;
}

/**
 * Canonical report payload. The signature is over the UTF-8 hex SHA-256 of
 * `canonicalReportJson(payload)`, the same SignatureDocument pattern as
 * `sign` (the hex string, not the HTML). The HTML is then rendered from
 * this object plus the signature document, and verify requires those bytes.
 */
export interface ReportPayload {
  kind: typeof REPORT_PAYLOAD_KIND;
  version: typeof REPORT_PAYLOAD_VERSION;
  /**
   * Which HTML renderer wrote the page. 1 is this template.
   * Verify selects the renderer by this integer.
   */
  renderVersion: number;
  cliVersion: string;
  generatedAt: string;
  subject: 'receipt' | 'session';
  session: string | null;
  /** SHA-256 of the raw `session-manifest.json` bytes, or null. */
  manifestSha256: string | null;
  exposure: ReportExposure;
  verdict: ReportVerdict;
  title: string;
  banner: ReportBanner;
  /** Null when exposure is redacted. The page then has no UNREDACTED marker. */
  unredacted: ReportUnredacted | null;
  /** Exact offline commands shown on the page. Basenames, not absolute paths. */
  verifyCommands: string[];
  /** Plain session tree, or null for a single-receipt report. */
  tree: string | null;
  receipts: ReportReceiptPayload[];
}

export function reportTitle(verdict: ReportVerdict): string {
  return `Agent Receipt report — ${verdict}`;
}

export function reportBanner(
  verdict: ReportVerdict,
  signed: boolean,
  trusted: boolean | null,
  fingerprint: string | null,
): ReportBanner {
  const trust = !signed
    ? 'unsigned'
    : trusted === true
      ? 'trusted'
      : trusted === false
        ? 'untrusted'
        : 'no trust store';
  return {
    className: verdict.toLowerCase() as ReportBannerClass,
    verdict,
    signatureStatus: `Report signature: ${signed ? 'present' : 'absent'} (${trust})`,
    fingerprint: signed && fingerprint ? fingerprint : 'unsigned',
  };
}

export function reportUnredacted(exposure: ReportExposure): ReportUnredacted | null {
  if (exposure === 'redacted') return null;
  if (exposure === 'host') {
    return {
      marker: 'UNREDACTED',
      detail: 'host is included. Secrets and nested receipt bodies are still masked.',
    };
  }
  return {
    marker: 'UNREDACTED',
    detail: 'redaction is off. Secrets, host, and nested bodies are shown.',
  };
}

export function reportPills(receipt: {
  verified: boolean;
  signature: ReportSignatureState;
  trusted: boolean | null;
}): ReportPills {
  const trust =
    receipt.trusted === true
      ? 'TRUSTED'
      : receipt.trusted === false
        ? 'UNTRUSTED'
        : receipt.signature === 'unsigned'
          ? 'UNSIGNED'
          : 'NO TRUST STORE';
  return {
    verified: receipt.verified ? 'yes' : 'no',
    signature:
      receipt.signature === 'valid' ? 'VALID' : receipt.signature === 'invalid' ? 'INVALID' : 'UNSIGNED',
    trust,
  };
}

export function decideVerdict(
  reportSigned: boolean,
  reportTrusted: boolean | null,
  receipts: Array<{ verified: boolean; signature: ReportSignatureState; trusted: boolean | null }>,
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

/**
 * Turn a receipt Range or Summary into the words the page shows.
 * Tables become "label: value" lines. Backticks, bold, and emphasis
 * markers are removed. The caller still HTML-escapes the result.
 */
export function plainReportText(value: string): string {
  const lines = value.replace(/\r\n/g, '\n').split('\n');
  const out: string[] = [];
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (trimmed.includes('|')) {
      const cells = trimmed
        .replace(/^\|/, '')
        .replace(/\|$/, '')
        .split('|')
        .map((cell) => cell.trim());
      if (cells.length >= 2 && cells.every((cell) => /^:?-{3,}:?$/.test(cell))) continue;
      if (cells.length >= 2 && cells[0].toLowerCase() === 'metric' && cells[1].toLowerCase() === 'value') {
        continue;
      }
      if (cells.length >= 2) {
        out.push(stripInlineMd(`${cells[0]}: ${cells.slice(1).join(' ')}`));
        continue;
      }
    }
    out.push(stripInlineMd(trimmed));
  }
  return out.join('\n').trim();
}

function stripInlineMd(value: string): string {
  return value
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\*\*([^*]*)\*\*/g, '$1')
    .replace(/_([^_\n]+)_/g, '$1')
    .replace(/\*([^*\n]+)\*/g, '$1')
    .replace(/`/g, '')
    .trim();
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

const COVERAGE_NOTE =
  'The Ed25519 signature covers the canonical JSON payload embedded in this file (sorted keys, no whitespace). report verify re-renders this page from that payload and the signature block and requires the same bytes. A single missing trailing newline is ignored. Any other difference, including this sentence, the banner, the pills, the narrative, and the exposure marker, fails verify. renderVersion selects this HTML renderer. Every same-id file, and every file whose raw or embedded hash is the recorded sha256 or redactedSha256, must pass integrity. A raw sha256 equal to the recorded sha256 or redactedSha256 matches. A session-package report may also match the redacted form, and a non-null originalFingerprint then requires a valid sidecar with that fingerprint. A symlink fails verify. originalFingerprint, resignedBy, and signedBy are the manifest signer\'s claims when they come from a session package. This is not a certificate authority.';

/**
 * Bidi controls are rendered as \\uXXXX so a receipt cannot reorder the page.
 * U+202A–U+202E, U+2066–U+2069, and the LRM/RLM marks U+200E/U+200F.
 */
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g;

export function neutralizeBidi(value: string): string {
  return value.replace(BIDI_RE, (ch) => {
    const hex = ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
    return `\\u${hex}`;
  });
}

function showText(value: string): string {
  return escapeHtml(neutralizeBidi(value));
}

function row(label: string, valueHtml: string): string {
  return `<tr><th scope="row">${showText(label)}</th><td>${valueHtml}</td></tr>`;
}

function pillClass(label: string): 'ok' | 'bad' | 'mid' {
  if (label === 'yes' || label === 'VALID' || label === 'TRUSTED') return 'ok';
  if (label === 'no' || label === 'INVALID' || label === 'UNTRUSTED') return 'bad';
  return 'mid';
}

function pill(label: string): string {
  return `<span class="pill ${pillClass(label)}">${showText(label)}</span>`;
}

function codeOr(value: string | null, empty: string): string {
  return value ? `<code>${showText(value)}</code>` : showText(empty);
}

function receiptArticle(receipt: ReportReceiptPayload): string {
  const files = receipt.files.slice(0, 50).map((file) => `<li><code>${showText(file)}</code></li>`).join('');
  const moreFiles = receipt.files.length > 50 ? `<li class="muted">+${receipt.files.length - 50} more</li>` : '';
  const risks = receipt.risks
    .slice(0, 50)
    .map((item) => `<li>${showText(item.severity)} <code>${showText(item.code)}</code> ${showText(item.detail)}</li>`)
    .join('');
  const moreRisks = receipt.risks.length > 50 ? `<li class="muted">+${receipt.risks.length - 50} more</li>` : '';
  const commands = receipt.commands.length
    ? receipt.commands.map((command) => `<li><code>${showText(command)}</code></li>`).join('')
    : '<li class="muted">(none)</li>';
  const signature = receipt.fingerprint
    ? `${pill(receipt.pills.signature)} <code>${showText(receipt.fingerprint)}</code>`
    : `${pill(receipt.pills.signature)} no sidecar`;
  return [
    '<article>',
    `<h3><code>${showText(receipt.id)}</code></h3>`,
    '<table><tbody>',
    row('SHA-256', `<code>${showText(receipt.sha256)}</code>`),
    row('Verified', pill(receipt.pills.verified)),
    row('Agent', showText(receipt.agent ?? '(none)')),
    row('Parent', codeOr(receipt.parent, '(none)')),
    row('Timestamp', showText(receipt.timestamp)),
    row('Branch', `<code>${showText(receipt.branch)}</code>`),
    row('HEAD', codeOr(receipt.head === '(none)' ? null : receipt.head, '(none)')),
    row('Range', `<code>${showText(receipt.range)}</code>`),
    row('Message', showText(receipt.message)),
    row('Summary', `<pre>${showText(receipt.summary)}</pre>`),
    row('Signature', signature),
    row('Trust', pill(receipt.pills.trust)),
    row('originalFingerprint', codeOr(receipt.originalFingerprint, 'null')),
    row('resignedBy', codeOr(receipt.resignedBy, 'null')),
    row('signedBy', codeOr(receipt.signedBy, 'null')),
    '</tbody></table>',
    '<h2>Commands</h2>',
    `<ul>${commands}</ul>`,
    '<h2>Files touched</h2>',
    files ? `<ul>${files}${moreFiles}</ul>` : '<p class="muted">No file rows in the receipt.</p>',
    '<h2>Risk flags</h2>',
    risks ? `<ul>${risks}${moreRisks}</ul>` : '<p class="muted">No risk findings.</p>',
    '<h2>What to review</h2>',
    `<pre>${showText(receipt.review)}</pre>`,
    '<h2>Commits</h2>',
    `<pre>${showText(receipt.commits)}</pre>`,
    '<h2>Diff lines</h2>',
    `<pre>${showText(receipt.diffs)}</pre>`,
    '</article>',
  ].join('\n');
}

function canonicalSignature(doc: SignatureDocument): SignatureDocument {
  return {
    alg: 'ed25519',
    version: 1,
    sha256: doc.sha256,
    fingerprint: doc.fingerprint,
    signature: doc.signature,
    publicKey: doc.publicKey,
  };
}

/**
 * v1 page. Later templates add a function and a map entry. Do not edit this
 * body to change the look of a new renderVersion.
 */
function renderReportHtmlV1(payload: ReportPayload, signature: SignatureDocument | null): string {
  const banner = payload.banner;
  const commands = payload.verifyCommands.map((command) => `<li>${showText(command)}</li>`).join('');
  const unredacted = payload.unredacted
    ? `<div class="banner unredacted" role="status"><strong>${showText(payload.unredacted.marker)}</strong> — ${showText(payload.unredacted.detail)}</div>`
    : '';
  const tree =
    payload.tree === null
      ? ''
      : `<h2>Session tree</h2>\n<pre>${showText(payload.tree)}</pre>`;
  const sigJson = signature ? embedJson(canonicalSignature(signature)) : 'null';
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="${OFFLINE_HTML_CSP}">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    `<title>${showText(payload.title)}</title>`,
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    '<!-- style-src unsafe-inline: the stylesheet is in this file so it opens offline. script-src none: the JSON blocks are data, not script. No remote sources. -->',
    `<div class="banner ${banner.className}" role="status">`,
    `<div class="verdict">${showText(banner.verdict)}</div>`,
    `<p>${showText(banner.signatureStatus)}</p>`,
    `<p>Fingerprint: <code>${showText(banner.fingerprint)}</code></p>`,
    '</div>',
    unredacted,
    '<h1>Agent Receipt — signed report</h1>',
    `<p class="muted">CLI ${showText(payload.cliVersion)} · generated ${showText(payload.generatedAt)}</p>`,
    '<table><tbody>',
    row('Subject', showText(payload.subject)),
    row('Session', showText(payload.session ?? 'none')),
    row('Manifest SHA-256', showText(payload.manifestSha256 ?? 'none')),
    row('Exposure', showText(payload.exposure)),
    '</tbody></table>',
    '<h2>What the agent did</h2>',
    payload.receipts.map((receipt) => receiptArticle(receipt)).join('\n'),
    tree,
    '<h2>Re-verify offline</h2>',
    `<ol>${commands}</ol>`,
    `<footer><p>${showText(COVERAGE_NOTE)}</p></footer>`,
    `<script type="application/json" id="${REPORT_SCRIPT_ID}">${embedJson(canonicalReportJson(payload))}</script>`,
    `<script type="application/json" id="${REPORT_SIG_SCRIPT_ID}">${sigJson}</script>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

/**
 * HTML renderers keyed by payload.renderVersion.
 * A template change adds the next function here and leaves the old one.
 */
const REPORT_RENDERERS: Record<number, typeof renderReportHtmlV1> = {
  1: renderReportHtmlV1,
};

/**
 * Render the complete HTML document for payload.renderVersion.
 * `signature` null writes the signature block as JSON `null` (UNSIGNED).
 * An unknown renderVersion exits 2. The v1 renderer is kept.
 */
export function renderReportHtml(payload: ReportPayload, signature: SignatureDocument | null): string {
  const render = REPORT_RENDERERS[payload.renderVersion];
  if (!render) {
    throw new ReportHtmlError(2, `unsupported report renderVersion ${payload.renderVersion}`);
  }
  return render(payload, signature);
}

/**
 * The renderer always ends with one newline. Verify treats a file that is
 * missing that single newline as the same page. Any other byte differs.
 */
export function normalizeReportHtml(html: string): string {
  return html.endsWith('\n') ? html : `${html}\n`;
}

export function assertRenderedPage(
  html: string,
  payload: ReportPayload,
  signature: SignatureDocument | null,
): void {
  const expected = renderReportHtml(payload, signature);
  const actual = normalizeReportHtml(html);
  if (actual !== expected) {
    throw new ReportHtmlError(2, PAGE_MISMATCH_MESSAGE);
  }
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

interface ParsedTag {
  name: string;
  closing: boolean;
  attrs: Map<string, string>;
  end: number;
}

/** Read one HTML tag starting at `<`. Quoted attributes are honored. Returns null for comments and declarations. */
function readTag(html: string, start: number): ParsedTag | null {
  if (html[start] !== '<') return null;
  if (html.startsWith('<!--', start) || html.startsWith('<!', start) || html.startsWith('<?', start)) return null;
  let i = start + 1;
  let closing = false;
  if (html[i] === '/') {
    closing = true;
    i += 1;
  }
  const nameStart = i;
  while (i < html.length && /[A-Za-z0-9]/.test(html[i])) i += 1;
  if (i === nameStart) return null;
  const name = html.slice(nameStart, i).toLowerCase();
  const attrs = new Map<string, string>();
  while (i < html.length) {
    while (i < html.length && /[\t\n\r\f ]/.test(html[i])) i += 1;
    if (i >= html.length) return null;
    if (html[i] === '>') return { name, closing, attrs, end: i + 1 };
    if (html[i] === '/' && html[i + 1] === '>') return { name, closing, attrs, end: i + 2 };
    const attrStart = i;
    while (i < html.length && /[^\s=/>]/.test(html[i])) i += 1;
    const attrName = html.slice(attrStart, i).toLowerCase();
    while (i < html.length && /[\t\n\r\f ]/.test(html[i])) i += 1;
    if (html[i] !== '=') {
      if (attrName) attrs.set(attrName, '');
      else i += 1; // a lone "/" is not an attribute name; do not spin
      continue;
    }
    i += 1;
    while (i < html.length && /[\t\n\r\f ]/.test(html[i])) i += 1;
    let value = '';
    if (html[i] === '"' || html[i] === "'") {
      const quote = html[i];
      i += 1;
      const valueStart = i;
      while (i < html.length && html[i] !== quote) i += 1;
      value = html.slice(valueStart, i);
      if (html[i] === quote) i += 1;
    } else {
      const valueStart = i;
      while (i < html.length && /[^\s>]/.test(html[i])) i += 1;
      value = html.slice(valueStart, i);
    }
    if (attrName) attrs.set(attrName, value);
  }
  return null;
}

function findClosingScript(html: string, from: number): { start: number; end: number } | null {
  for (let i = from; i < html.length; i += 1) {
    if (html[i] !== '<') continue;
    const tag = readTag(html, i);
    if (tag && tag.closing && tag.name === 'script') return { start: i, end: tag.end };
    if (!tag) continue;
    i = tag.end - 1;
  }
  return null;
}

interface FoundBlock {
  id: string;
  body: string;
  inComment: boolean;
}

/**
 * Walk the document. Script bodies are not scanned (HTML rawtext).
 * A payload or signature block inside a comment is recorded as such.
 */
function scanReportBlocks(html: string): FoundBlock[] {
  const blocks: FoundBlock[] = [];
  let i = 0;
  let inComment = false;
  while (i < html.length) {
    if (!inComment && html.startsWith('<!--', i)) {
      inComment = true;
      i += 4;
      continue;
    }
    if (inComment && html.startsWith('-->', i)) {
      inComment = false;
      i += 3;
      continue;
    }
    if (html[i] !== '<') {
      i += 1;
      continue;
    }
    const tag = readTag(html, i);
    if (!tag) {
      i += 1;
      continue;
    }
    if (!tag.closing && tag.name === 'script') {
      const close = findClosingScript(html, tag.end);
      if (!close) {
        throw new ReportHtmlError(2, 'report script block is not closed');
      }
      const id = tag.attrs.get('id') ?? '';
      const type = (tag.attrs.get('type') ?? '').toLowerCase();
      if (type === 'application/json' && (id === REPORT_SCRIPT_ID || id === REPORT_SIG_SCRIPT_ID)) {
        blocks.push({ id, body: html.slice(tag.end, close.start), inComment });
      }
      i = close.end;
      continue;
    }
    i = tag.end;
  }
  if (inComment) {
    throw new ReportHtmlError(2, 'report HTML comment is not closed');
  }
  return blocks;
}

function requireOne(blocks: FoundBlock[], id: string, label: string): string {
  const matched = blocks.filter((block) => block.id === id);
  if (matched.some((block) => block.inComment)) {
    throw new ReportHtmlError(2, `report ${label} block is inside a comment`);
  }
  const live = matched.filter((block) => !block.inComment);
  if (live.length === 0) throw new ReportHtmlError(2, `report ${label} block is missing`);
  if (live.length > 1) throw new ReportHtmlError(2, `report has more than one ${label} block`);
  return live[0].body;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function rejectUnknown(doc: Record<string, unknown>, allowed: readonly string[], label: string): void {
  for (const key of Object.keys(doc)) {
    if (!allowed.includes(key)) {
      throw new ReportHtmlError(2, `${label} has unknown field ${key}`);
    }
  }
}

const HEX64 = /^[0-9a-f]{64}$/;

function hexOrNull(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value === 'string' && HEX64.test(value)) return value;
  throw new ReportHtmlError(2, `report payload ${label} is invalid`);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new ReportHtmlError(2, `report payload ${label} is invalid`);
  return value;
}

function parsePills(value: unknown, index: number): ReportPills {
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(2, `report payload receipts[${index}].pills is invalid`);
  rejectUnknown(doc, ['verified', 'signature', 'trust'], `report payload receipts[${index}].pills`);
  if (doc.verified !== 'yes' && doc.verified !== 'no') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].pills.verified is invalid`);
  }
  if (doc.signature !== 'VALID' && doc.signature !== 'INVALID' && doc.signature !== 'UNSIGNED') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].pills.signature is invalid`);
  }
  if (typeof doc.trust !== 'string' || !doc.trust) {
    throw new ReportHtmlError(2, `report payload receipts[${index}].pills.trust is invalid`);
  }
  return { verified: doc.verified, signature: doc.signature, trust: doc.trust };
}

function parseRisks(value: unknown, index: number): ReportRisk[] {
  if (!Array.isArray(value)) throw new ReportHtmlError(2, `report payload receipts[${index}].risks is invalid`);
  return value.map((item, riskIndex) => {
    const doc = asRecord(item);
    if (!doc) throw new ReportHtmlError(2, `report payload receipts[${index}].risks[${riskIndex}] is invalid`);
    rejectUnknown(doc, ['severity', 'code', 'detail'], `report payload receipts[${index}].risks[${riskIndex}]`);
    if (typeof doc.severity !== 'string' || typeof doc.code !== 'string' || typeof doc.detail !== 'string') {
      throw new ReportHtmlError(2, `report payload receipts[${index}].risks[${riskIndex}] is invalid`);
    }
    return { severity: doc.severity, code: doc.code, detail: doc.detail };
  });
}

function parseStringList(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new ReportHtmlError(2, `report payload ${label} is invalid`);
  }
  return value as string[];
}

const RECEIPT_KEYS = [
  'id',
  'sha256',
  'redactedSha256',
  'parent',
  'agent',
  'verified',
  'signature',
  'fingerprint',
  'trusted',
  'originalFingerprint',
  'resignedBy',
  'signedBy',
  'pills',
  'timestamp',
  'branch',
  'head',
  'range',
  'message',
  'summary',
  'commands',
  'files',
  'risks',
  'review',
  'commits',
  'diffs',
] as const;

function parseReceipt(value: unknown, index: number): ReportReceiptPayload {
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(2, `report payload receipts[${index}] must be an object`);
  rejectUnknown(doc, RECEIPT_KEYS, `report payload receipts[${index}]`);
  if (typeof doc.id !== 'string' || !doc.id) {
    throw new ReportHtmlError(2, `report payload receipts[${index}].id is missing`);
  }
  if (typeof doc.sha256 !== 'string' || !HEX64.test(doc.sha256)) {
    throw new ReportHtmlError(2, `report payload receipts[${index}].sha256 is invalid`);
  }
  if (doc.parent !== null && typeof doc.parent !== 'string') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].parent is invalid`);
  }
  if (doc.agent !== null && typeof doc.agent !== 'string') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].agent is invalid`);
  }
  if (typeof doc.verified !== 'boolean') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].verified is invalid`);
  }
  if (doc.signature !== 'valid' && doc.signature !== 'invalid' && doc.signature !== 'unsigned') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].signature is invalid`);
  }
  if (doc.trusted !== null && typeof doc.trusted !== 'boolean') {
    throw new ReportHtmlError(2, `report payload receipts[${index}].trusted is invalid`);
  }
  return {
    id: doc.id,
    sha256: doc.sha256,
    redactedSha256: hexOrNull(doc.redactedSha256, `receipts[${index}].redactedSha256`),
    parent: doc.parent,
    agent: doc.agent,
    verified: doc.verified,
    signature: doc.signature,
    fingerprint: hexOrNull(doc.fingerprint, `receipts[${index}].fingerprint`),
    trusted: doc.trusted,
    originalFingerprint: hexOrNull(doc.originalFingerprint, `receipts[${index}].originalFingerprint`),
    resignedBy: hexOrNull(doc.resignedBy, `receipts[${index}].resignedBy`),
    signedBy: hexOrNull(doc.signedBy, `receipts[${index}].signedBy`),
    pills: parsePills(doc.pills, index),
    timestamp: requiredString(doc.timestamp, `receipts[${index}].timestamp`),
    branch: requiredString(doc.branch, `receipts[${index}].branch`),
    head: requiredString(doc.head, `receipts[${index}].head`),
    range: requiredString(doc.range, `receipts[${index}].range`),
    message: requiredString(doc.message, `receipts[${index}].message`),
    summary: requiredString(doc.summary, `receipts[${index}].summary`),
    commands: parseStringList(doc.commands, `receipts[${index}].commands`),
    files: parseStringList(doc.files, `receipts[${index}].files`),
    risks: parseRisks(doc.risks, index),
    review: requiredString(doc.review, `receipts[${index}].review`),
    commits: requiredString(doc.commits, `receipts[${index}].commits`),
    diffs: requiredString(doc.diffs, `receipts[${index}].diffs`),
  };
}

const PAYLOAD_KEYS = [
  'kind',
  'version',
  'renderVersion',
  'cliVersion',
  'generatedAt',
  'subject',
  'session',
  'manifestSha256',
  'exposure',
  'verdict',
  'title',
  'banner',
  'unredacted',
  'verifyCommands',
  'tree',
  'receipts',
] as const;

const BANNER_KEYS = ['className', 'verdict', 'signatureStatus', 'fingerprint'] as const;

function parseBanner(value: unknown): ReportBanner {
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(2, 'report payload banner is invalid');
  rejectUnknown(doc, BANNER_KEYS, 'report payload banner');
  if (
    doc.className !== 'verified' &&
    doc.className !== 'failed' &&
    doc.className !== 'unsigned' &&
    doc.className !== 'untrusted'
  ) {
    throw new ReportHtmlError(2, 'report payload banner class is invalid');
  }
  if (doc.verdict !== 'VERIFIED' && doc.verdict !== 'FAILED' && doc.verdict !== 'UNSIGNED' && doc.verdict !== 'UNTRUSTED') {
    throw new ReportHtmlError(2, 'report payload banner verdict is invalid');
  }
  if (typeof doc.signatureStatus !== 'string' || !doc.signatureStatus) {
    throw new ReportHtmlError(2, 'report payload banner signatureStatus is invalid');
  }
  if (typeof doc.fingerprint !== 'string' || !doc.fingerprint) {
    throw new ReportHtmlError(2, 'report payload banner fingerprint is invalid');
  }
  return {
    className: doc.className,
    verdict: doc.verdict,
    signatureStatus: doc.signatureStatus,
    fingerprint: doc.fingerprint,
  };
}

function parseUnredacted(value: unknown): ReportUnredacted | null {
  if (value === null) return null;
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(2, 'report payload unredacted is invalid');
  rejectUnknown(doc, ['marker', 'detail'], 'report payload unredacted');
  if (doc.marker !== 'UNREDACTED') throw new ReportHtmlError(2, 'report payload unredacted marker is invalid');
  if (typeof doc.detail !== 'string' || !doc.detail) {
    throw new ReportHtmlError(2, 'report payload unredacted detail is invalid');
  }
  return { marker: 'UNREDACTED', detail: doc.detail };
}

function parseRenderVersion(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > Number.MAX_SAFE_INTEGER) {
    throw new ReportHtmlError(2, 'report payload renderVersion is invalid');
  }
  return value;
}

function parsePayload(value: unknown): ReportPayload {
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(2, 'report payload must be an object');
  rejectUnknown(doc, PAYLOAD_KEYS, 'report payload');
  if (doc.kind !== REPORT_PAYLOAD_KIND) {
    throw new ReportHtmlError(2, 'report payload kind is not agent-receipt-report');
  }
  if (doc.version !== REPORT_PAYLOAD_VERSION) {
    throw new ReportHtmlError(2, 'unsupported report payload version');
  }
  const renderVersion = parseRenderVersion(doc.renderVersion);
  if (typeof doc.cliVersion !== 'string' || !doc.cliVersion) {
    throw new ReportHtmlError(2, 'report payload cliVersion is missing');
  }
  if (typeof doc.generatedAt !== 'string' || !doc.generatedAt) {
    throw new ReportHtmlError(2, 'report payload generatedAt is missing');
  }
  if (doc.subject !== 'receipt' && doc.subject !== 'session') {
    throw new ReportHtmlError(2, 'report payload subject is invalid');
  }
  if (doc.session !== null && typeof doc.session !== 'string') {
    throw new ReportHtmlError(2, 'report payload session is invalid');
  }
  if (doc.manifestSha256 !== null && (typeof doc.manifestSha256 !== 'string' || !HEX64.test(doc.manifestSha256))) {
    throw new ReportHtmlError(2, 'report payload manifestSha256 is invalid');
  }
  if (doc.exposure !== 'redacted' && doc.exposure !== 'host' && doc.exposure !== 'unredacted') {
    throw new ReportHtmlError(2, 'report payload exposure is invalid');
  }
  if (doc.verdict !== 'VERIFIED' && doc.verdict !== 'FAILED' && doc.verdict !== 'UNSIGNED' && doc.verdict !== 'UNTRUSTED') {
    throw new ReportHtmlError(2, 'report payload verdict is invalid');
  }
  if (typeof doc.title !== 'string' || !doc.title) {
    throw new ReportHtmlError(2, 'report payload title is missing');
  }
  if (!Array.isArray(doc.verifyCommands) || doc.verifyCommands.length < 1 || doc.verifyCommands.some((c) => typeof c !== 'string' || !c)) {
    throw new ReportHtmlError(2, 'report payload verifyCommands is invalid');
  }
  if (doc.tree !== null && typeof doc.tree !== 'string') {
    throw new ReportHtmlError(2, 'report payload tree is invalid');
  }
  if (!Array.isArray(doc.receipts) || doc.receipts.length < 1) {
    throw new ReportHtmlError(2, 'report payload receipts is empty');
  }
  return {
    kind: REPORT_PAYLOAD_KIND,
    version: REPORT_PAYLOAD_VERSION,
    renderVersion,
    cliVersion: doc.cliVersion,
    generatedAt: doc.generatedAt,
    subject: doc.subject,
    session: doc.session,
    manifestSha256: doc.manifestSha256,
    exposure: doc.exposure,
    verdict: doc.verdict,
    title: doc.title,
    banner: parseBanner(doc.banner),
    unredacted: parseUnredacted(doc.unredacted),
    verifyCommands: doc.verifyCommands,
    tree: doc.tree,
    receipts: doc.receipts.map((item, index) => parseReceipt(item, index)),
  };
}

const SIG_KEYS = ['alg', 'version', 'sha256', 'fingerprint', 'signature', 'publicKey'] as const;

function parseSignatureValue(value: unknown): SignatureDocument | null {
  if (value === null) return null;
  const doc = asRecord(value);
  if (!doc) throw new ReportHtmlError(2, 'embedded report signature is malformed');
  rejectUnknown(doc, SIG_KEYS, 'embedded report signature');
  if (doc.alg !== 'ed25519' || doc.version !== 1) {
    throw new ReportHtmlError(2, 'embedded report signature is malformed');
  }
  if (typeof doc.sha256 !== 'string' || typeof doc.fingerprint !== 'string' || typeof doc.signature !== 'string' || typeof doc.publicKey !== 'string') {
    throw new ReportHtmlError(2, 'embedded report signature is malformed');
  }
  return canonicalSignature({
    alg: 'ed25519',
    version: 1,
    sha256: doc.sha256,
    fingerprint: doc.fingerprint,
    signature: doc.signature,
    publicKey: doc.publicKey,
  });
}

function assertDisplayAgrees(payload: ReportPayload, signature: SignatureDocument | null): void {
  if (payload.title !== reportTitle(payload.verdict)) {
    throw new ReportHtmlError(2, 'report title does not match the verdict');
  }
  if (payload.banner.verdict !== payload.verdict || payload.banner.className !== payload.verdict.toLowerCase()) {
    throw new ReportHtmlError(2, 'report banner does not match the verdict');
  }
  if (signature) {
    if (payload.banner.fingerprint !== signature.fingerprint) {
      throw new ReportHtmlError(2, 'report banner fingerprint does not match the signature');
    }
    if (!/^Report signature: present \((trusted|untrusted|no trust store)\)$/.test(payload.banner.signatureStatus)) {
      throw new ReportHtmlError(2, 'report signature status line is invalid');
    }
  } else if (payload.banner.fingerprint !== 'unsigned' || payload.banner.signatureStatus !== 'Report signature: absent (unsigned)') {
    throw new ReportHtmlError(2, 'unsigned report must say it is unsigned');
  }
  if (payload.exposure === 'redacted') {
    if (payload.unredacted !== null) throw new ReportHtmlError(2, 'redacted report has an UNREDACTED marker');
  } else if (!payload.unredacted) {
    throw new ReportHtmlError(2, 'report is missing the UNREDACTED marker');
  }
  if (payload.subject === 'receipt' && payload.tree !== null) {
    throw new ReportHtmlError(2, 'receipt report tree must be null');
  }
  if (payload.subject === 'session' && typeof payload.tree !== 'string') {
    throw new ReportHtmlError(2, 'session report tree is missing');
  }
  for (const receipt of payload.receipts) {
    const pills = reportPills(receipt);
    if (
      receipt.pills.verified !== pills.verified ||
      receipt.pills.signature !== pills.signature ||
      receipt.pills.trust !== pills.trust
    ) {
      throw new ReportHtmlError(2, `report payload pills do not match receipt ${receipt.id}`);
    }
  }
  const broken = payload.receipts.some((receipt) => !receipt.verified || receipt.signature === 'invalid');
  if (broken && payload.verdict !== 'FAILED') {
    throw new ReportHtmlError(2, 'report verdict does not match receipt verification');
  }
}

/**
 * Find exactly one payload block and exactly one signature block, outside
 * comments. Zero, duplicates, a block inside a comment, or a payload that
 * is present but does not match the schema is tampering (exit 2).
 * The signature block is JSON `null` on an unsigned report.
 */
export function parseReportHtml(html: string): ExtractedReport {
  const blocks = scanReportBlocks(html);
  const payloadRaw = requireOne(blocks, REPORT_SCRIPT_ID, 'payload');
  const sigRaw = requireOne(blocks, REPORT_SIG_SCRIPT_ID, 'signature');
  let payloadJson: unknown;
  try {
    payloadJson = JSON.parse(payloadRaw);
  } catch {
    throw new ReportHtmlError(2, 'embedded report payload is malformed JSON');
  }
  const payload = parsePayload(payloadJson);
  let sigJson: unknown;
  try {
    sigJson = JSON.parse(sigRaw);
  } catch {
    throw new ReportHtmlError(2, 'embedded report signature is malformed JSON');
  }
  const signature = parseSignatureValue(sigJson);
  assertDisplayAgrees(payload, signature);
  const canonical = canonicalReportJson(payload);
  return { payload, signature, canonical, payloadHash: sha256Hex(canonical) };
}
