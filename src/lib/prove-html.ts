/**
 * `prove --html`: one self-contained, offline HTML verification report.
 *
 * - Inline CSS only. No scripts, no links, no images, no fonts, no network.
 * - A strict Content-Security-Policy meta tag (`default-src 'none'`).
 * - Every receipt-derived string is redacted with the same secret rules as
 *   `share` / `export --redact`, then HTML-escaped.
 * - URLs in receipt text are defanged (`https[:]//`) so nothing in the
 *   report is clickable or fetchable.
 * - Rendered from the same ProveReport object as stdout / `--json` / `--page`.
 *   It never re-verifies on its own.
 */

import { escapeHtml } from './html.js';
import { isHighSecretRiskCode, redactSecretsInText } from './redact.js';
import type { SignatureStatus } from './sign.js';
import type { GateRisk } from './gate.js';

export interface ProveHtmlAudit {
  present: boolean;
  chainOk: boolean | null;
  events: number;
  matched: boolean;
  reason: string | null;
}

/** Subset of ProveReport the HTML needs (kept structural to avoid a cycle). */
export interface ProveHtmlReport {
  exitCode: number;
  version: string;
  verified: boolean | null;
  trailingIgnored: boolean | null;
  failedOn: boolean;
  failOn: string | null;
  redacted: boolean;
  uncommitted: boolean | null;
  sha256: string | null;
  tldr: string | null;
  agent: string | null;
  risk: GateRisk | null;
  audit: ProveHtmlAudit;
  signature: SignatureStatus;
  reason: string | null;
}

/** Receipt summary lines parsed from the receipt body (see parseReceiptGlance). */
export interface ProveHtmlSummary {
  /** Display path (relative to cwd when possible). */
  displayPath: string;
  timestamp?: string;
  branch?: string;
  head?: string;
  message?: string;
  fileCount?: number;
  insertions?: number;
  deletions?: number;
  files: string[];
  risks: Array<{ severity: string; code: string; detail: string }>;
}

export interface ProveHtmlOptions {
  /** ISO timestamp for "generated at". Defaults to now. */
  generatedAt?: string;
}

/** Max file rows rendered; the rest are summarized as "+N more". */
export const PROVE_HTML_MAX_FILES = 50;
/** Max risk rows rendered. */
export const PROVE_HTML_MAX_RISKS = 50;

export const PROVE_HTML_DISCLAIMER =
  'The hash and the audit link are tamper-evident, not a cryptographic signature. The signature row reports a local Ed25519 sidecar when one is present. This is not a certificate authority and not access control. This HTML report is not itself signed; re-run `agent-receipt prove` to re-check.';

/** Defang URL schemes so no text can be read as a fetchable asset or link. */
export function defangUrls(text: string): string {
  return text.replace(/\b(https?|ftp|wss?|file)(:)(\/\/)/gi, '$1[:]$3');
}

/** Redact secrets, defang URLs, then escape. Use for every receipt-derived string. */
export function safeText(value: string | null | undefined, fallback = '(none)'): string {
  if (value === null || value === undefined || value === '') return escapeHtml(fallback);
  return escapeHtml(defangUrls(redactSecretsInText(String(value))));
}

function tri(value: boolean | null): string {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return 'unknown';
}

function statusCell(state: 'pass' | 'fail' | 'info', label: string): string {
  return `<span class="pill ${state}">${escapeHtml(label)}</span>`;
}

function row(label: string, valueHtml: string): string {
  return `<tr><th scope="row">${escapeHtml(label)}</th><td>${valueHtml}</td></tr>`;
}

function hashRow(report: ProveHtmlReport): string {
  if (report.verified === true) {
    const extra = report.trailingIgnored ? ' (trailing content after footer ignored)' : '';
    return statusCell('pass', 'PASS') + ` embedded SHA-256 matches the body${escapeHtml(extra)}`;
  }
  if (report.verified === false) {
    return statusCell('fail', 'FAIL') + ' embedded SHA-256 does not match (tampered or edited)';
  }
  return statusCell('info', 'UNKNOWN') + ' hash not checked';
}

function auditRow(audit: ProveHtmlAudit): string {
  if (!audit.present) {
    return statusCell('info', 'ABSENT') + ' no audit log (does not fail prove)';
  }
  const events = `${audit.events} event${audit.events === 1 ? '' : 's'}`;
  const matched = audit.matched ? 'receipt linked in audit log' : 'receipt not found in audit log';
  if (audit.chainOk) {
    return statusCell('pass', 'PASS') + ` hash chain intact, ${escapeHtml(events)}, ${escapeHtml(matched)}`;
  }
  const why = audit.reason ? `: ${safeText(audit.reason)}` : '';
  return statusCell('fail', 'FAIL') + ` hash chain broken${why} (${escapeHtml(events)})`;
}

function signatureRow(sig: SignatureStatus): string {
  if (!sig.present) {
    return statusCell('info', 'UNSIGNED') + ' no Ed25519 sidecar (does not fail prove; use <code>verify --require-sig</code> to require one)';
  }
  const fp = sig.fingerprint ? ` <code>${escapeHtml(sig.fingerprint)}</code>` : '';
  if (sig.ok === true) {
    let trust = '';
    if (sig.trusted === true) trust = ' ' + statusCell('pass', 'TRUSTED');
    else if (sig.trusted === false) trust = ' ' + statusCell('fail', 'UNTRUSTED');
    else trust = ' ' + statusCell('info', 'NO TRUST STORE');
    return statusCell('pass', 'VALID') + ` Ed25519 signature${fp}${trust}`;
  }
  const why = sig.reason ? `: ${safeText(sig.reason)}` : '';
  return statusCell('fail', 'INVALID') + ` Ed25519 signature${fp}${why}`;
}

function riskRow(risk: GateRisk | null): string {
  if (!risk) return '(none)';
  if (!risk.total && !risk.maxSeverity) return 'none';
  const max = risk.maxSeverity ?? 'none';
  return escapeHtml(
    `${risk.total} (high ${risk.high}, medium ${risk.medium}, low ${risk.low}), max ${max}`,
  );
}

function filesTable(summary: ProveHtmlSummary): string {
  if (!summary.files.length) return '<p class="muted">No file rows in the receipt.</p>';
  const shown = summary.files.slice(0, PROVE_HTML_MAX_FILES);
  const items = shown.map((f) => `<li><code>${safeText(f)}</code></li>`).join('');
  const more = summary.files.length - shown.length;
  const tail = more > 0 ? `<li class="muted">+${more} more</li>` : '';
  return `<ul class="files">${items}${tail}</ul>`;
}

function risksTable(summary: ProveHtmlSummary): string {
  if (!summary.risks.length) return '<p class="muted">No risk findings.</p>';
  const shown = summary.risks.slice(0, PROVE_HTML_MAX_RISKS);
  const rows = shown
    .map((r) => {
      const detail = isHighSecretRiskCode(r.code) ? '[REDACTED]' : safeText(r.detail);
      return `<tr><td>${safeText(r.severity)}</td><td><code>${safeText(r.code)}</code></td><td>${detail}</td></tr>`;
    })
    .join('');
  const more = summary.risks.length - shown.length;
  const tail = more > 0 ? `<tr><td colspan="3" class="muted">+${more} more</td></tr>` : '';
  return `<table class="grid"><thead><tr><th>Severity</th><th>Code</th><th>Detail</th></tr></thead><tbody>${rows}${tail}</tbody></table>`;
}

const STYLE = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:24px;max-width:960px;margin:0 auto;color:#1f2328;background:#fff}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:16px;margin:24px 0 8px;border-bottom:1px solid #d0d7de;padding-bottom:4px}
code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f6f8fa;padding:1px 4px;border-radius:4px;word-break:break-all}
.banner{border-radius:8px;padding:16px 20px;margin:0 0 16px;color:#fff}
.banner.pass{background:#1a7f37}
.banner.fail{background:#cf222e}
.banner .verdict{font-size:28px;font-weight:700;letter-spacing:1px}
.banner .why{margin-top:6px;word-break:break-word}
table.kv,table.grid{border-collapse:collapse;width:100%}
table.kv th{text-align:left;vertical-align:top;width:180px;padding:6px 8px;color:#57606a;font-weight:600}
table.kv td,table.grid td,table.grid th{padding:6px 8px;border-top:1px solid #eaeef2;vertical-align:top;text-align:left}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:1px 8px;border-radius:10px;margin-right:4px}
.pill.pass{background:#dafbe1;color:#116329}
.pill.fail{background:#ffebe9;color:#a40e26}
.pill.info{background:#eaeef2;color:#424a53}
.muted{color:#57606a}
ul.files{margin:0;padding-left:20px}
footer{margin-top:32px;font-size:13px;color:#57606a;border-top:1px solid #d0d7de;padding-top:12px}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}code{background:#161b22}h2,footer{border-color:#30363d}table.kv td,table.grid td,table.grid th{border-color:#21262d}.muted,table.kv th,footer{color:#8b949e}}
@media print{.banner{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
`.trim();

/** Render the complete HTML document. Pure: no I/O. */
export function renderProveHtml(
  report: ProveHtmlReport,
  summary: ProveHtmlSummary,
  opts: ProveHtmlOptions = {},
): string {
  const pass = report.exitCode === 0;
  const verdict = pass ? 'PASS' : 'FAIL';
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const why = report.reason
    ? `<div class="why">${safeText(report.reason)}</div>`
    : '<div class="why">Hash matches, audit chain intact or absent, and any signature is valid.</div>';

  const lines = summary.insertions !== undefined && summary.deletions !== undefined
    ? `+${summary.insertions} / −${summary.deletions}`
    : undefined;

  const summaryRows = [
    row('Receipt', `<code>${safeText(summary.displayPath)}</code>`),
    row('Agent', safeText(report.agent)),
    row('Timestamp', safeText(summary.timestamp)),
    row('Branch', safeText(summary.branch)),
    row('HEAD', summary.head ? `<code>${safeText(summary.head)}</code>` : '(none)'),
    row('Message', safeText(summary.message)),
    row('TL;DR', safeText(report.tldr)),
    row('Files', summary.fileCount !== undefined ? escapeHtml(String(summary.fileCount)) : '(none)'),
    row('Lines', safeText(lines)),
    row('Risk', riskRow(report.risk)),
    row('Uncommitted', escapeHtml(tri(report.uncommitted))),
    row('Failed gate', escapeHtml(report.failedOn ? 'yes' : 'no')),
  ];
  if (report.failOn) summaryRows.push(row('--fail-on', safeText(report.failOn)));

  const verifyRows = [
    row('Verdict', statusCell(pass ? 'pass' : 'fail', verdict)),
    row('Hash', hashRow(report)),
    row('SHA-256', report.sha256 ? `<code>${escapeHtml(report.sha256)}</code>` : '(none)'),
    row('Audit chain', auditRow(report.audit)),
    row('Signature', signatureRow(report.signature)),
    row(
      'Redaction',
      statusCell('pass', 'ON') +
        ' secrets masked in this report' +
        (report.redacted ? '; receipt body was already redacted at capture' : ''),
    ),
  ];

  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    `<meta name="generator" content="agent-receipt ${escapeHtml(report.version)}">`,
    `<title>Agent Receipt — Prove ${verdict}</title>`,
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    `<div class="banner ${pass ? 'pass' : 'fail'}" role="status" data-verdict="${verdict}">`,
    `<div class="verdict">${verdict}</div>`,
    `<div>agent-receipt prove — ${pass ? 'receipt verified' : 'verification failed'}</div>`,
    why,
    '</div>',
    '<h1>Agent Receipt — Verification report</h1>',
    `<p class="muted">Generated ${escapeHtml(generatedAt)} by agent-receipt ${escapeHtml(report.version)}. Offline, self-contained, redacted.</p>`,
    '<h2>Verification</h2>',
    `<table class="kv"><tbody>${verifyRows.join('')}</tbody></table>`,
    '<h2>Receipt summary</h2>',
    `<table class="kv"><tbody>${summaryRows.join('')}</tbody></table>`,
    '<h2>Files changed</h2>',
    filesTable(summary),
    '<h2>Risk findings</h2>',
    risksTable(summary),
    `<footer><p>${escapeHtml(PROVE_HTML_DISCLAIMER)}</p></footer>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}
