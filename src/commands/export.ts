import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { resolveReceiptPath } from './show.js';
import { markdownToHtml } from '../lib/html.js';
import { prepareRedactedBody } from '../lib/redact.js';
import { appendHashFooter, verifyMarkdown } from '../lib/hash.js';
import { recordAuditEvent } from '../lib/audit.js';
import { color } from '../lib/color.js';
import { handoffMarkdownSignature } from '../lib/sign.js';

export interface ExportOptions {
  /** Output path (.html or .md). Default: sibling .html next to the receipt. */
  out?: string;
  /** Mask high/secret findings before writing. */
  redact?: boolean;
  /** Force markdown output instead of HTML. */
  format?: 'html' | 'markdown' | 'md';
  /** Skip human stdout (share / JSON gate print their own summary). */
  quiet?: boolean;
  /**
   * Append an `export` audit line. Default true.
   * Share passes false — it records one `share` event for the handoff.
   */
  audit?: boolean;
}

export interface ExportResult {
  path: string;
  source: string;
  format: 'html' | 'markdown';
  redacted: boolean;
  /** Markdown body that was written, or rendered into HTML. */
  markdown: string;
  /** Sidecar copied or re-signed beside a Markdown export. Null for HTML. */
  sigPath: string | null;
  /** Tip when a rewritten Markdown export was left unsigned. */
  signatureTip: string | null;
}

function agentLabel(markdown: string): string | null {
  const m = markdown.match(/^- \*\*Agent\*\*:\s*(.+)$/m);
  const agent = m?.[1]?.trim();
  return agent || null;
}

function defaultOutPath(source: string, format: 'html' | 'markdown'): string {
  if (format === 'html') {
    return source.replace(/\.md$/i, '') + '.html';
  }
  return source.replace(/\.md$/i, '') + '.redacted.md';
}

/**
 * Export a receipt (default: latest) as self-contained HTML, or redacted Markdown.
 * `html` is an alias that always writes HTML.
 */
export function cmdExport(
  cwd: string,
  pathArg: string | undefined,
  opts: ExportOptions = {},
): ExportResult {
  const source = resolveReceiptPath(cwd, pathArg);
  const original = readFileSync(source, 'utf8');
  const sourceSha256 = verifyMarkdown(original).actual;
  let markdown = original;
  const agent = agentLabel(markdown);
  const redacted = Boolean(opts.redact);

  if (redacted) {
    markdown = appendHashFooter(prepareRedactedBody(markdown));
  }

  const fmtRaw = (opts.format || 'html').toLowerCase();
  const format: 'html' | 'markdown' =
    fmtRaw === 'md' || fmtRaw === 'markdown' ? 'markdown' : 'html';

  let outPath: string;
  if (opts.out) {
    outPath = resolve(cwd, opts.out);
  } else {
    outPath = defaultOutPath(source, format);
    // If redacting to markdown without --out and source would collide, add suffix
    if (format === 'markdown' && !opts.redact) {
      outPath = source.replace(/\.md$/i, '') + '.export.md';
    }
  }
  mkdirSync(dirname(outPath), { recursive: true });

  const log = (line: string) => {
    if (!opts.quiet) console.log(line);
  };

  if (format === 'html') {
    const html = markdownToHtml(markdown, {
      title: `Agent Receipt — ${basename(source)}`,
      redacted,
    });
    writeFileSync(outPath, html, 'utf8');
  } else {
    writeFileSync(outPath, markdown, 'utf8');
  }

  const check = verifyMarkdown(markdown);
  const integrityFailed = format === 'markdown' && !check.ok;
  if (opts.audit !== false) {
    recordAuditEvent(cwd, {
      event: 'export',
      path: outPath,
      sha256: check.actual,
      agent,
      redacted,
      verified: check.ok,
      failedOn: false,
      exitCode: integrityFailed ? 1 : 0,
    });
  }
  if (integrityFailed) {
    throw new Error(`Export markdown failed integrity self-check: ${check.reason}`);
  }

  let sigPath: string | null = null;
  let signatureTip: string | null = null;
  let signatureAction: 'copied' | 'resigned' | 'unsigned' | null = null;
  if (format === 'markdown' && check.ok) {
    const handoff = handoffMarkdownSignature({
      cwd,
      sourcePath: source,
      sourceSha256,
      publishedPath: outPath,
      publishedSha256: check.actual,
    });
    sigPath = handoff.sigPath;
    signatureTip = handoff.tip;
    signatureAction = handoff.action;
  }

  log(color.green('✓') + ` Wrote ${format}: ${outPath}`);
  log(color.dim(`  source: ${source}`));
  if (redacted) {
    log(color.yellow('  ⚠ Redacted — high/secret findings masked.'));
  }
  if (signatureTip) {
    log(color.yellow(`  ${signatureTip}`));
  } else if (sigPath) {
    const how = signatureAction === 'copied' ? 'copied' : 're-signed';
    log(color.dim(`  sig: ${sigPath} (${how})`));
  }
  log(color.dim('  Open in a browser (HTML) or share the file as-is.'));
  if (format === 'html') {
    log(color.dim('  HTML is unsigned. Peers verify and sign the Markdown receipt.'));
  }

  return { path: outPath, source, format, redacted, markdown, sigPath, signatureTip };
}

/** Alias used by the `html` command. */
export function cmdHtml(
  cwd: string,
  pathArg: string | undefined,
  opts: Omit<ExportOptions, 'format'> = {},
): ExportResult {
  return cmdExport(cwd, pathArg, { ...opts, format: 'html' });
}
