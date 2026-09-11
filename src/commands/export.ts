import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { resolveReceiptPath } from './show.js';
import { markdownToHtml } from '../lib/html.js';
import { prepareRedactedBody } from '../lib/redact.js';
import { appendHashFooter, verifyMarkdown } from '../lib/hash.js';
import { color } from '../lib/color.js';

export interface ExportOptions {
  /** Output path (.html or .md). Default: sibling .html next to the receipt. */
  out?: string;
  /** Mask high/secret findings before writing. */
  redact?: boolean;
  /** Force markdown output instead of HTML. */
  format?: 'html' | 'markdown' | 'md';
}

export interface ExportResult {
  path: string;
  source: string;
  format: 'html' | 'markdown';
  redacted: boolean;
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
  let markdown = readFileSync(source, 'utf8');
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

  if (format === 'html') {
    const html = markdownToHtml(markdown, {
      title: `Agent Receipt — ${basename(source)}`,
      redacted,
    });
    writeFileSync(outPath, html, 'utf8');
  } else {
    writeFileSync(outPath, markdown, 'utf8');
    // sanity: redacted/exported md should still verify when we re-hashed
    const v = verifyMarkdown(markdown);
    if (!v.ok) {
      throw new Error(`Export markdown failed integrity self-check: ${v.reason}`);
    }
  }

  console.log(color.green('✓') + ` Wrote ${format}: ${outPath}`);
  console.log(color.dim(`  source: ${source}`));
  if (redacted) {
    console.log(color.yellow('  ⚠ Redacted — high/secret findings masked.'));
  }
  console.log(color.dim('  Open in a browser (HTML) or share the file as-is.'));

  return { path: outPath, source, format, redacted };
}

/** Alias used by the `html` command. */
export function cmdHtml(
  cwd: string,
  pathArg: string | undefined,
  opts: Omit<ExportOptions, 'format'> = {},
): ExportResult {
  return cmdExport(cwd, pathArg, { ...opts, format: 'html' });
}
