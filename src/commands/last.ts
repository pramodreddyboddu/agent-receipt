import { readFileSync } from 'node:fs';
import { resolveReceiptPath } from './show.js';
import { extractEmbeddedHash } from '../lib/hash.js';
import { color } from '../lib/color.js';
import { VERSION } from '../lib/version.js';
import { extractTldr } from '../lib/receipt.js';
import { redactSecretsInText } from '../lib/redact.js';
import { failedOnFromIndex, findIndexEntry } from '../lib/receipt-index.js';
import { glanceRowFailed } from './history.js';
import { parseReceiptGlance } from './compare.js';

/**
 * Display only. `last` repeats secret-shaped text that was only in a
 * commit message or `--message`. Mask the same patterns as history, show,
 * and compare. The stored receipt and index stay as captured.
 */
function redactLastJson(value: unknown): unknown {
  if (typeof value === 'string') return redactSecretsInText(value);
  if (Array.isArray(value)) return value.map(redactLastJson);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      out[key] = redactLastJson(inner);
    }
    return out;
  }
  return value;
}

export interface LastOptions {
  /** Print only the absolute path (for scripting). */
  pathOnly?: boolean;
  /**
   * One JSON object on stdout (`command: "last"`).
   * When set with `--path`, this wins.
   */
  json?: boolean;
}

function textOrNull(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

/**
 * Show the most recent receipt path + a short preview.
 * Distinct from `show`, which dumps the full Markdown body without the banner.
 */
export function cmdLast(cwd: string, opts: LastOptions = {}): string {
  const path = resolveReceiptPath(cwd);
  if (opts.json) {
    const text = readFileSync(path, 'utf8');
    const glance = parseReceiptGlance(path);
    const entry = findIndexEntry(cwd, path);
    const agent =
      entry && entry.agent !== undefined
        ? textOrNull(entry.agent)
        : textOrNull(glance.agent);
    const failedOn = entry ? failedOnFromIndex(entry) : glanceRowFailed(glance.risks);
    const uncommitted =
      entry && typeof entry.uncommitted === 'boolean'
        ? entry.uncommitted
        : glance.uncommitted === true;
    const sha256 =
      entry && typeof entry.sha256 === 'string' && entry.sha256
        ? entry.sha256
        : glance.sha ?? null;
    const message = entry
      ? textOrNull(entry.message) ?? textOrNull(glance.message)
      : textOrNull(glance.message);
    const timestamp = entry?.timestamp || glance.timestamp || null;
    console.log(
      JSON.stringify(redactLastJson({
        ok: true,
        command: 'last',
        version: VERSION,
        path,
        sha256,
        agent,
        message,
        timestamp,
        failedOn,
        uncommitted,
        tldr: extractTldr(text),
      })),
    );
    return path;
  }
  if (opts.pathOnly) {
    console.log(path);
    return path;
  }

  const text = readFileSync(path, 'utf8');
  const hash = extractEmbeddedHash(text);

  console.log(color.bold(`latest: ${redactSecretsInText(path)}`));
  if (hash) console.log(color.dim(`integrity: sha256:${hash.slice(0, 16)}…`));
  console.log('');

  // Print a useful preview: title + summary/session lines through first blank after Session.
  // Mask the joined preview so a commit message secret is not printed. The file stays raw.
  const previewLines: string[] = [];
  let inBody = false;
  for (const line of text.split('\n')) {
    if (line.startsWith('# Agent Receipt')) {
      previewLines.push(line);
      inBody = true;
      continue;
    }
    if (!inBody) continue;
    if (line.startsWith('## Files changed') || line.startsWith('## Diff')) break;
    previewLines.push(line);
    if (previewLines.length > 50) break;
  }
  console.log(redactSecretsInText(previewLines.join('\n')).trimEnd());
  console.log('');
  console.log(color.dim('Tip: agent-receipt history # list recent receipts'));
  console.log(color.dim('     agent-receipt show    # full Markdown'));
  console.log(color.dim('     agent-receipt verify  # integrity check'));
  console.log(color.dim('     agent-receipt prove   # prove-this-run (not a signature)'));
  return path;
}
