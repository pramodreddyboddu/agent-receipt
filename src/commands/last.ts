import { readFileSync } from 'node:fs';
import { resolveReceiptPath } from './show.js';
import { extractEmbeddedHash } from '../lib/hash.js';
import { color } from '../lib/color.js';

export interface LastOptions {
  /** Print only the absolute path (for scripting). */
  pathOnly?: boolean;
}

/**
 * Show the most recent receipt path + a short preview.
 * Distinct from `show`, which dumps the full Markdown body without the banner.
 */
export function cmdLast(cwd: string, opts: LastOptions = {}): string {
  const path = resolveReceiptPath(cwd);
  if (opts.pathOnly) {
    console.log(path);
    return path;
  }

  const text = readFileSync(path, 'utf8');
  const hash = extractEmbeddedHash(text);

  console.log(color.bold(`latest: ${path}`));
  if (hash) console.log(color.dim(`integrity: sha256:${hash.slice(0, 16)}…`));
  console.log('');

  // Print a useful preview: title + summary/session lines through first blank after Session
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
    if (previewLines.length > 40) break;
  }
  console.log(previewLines.join('\n').trimEnd());
  console.log('');
  console.log(color.dim('Tip: agent-receipt show    # full Markdown'));
  console.log(color.dim('     agent-receipt verify  # integrity check'));
  return path;
}
