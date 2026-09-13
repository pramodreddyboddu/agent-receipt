import { createHash } from 'node:crypto';

const HASH_MARKER = '<!-- agent-receipt-sha256:';
const HASH_END = ' -->';

/**
 * Canonical body used for hashing: everything before the Integrity section
 * (or any line containing the hash marker). Trailing blank lines normalized.
 *
 * By design, anything after `## Integrity` / the hash marker is ignored by
 * verify — appends after the Integrity footer do not affect the hash.
 */
export function canonicalBody(markdown: string): string {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const out: string[] = [];
  for (const line of lines) {
    if (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256')) {
      break;
    }
    out.push(line);
  }
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  return out.join('\n') + '\n';
}

export function sha256Hex(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export function appendHashFooter(markdown: string): string {
  const body = canonicalBody(markdown);
  const hash = sha256Hex(body);
  return (
    body +
    '\n## Integrity\n\n' +
    `${HASH_MARKER}${hash}${HASH_END}\n` +
    `\nSHA-256 of canonical body: \`${hash}\`\n`
  );
}

export function extractEmbeddedHash(markdown: string): string | null {
  const idx = markdown.indexOf(HASH_MARKER);
  if (idx < 0) return null;
  const start = idx + HASH_MARKER.length;
  const end = markdown.indexOf(HASH_END, start);
  if (end < 0) return null;
  return markdown.slice(start, end).trim();
}

/**
 * True when the file has non-empty content after the Integrity section that
 * is not part of the standard hash footer. Such appends are ignored by
 * canonicalBody / verify by design.
 */
export function hasTrailingAfterIntegrity(markdown: string): boolean {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  let i = 0;
  while (i < lines.length) {
    if (
      lines[i].startsWith('## Integrity') ||
      lines[i].includes('agent-receipt-sha256')
    ) {
      break;
    }
    i++;
  }
  if (i >= lines.length) return false;

  // Skip the Integrity heading, blank lines, hash marker, and SHA-256 prose.
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') continue;
    if (line.startsWith('## Integrity')) continue;
    if (line.includes('agent-receipt-sha256')) continue;
    if (/^SHA-256 of canonical body:/.test(line)) continue;
    return true;
  }
  return false;
}

export function verifyMarkdown(markdown: string): {
  ok: boolean;
  expected: string | null;
  actual: string;
  reason: string;
  /** Content after Integrity exists and is ignored by the hash (by design). */
  trailingIgnored?: boolean;
} {
  const expected = extractEmbeddedHash(markdown);
  const actual = sha256Hex(canonicalBody(markdown));
  const trailingIgnored = hasTrailingAfterIntegrity(markdown);
  if (!expected) {
    return {
      ok: false,
      expected: null,
      actual,
      reason: 'No embedded agent-receipt-sha256 marker found',
      trailingIgnored,
    };
  }
  if (expected !== actual) {
    return {
      ok: false,
      expected,
      actual,
      reason: 'Hash mismatch — receipt may have been tampered with',
      trailingIgnored,
    };
  }
  return { ok: true, expected, actual, reason: 'OK', trailingIgnored };
}
