import { createHash } from 'node:crypto';

const HASH_MARKER = '<!-- agent-receipt-sha256:';
const HASH_END = ' -->';

/**
 * A CommonMark fence at column 0, or indented by at most three spaces.
 * The info string is `rest`. A closing fence has an empty info string.
 */
function fenceAt(line: string): { ch: string; len: number; rest: string } | null {
  const match = /^ {0,3}(```+|~~~+)(.*)$/.exec(line);
  if (!match) return null;
  return { ch: match[1][0], len: match[1].length, rest: match[2] };
}

/**
 * Index of the first `## Integrity` heading or hash-marker line that is
 * not inside an open fence. A fenced copy of the marker stays in the body.
 * Returns `lines.length` when the body has no footer.
 */
export function integrityCutIndex(lines: string[]): number {
  let fence: { ch: string; len: number } | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, '');
    const marker = fenceAt(line);
    if (marker) {
      if (!fence) {
        fence = { ch: marker.ch, len: marker.len };
        continue;
      }
      if (fence.ch === marker.ch && marker.len >= fence.len && marker.rest.trim() === '') {
        fence = null;
      }
      continue;
    }
    if (fence) continue;
    if (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256')) return i;
  }
  return lines.length;
}

/**
 * Canonical body used for hashing: everything before the Integrity section
 * (or any unfenced line containing the hash marker). A marker inside a
 * fence stays in the body. Trailing blank lines are normalized.
 *
 * By design, anything after `## Integrity` / the hash marker is ignored by
 * verify — appends after the Integrity footer do not affect the hash.
 */
export function canonicalBody(markdown: string): string {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const out = lines.slice(0, integrityCutIndex(lines));
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
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const tail = lines.slice(integrityCutIndex(lines)).join('\n');
  const idx = tail.indexOf(HASH_MARKER);
  if (idx < 0) return null;
  const start = idx + HASH_MARKER.length;
  const end = tail.indexOf(HASH_END, start);
  if (end < 0) return null;
  return tail.slice(start, end).trim();
}

/**
 * True when the file has non-empty content after the Integrity section that
 * is not part of the standard hash footer. Such appends are ignored by
 * canonicalBody / verify by design.
 */
export function hasTrailingAfterIntegrity(markdown: string): boolean {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const start = integrityCutIndex(lines);
  if (start >= lines.length) return false;
  let i = start;

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
