import { createHash } from 'node:crypto';

const HASH_MARKER = '<!-- agent-receipt-sha256:';
const HASH_END = ' -->';

/**
 * Canonical body used for hashing: everything before the Integrity section
 * (or any line containing the hash marker). Trailing blank lines normalized.
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

export function verifyMarkdown(markdown: string): {
  ok: boolean;
  expected: string | null;
  actual: string;
  reason: string;
} {
  const expected = extractEmbeddedHash(markdown);
  const actual = sha256Hex(canonicalBody(markdown));
  if (!expected) {
    return {
      ok: false,
      expected: null,
      actual,
      reason: 'No embedded agent-receipt-sha256 marker found',
    };
  }
  if (expected !== actual) {
    return {
      ok: false,
      expected,
      actual,
      reason: 'Hash mismatch — receipt may have been tampered with',
    };
  }
  return { ok: true, expected, actual, reason: 'OK' };
}
