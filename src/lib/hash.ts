import { createHash } from 'node:crypto';

const HASH_MARKER = '<!-- agent-receipt-sha256:';
const HASH_END = ' -->';

export function sha256Hex(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

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
 * Column-0 closing fence. A unified-diff context line is prefixed with a
 * space, so ` ``` ` or ` ~~~ ` inside a diff must not close the writer's fence.
 */
function isWriterDiffClose(line: string, open: { ch: string; len: number }): boolean {
  const match = /^(```+|~~~+)(.*)$/.exec(line);
  if (!match) return false;
  return match[1][0] === open.ch && match[1].length >= open.len && match[2].trim() === '';
}

/**
 * v1.0.42 cut: the first integrity line, fences ignored. A marker inside a
 * diff or a code fence ended the body, and `appendHashFooter` dropped the rest.
 */
function legacyCutIndex(lines: string[]): number {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256')) return i;
  }
  return lines.length;
}

/**
 * v1.0.43 cut. A quoted marker stays in the body while a fence is open.
 * Writer ` ```diff ` blocks skip fence tracking: diff text that shows
 * ` ``` ` or `~~~` is not a fence, and a marker inside the diff is not the footer.
 */
function modernCutIndex(lines: string[]): number {
  let fence: { ch: string; len: number } | null = null;
  let inDiff = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, '');
    if (inDiff && fence) {
      if (isWriterDiffClose(line, fence)) {
        inDiff = false;
        fence = null;
      }
      continue;
    }
    const marker = fenceAt(line);
    if (marker) {
      if (!fence) {
        fence = { ch: marker.ch, len: marker.len };
        if (marker.ch === '`' && marker.rest.trim() === 'diff') inDiff = true;
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
 * Ignorable whitespace for the integrity footer and for lines compared
 * around it. Only ASCII space, tab, CR, and LF. NBSP (U+00A0), BOM
 * (U+FEFF), ideographic space (U+3000), and line separator (U+2028)
 * are content. `String.prototype.trim` is not used here.
 */
function isIgnorableWsCode(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0d || code === 0x0a;
}

function isIgnorableWsLine(line: string): boolean {
  for (let i = 0; i < line.length; i++) {
    if (!isIgnorableWsCode(line.charCodeAt(i))) return false;
  }
  return true;
}

function stripIgnorableTrailingWs(line: string): string {
  let end = line.length;
  while (end > 0 && isIgnorableWsCode(line.charCodeAt(end - 1))) end -= 1;
  return end === line.length ? line : line.slice(0, end);
}

function stripIgnorableEdgeWs(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && isIgnorableWsCode(text.charCodeAt(start))) start += 1;
  while (end > start && isIgnorableWsCode(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

function bodyAt(lines: string[], cut: number): string {
  const out = lines.slice(0, cut);
  while (out.length > 0 && isIgnorableWsLine(out[out.length - 1])) out.pop();
  return out.join('\n') + '\n';
}

function embeddedHashAfter(lines: string[], cut: number): string | null {
  const tail = lines.slice(cut).join('\n');
  const idx = tail.indexOf(HASH_MARKER);
  if (idx < 0) return null;
  const start = idx + HASH_MARKER.length;
  const end = tail.indexOf(HASH_END, start);
  if (end < 0) return null;
  return stripIgnorableEdgeWs(tail.slice(start, end));
}

/**
 * Index of the integrity footer. Returns `lines.length` when the body has none.
 *
 * The receipt has no field that says which cut sealed it. v1.0.42 cut at the
 * first marker even inside a fence, which can leave ` ```diff ` or ` ``` `
 * unclosed above the real footer. When that older body still hashes to the
 * embedded marker, keep it. Otherwise use the fence-aware cut.
 */
export function integrityCutIndex(lines: string[]): number {
  const modern = modernCutIndex(lines);
  const legacy = legacyCutIndex(lines);
  if (legacy === modern) return legacy;
  const embedded = embeddedHashAfter(lines, legacy);
  if (embedded && embedded === sha256Hex(bodyAt(lines, legacy))) return legacy;
  return modern;
}

/**
 * Canonical body used for hashing: everything before the Integrity section
 * (or any unfenced line containing the hash marker). A marker inside a
 * fence stays in the body. Trailing blank lines are normalized.
 *
 * The hash covers this body only. Bytes after the Integrity footer are not
 * hashed. `verify` fails closed unless those bytes are the footer
 * `appendHashFooter` writes. Only ASCII space, tab, CR, and LF are
 * ignorable trailing whitespace.
 */
export function canonicalBody(markdown: string): string {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  return bodyAt(lines, integrityCutIndex(lines));
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
  return embeddedHashAfter(lines, integrityCutIndex(lines));
}

const FOOTER_HEADING = '## Integrity';
/** Writer marker line: 64 lowercase hex, no extra text. */
const FOOTER_MARKER = /^<!-- agent-receipt-sha256:([0-9a-f]{64}) -->$/;

/**
 * True when bytes after the integrity cut are not the footer
 * `appendHashFooter` writes.
 *
 * The only accepted shape, after the cut, is one heading line, one
 * ignorable-whitespace line, one marker line with 64 lowercase hex, one
 * ignorable-whitespace line, and one prose line carrying that same hash.
 * Trailing ignorable-whitespace lines after that prose still pass. A second
 * footer, an extra line, a short or non-hex marker, a prose hash that
 * differs from the marker, or any other text fails. NBSP, BOM, U+3000, and
 * U+2028 are not ignorable.
 *
 * The hash itself still ignores those bytes, so a matching body with a
 * trailing note is a verify failure, not a hash mismatch.
 */
export function hasTrailingAfterIntegrity(markdown: string): boolean {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const start = integrityCutIndex(lines);
  if (start >= lines.length) return false;

  let end = lines.length;
  while (end > start && isIgnorableWsLine(lines[end - 1])) end -= 1;
  // heading, blank, marker, blank, prose
  if (end - start !== 5) return true;

  const heading = stripIgnorableTrailingWs(lines[start]);
  const marker = stripIgnorableTrailingWs(lines[start + 2]);
  const prose = stripIgnorableTrailingWs(lines[start + 4]);
  if (heading !== FOOTER_HEADING) return true;
  if (!isIgnorableWsLine(lines[start + 1]) || !isIgnorableWsLine(lines[start + 3])) return true;
  const matched = FOOTER_MARKER.exec(marker);
  if (!matched) return true;
  if (prose !== `SHA-256 of canonical body: \`${matched[1]}\``) return true;
  return false;
}

export function verifyMarkdown(markdown: string): {
  ok: boolean;
  expected: string | null;
  actual: string;
  reason: string;
  /** Content after Integrity exists. The hash ignores it. `verify` fails closed. */
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
