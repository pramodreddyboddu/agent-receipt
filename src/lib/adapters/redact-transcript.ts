import { redactSecretsInText } from '../redact.js';
import { shannonEntropy } from '../risk.js';

/**
 * Transcript text always goes through the shared secret patterns, then a
 * host mask, then a high-entropy pass. File names like `a.ts` are left
 * alone (one dot, not a host). A label with two or more dots, a URL, an
 * email, an IPv4 address, or a bare name on a short public-suffix list
 * (including internal suffixes such as `.corp` and `.lan`) is replaced
 * with `[host]`.
 */
const HOST_RE = new RegExp(
  [
    String.raw`\bhttps?:\/\/\S+`,
    String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
    String.raw`\b(?:\d{1,3}\.){3}\d{1,3}\b`,
    String.raw`\b(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}\b`,
    String.raw`\b[a-zA-Z0-9-]+\.(?:com|net|org|io|dev|internal|example|corp|lan|local|intranet)\b`,
  ].join('|'),
  'g',
);

/** Same rule as the diff scanner: 32+ chars, entropy ≥ 4.2, ≥ 10 unique, not a hex digest. */
const HIGH_ENTROPY_TOKEN_RE =
  /(?<![A-Za-z0-9+/=_\-.])[A-Za-z0-9+/=_\-.]{32,}(?![A-Za-z0-9+/=_\-.])/g;
const HEX_DIGEST_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

export function redactHighEntropyTokens(text: string): string {
  return text.replace(HIGH_ENTROPY_TOKEN_RE, (token) => {
    if (HEX_DIGEST_RE.test(token)) return token;
    if (new Set(token).size < 10) return token;
    if (shannonEntropy(token) < 4.2) return token;
    return '[REDACTED]';
  });
}

/**
 * Base64 or even-length hex that decodes to printable ASCII and still
 * matches a secret pattern. Short encoded values (under 32 chars) miss the
 * high-entropy pass. Binary and ordinary words stay. Called only from
 * `redactTranscriptText`, not from the Markdown share rewrite.
 */
const ENCODED_B64_RE = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])/g;
const ENCODED_HEX_RE = /(?<![A-Za-z0-9])(?:[0-9a-fA-F]{2}){8,}(?![A-Za-z0-9])/g;

function printableAscii(text: string): boolean {
  if (text.length < 8) return false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 9 && c !== 10 && c !== 13 && (c < 32 || c > 126)) return false;
  }
  return true;
}

function encodedSecret(token: string, encoding: 'base64' | 'hex'): string | null {
  let buf: Buffer;
  try {
    buf = Buffer.from(token, encoding);
  } catch {
    return null;
  }
  if (!buf.length) return null;
  if (encoding === 'hex') {
    if (buf.toString('hex') !== token.toLowerCase()) return null;
  } else {
    const round = buf.toString('base64').replace(/=+$/, '');
    if (round !== token.replace(/=+$/, '')) return null;
  }
  const text = buf.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buf)) return null;
  if (!printableAscii(text)) return null;
  if (redactSecretsInText(text) === text) return null;
  return '[REDACTED]';
}

export function redactEncodedSecrets(text: string): string {
  const base64 = text.replace(ENCODED_B64_RE, (token) => encodedSecret(token, 'base64') ?? token);
  return base64.replace(ENCODED_HEX_RE, (token) => encodedSecret(token, 'hex') ?? token);
}

export function redactTranscriptText(text: string): string {
  const masked = redactHighEntropyTokens(redactSecretsInText(text).replace(HOST_RE, '[host]'));
  return redactEncodedSecrets(masked);
}

export function clipText(text: string, max: number): string {
  const flat = text.replace(/[\r\n\u2028\u2029\t]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, Math.max(0, max - 1))}…`;
}
