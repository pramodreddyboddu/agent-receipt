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

export function redactTranscriptText(text: string): string {
  return redactHighEntropyTokens(redactSecretsInText(text).replace(HOST_RE, '[host]'));
}

export function clipText(text: string, max: number): string {
  const flat = text.replace(/[\r\n\u2028\u2029\t]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, Math.max(0, max - 1))}…`;
}
