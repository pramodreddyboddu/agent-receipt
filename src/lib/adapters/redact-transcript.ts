import { redactSecretsInText } from '../redact.js';

/**
 * Transcript text always goes through the shared secret patterns, then a
 * host mask. File names like `a.ts` are left alone (one dot, not a host).
 * A label with two or more dots, a URL, an email, an IPv4 address, or a
 * bare name on a short public-suffix list is replaced with `[host]`.
 */
const HOST_RE = new RegExp(
  [
    String.raw`\bhttps?:\/\/\S+`,
    String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
    String.raw`\b(?:\d{1,3}\.){3}\d{1,3}\b`,
    String.raw`\b(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}\b`,
    String.raw`\b[a-zA-Z0-9-]+\.(?:com|net|org|io|dev|internal|example)\b`,
  ].join('|'),
  'g',
);

export function redactTranscriptText(text: string): string {
  return redactSecretsInText(text).replace(HOST_RE, '[host]');
}

export function clipText(text: string, max: number): string {
  const flat = text.replace(/[\r\n\u2028\u2029\t]+/g, ' ').replace(/ {2,}/g, ' ').trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, Math.max(0, max - 1))}…`;
}
