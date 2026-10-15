/**
 * Redaction helpers for safer sharing of receipts.
 * Masks high-signal secrets in Markdown/HTML bodies, then callers re-hash.
 */
import { appendHashFooter, integrityCutIndex, sha256Hex } from './hash.js';

/**
 * 12 hex chars of sha256(secret). Distinct secrets stay distinct after
 * masking. The same secret always stamps the same way. The stamp is not
 * reversible to the raw secret.
 */
export function secretMaskStamp(secret: string): string {
  return sha256Hex(secret).slice(0, 12);
}

/**
 * True for `[REDACTED]` and the stamped form `[REDACTED:<sha256-12>]`.
 * The stamp's `]` is not next to `REDACTED`, so a search for the exact
 * substring `[REDACTED]` misses it.
 */
export function containsRedactionMark(text: string): boolean {
  return /\[REDACTED(?::[0-9a-f]{12})?\]/.test(text);
}

/** True for receipt / index artifacts that may embed prior secrets. */
export function isReceiptArtifactPath(path: string): boolean {
  const n = path.replace(/\\/g, '/');
  if (/(^|\/)\.agent-receipt\//i.test(n)) return true;
  if (/(^|\/)receipt-\d{4}-\d{2}-\d{2}T[^/]*\.md$/i.test(n)) return true;
  return false;
}

/** Patterns that look like live secrets in diffs / risk detail. */
/**
 * Token prefixes sit inside MCP names (`srv_AKIA…__q`). `\b` does not match
 * after `_` or before `_`, because both are word characters. A letter/digit
 * lookaround matches there and still stops at a real word character.
 */
type SecretReplacement = string | ((match: string) => string);

const SECRET_VALUE_PATTERNS: Array<{ re: RegExp; replacement: SecretReplacement }> = [
  {
    // Stamp the full key. Two AKIA values must not collapse to one id
    // after session import merges on the masked session string.
    re: /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])/g,
    replacement: (match) => `AKIA[REDACTED:${secretMaskStamp(match)}]`,
  },
  {
    re: /(?<![A-Za-z0-9])ASIA[0-9A-Z]{16}(?![A-Za-z0-9])/g,
    replacement: (match) => `ASIA[REDACTED:${secretMaskStamp(match)}]`,
  },
  {
    // ghp_ classic, gho_ OAuth, ghu_ user-to-server, ghs_ server, ghr_ refresh
    re: /(?<![A-Za-z0-9])(gh[pousr]_)[A-Za-z0-9]{36}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])(tok_)[A-Za-z0-9_\-]{8,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,}(?![A-Za-z0-9])/g,
    replacement: 'github_pat_[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])(glpat-)[A-Za-z0-9\-_]{20,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])(npm_)[A-Za-z0-9]{36}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])(AIza)[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])(ya29\.)[0-9A-Za-z\-_]{20,}/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])((?:sk|rk)_(?:live|test)_)[0-9A-Za-z]{10,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    replacement: 'SG.[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}/g,
    replacement: 'xox[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])xox[ce]-[A-Za-z0-9-]{10,}/g,
    replacement: 'xox[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])xapp-[A-Za-z0-9-]{10,}/g,
    replacement: 'xapp-[REDACTED]',
  },
  {
    // OpenAI sk- / sk-proj-, Anthropic sk-ant- (underscore form is Stripe, above).
    re: /(?<![A-Za-z0-9])(sk-(?:proj-|ant-)?)[A-Za-z0-9_\-]{24,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(?<![A-Za-z0-9])(hf_)[A-Za-z0-9]{20,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    // Groq console keys: gsk_ + 48 alphanumeric. 20+ avoids tiny lookalikes.
    re: /(?<![A-Za-z0-9])(gsk_)[A-Za-z0-9]{20,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    // xAI / Grok API keys: xai- + ~80 alphanumeric. Hyphenated model names stay.
    re: /(?<![A-Za-z0-9])(xai-)[A-Za-z0-9]{20,}(?![A-Za-z0-9])/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(Authorization\s*:\s*Bearer\s+)([A-Za-z0-9\-._~+/=]{20,})/gi,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(https:\/\/hooks\.slack\.com\/services\/)[A-Za-z0-9+/]+(?:\/[A-Za-z0-9+/]+){1,}/g,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(AccountKey\s*=\s*)([^;"'\s]+)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    re: /(SharedAccessKey\s*=\s*)([^;"'\s]+)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    re: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    replacement: '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----',
  },
  {
    // AWS secret assignments: keep key name, mask value
    re: /(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']?)([A-Za-z0-9/+=]{20,})/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Connection / credential URLs: scheme://user:password@host (or :password@).
    // The scheme is capped at 65 characters. An unbounded `[a-z0-9+.-]*`
    // includes `.` and, with the `i` flag, eats a long `eyJ.` run before
    // it looks for `://`, which is quadratic. Real schemes are far shorter.
    re: /(?<![A-Za-z0-9])([a-z][a-z0-9+.-]{0,64}:\/\/(?:[^:@\/\s"'<>]*):)([^@\/\s"'<>]+)(@)/gi,
    replacement: '$1[REDACTED]$3',
  },
  {
    // Common DB / URI env assignments (full value — covers uncommon schemes)
    re: /((?:DATABASE[_-]?URL|DB[_-]?URL|MONGO(?:DB)?[_-]?(?:URI|URL)|REDIS[_-]?URL|MYSQL[_-]?URL|POSTGRES(?:QL)?[_-]?URL|CONNECTION[_-]?STRING|DATABASE[_-]?URI)\s*[:=]\s*["']?)([^\s"']+)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // password= / token= / secret= query or form params
    re: /([?&](?:password|passwd|pwd|secret|token|sig|signature|api[_-]?key|access[_-]?token)=)([^&\s"']+)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Generic high-entropy token assignments common in .env diffs
    re: /((?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|PASSWORD|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|ACCOUNT[_-]?KEY|SESSION[_-]?TOKEN|NPM[_-]?TOKEN)\s*[:=]\s*["']?)([^\s"'\\]{8,})/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Low-entropy SQL and assignment values (`pw='…'`, `password=…`) that the
    // entropy scanner will not catch. JSON `"password":"…"` is handled before
    // stringify, key by key, because the quote sits between the name and `:`.
    re: /(?<![A-Za-z0-9])((?:pw|pwd|pass(?:word|wd)?|secret|token|api[_-]?key)\s*[:=]\s*['"]?)([^'"\s,;)\\]{4,})/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // 1–3 character assignment values (`password="ab"`). The `{4,}` pattern
    // above already took longer values. The lookahead keeps `password=[REDACTED]`
    // from being matched again.
    re: /(?<![A-Za-z0-9])((?:pw|pwd|pass(?:word|wd)?|secret|token|api[_-]?key)\s*[:=]\s*['"]?)([^'"\s,;)\\]{1,3})(?=['"\s,;)\\]|$)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Truncated high-entropy previews from prior risk findings (e.g. "K8vQm2nXp9Lr…")
    re: /\b([A-Za-z0-9+/=_\-.]{8,})…/g,
    replacement: '[REDACTED]…',
  },
];

const ASSIGNMENT_KEY =
  /(?<![A-Za-z0-9])(?:["'](?:pw|pwd|pass(?:word|wd)?|secret|token|api[_-]?key)["']|(?:pw|pwd|pass(?:word|wd)?|secret|token|api[_-]?key))(?=\s*[:=])/gi;

const PASSPHRASE_STOPWORDS = new Set([
  'the', 'a', 'an', 'is', 'to', 'for', 'and', 'or', 'of', 'in', 'on', 'with',
  'this', 'that', 'please', 'see', 'stored', 'your', 'you', 'we', 'be', 'it',
  'as', 'at', 'by', 'from', 'are', 'was', 'if', 'not', 'do', 'use', 'using',
  'should', 'must', 'can', 'will', 'when', 'into', 'than', 'then', 'also',
  'only', 'just', 'about', 'here', 'there', 'keep',
]);

/**
 * Whole words that may stay after `[REDACTED]` as a hyphen suffix.
 * A suffix is kept only when every `-` piece is one of these words,
 * written all-lowercase or with a single leading capital (`-then`,
 * `-Then`, `-config-file`). All-caps, digits, short stopwords that are
 * not in this set (`-the`, `-a`), and any other token tail are consumed
 * with the token. `suffix` and `low` are intentionally absent so the
 * v1.0.47 / v1.0.48 leaks stay masked. A mixed tail is consumed in full,
 * so a real word is not split off the end (`-config-file` stays whole;
 * `-suffix-file` does not leave `-file`).
 */
const HYPHEN_WORD_SUFFIXES = new Set(
  `word hello file name time after before outside inside between without
  during while where which their other first second third still back well
  even most such some them very what they have been were said each make
  like year many more over under again never always often small large
  whole same next last long short high true false read write open close
  start stop left right above below local valid empty found given called
  return value string number point place change changed added removed
  updated around another because through these those would could down
  off our now new old one two way any all how why its his her she who
  him has but out get got let put too per via yes yet nor own few both
  each many much more most less ever once upon into note user host info
  list item type date case text line path code data test world still
  under above below again never small large first other which where
  while because through without between during inside around another
  before after changed change added removed read write open close
  then config`.split(/\s+/).filter(Boolean),
);

const PASSPHRASE_WORD = /^[A-Za-z][A-Za-z0-9]{2,20}$/;

/**
 * Assignment values the token patterns miss: quoted JSON (`"password":"…"`),
 * short quotes, and dictionary passphrases (`password: correct horse …`).
 * A key must be followed by `:` or `=`. Prose and words such as compass or
 * passport are left alone. Runs before the token patterns.
 */
function redactSecretAssignments(text: string): string {
  const re = new RegExp(ASSIGNMENT_KEY.source, 'gi');
  let out = '';
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const sep = /^\s*[:=]\s*/.exec(text.slice(re.lastIndex));
    if (!sep) continue;
    const valueStart = re.lastIndex + sep[0].length;
    out += text.slice(last, valueStart);
    const quote = text[valueStart];
    if (quote === '"' || quote === "'") {
      let i = valueStart + 1;
      while (i < text.length) {
        if (text[i] === '\\') {
          i += 2;
          continue;
        }
        if (text[i] === quote) break;
        i += 1;
      }
      if (i >= text.length) {
        out += `${quote}[REDACTED]`;
        last = text.length;
        break;
      }
      out += `${quote}[REDACTED]${quote}`;
      last = i + 1;
      re.lastIndex = last;
      continue;
    }
    const token = /^[^'"\s,;)\\]+/.exec(text.slice(valueStart));
    if (!token) {
      last = valueStart;
      re.lastIndex = last;
      continue;
    }
    let end = valueStart + token[0].length;
    if (PASSPHRASE_WORD.test(token[0]) && !PASSPHRASE_STOPWORDS.has(token[0].toLowerCase())) {
      let extra = 0;
      while (extra < 5) {
        const next = /^ [A-Za-z][A-Za-z0-9]{2,20}/.exec(text.slice(end));
        if (!next) break;
        const word = next[0].slice(1);
        if (PASSPHRASE_STOPWORDS.has(word.toLowerCase())) break;
        end += next[0].length;
        extra += 1;
      }
    }
    out += '[REDACTED]';
    last = end;
    re.lastIndex = last;
  }
  out += text.slice(last);
  return out;
}

/** Risk codes whose detail rows should be fully masked in findings tables. */
const HIGH_SECRET_CODES = new Set([
  'aws-access-key',
  'aws-secret-key',
  'private-key-block',
  'github-token',
  'gitlab-token',
  'google-api-key',
  'google-oauth-token',
  'stripe-secret',
  'npm-token',
  'sendgrid-token',
  'azure-account-key',
  'slack-token',
  'llm-api-key',
  'huggingface-token',
  'groq-api-key',
  'xai-api-key',
  'bearer-token',
  'high-entropy-secret',
  'env-file',
  'secret-looking-path',
]);

/** True when a risk finding's detail must be fully masked (secret-bearing codes). */
export function isHighSecretRiskCode(code: string): boolean {
  return HIGH_SECRET_CODES.has(code);
}

/**
 * Per-segment cap for a compact JWT.
 * 1.0.46 stopped at 8 KiB, so a token-like segment just over that bound
 * stayed in the clear. 256 KiB is the DoS bound: the scan reads at most
 * this many token characters per segment, and a longer segment is not a
 * JWT. The walk is linear. It does not use a nested quantifier.
 */
export const JWT_SEGMENT_MAX = 256 * 1024;

/**
 * `general` is share, report, session export, and `redactSecretsInText`.
 * A header with a non-empty `alg`, or `typ` exactly `JWT`, is enough.
 * `strict` is the attest and keyless error scrubbers. Those require a
 * non-empty `alg` and do not accept `typ: JWT` alone. Both modes share
 * this scan, this cap, and the same suffix rule.
 */
export type JwtMaskMode = 'general' | 'strict';

/** `_x` / `_ab`, or a lone `_` / `-`. A hyphen plus a word or token tail is handled separately. */
const JWT_PRESERVE_SUFFIX = /(_[A-Za-z0-9]{1,2}|[_-])$/;
/**
 * Extra `eyJ` starts tried inside one header after the first candidate fails.
 * Each try slices the same span. `eyJ-`, `eyJ_`, and `eyJ=` make every
 * later `eyJ` a candidate, which is quadratic. A short cap still masks a
 * real token after a few of those prefixes. When the cap is hit, the scan
 * tries the last `eyJ` before the header dot once, so a real token after a
 * longer glued run is still masked. That is one extra try, not a restart
 * per prefix.
 */
const JWT_INTERIOR_RESTART_CAP = 8;

const JWT_DOT = 46;

function isJwtTokenCode(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 95 ||
    code === 43 ||
    code === 47 ||
    code === 61 ||
    code === 45
  );
}

function isAsciiAlnum(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122)
  );
}

function decodeBase64Segment(segment: string): string | null {
  if (!segment || segment.length > JWT_SEGMENT_MAX) return null;
  let pad = 0;
  if (segment.endsWith('==')) pad = 2;
  else if (segment.endsWith('=')) pad = 1;
  const body = segment.slice(0, segment.length - pad);
  if (!body || body.includes('=')) return null;
  if (!/^[A-Za-z0-9_+\-/]+$/.test(body)) return null;
  const normalized = body.replace(/-/g, '+').replace(/_/g, '/');
  if (normalized.length % 4 === 1) return null;
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const bytes = Buffer.from(padded, 'base64');
  if (bytes.length === 0) return null;
  return bytes.toString('utf8');
}

function isBase64Segment(segment: string, allowEmpty: boolean): boolean {
  if (segment.length === 0) return allowEmpty;
  if (segment.length > JWT_SEGMENT_MAX) return false;
  let pad = 0;
  if (segment.endsWith('==')) pad = 2;
  else if (segment.endsWith('=')) pad = 1;
  const body = segment.slice(0, segment.length - pad);
  if (!body || body.includes('=')) return false;
  return /^[A-Za-z0-9_+\-/]+$/.test(body);
}

/**
 * Header decodes to a JSON object. `general` accepts a non-empty string
 * `alg` or `typ` exactly `JWT`. `strict` accepts only a non-empty `alg`.
 * A valid header is at least 15 characters (`{"alg":"a"}`).
 */
function headerIsJwtUncached(header: string, mode: JwtMaskMode): boolean {
  if (header.length < 15 || !header.startsWith('eyJ')) return false;
  const decoded = decodeBase64Segment(header);
  if (!decoded) return false;
  // Compact JWT headers are one JSON object. Reject anything that does
  // not end at `}` before JSON.parse. A near-miss such as `eyJ-` repeated,
  // or a real header with `-eyJ` glued on, decodes to text that still
  // starts with `{` and then fails to parse. The throw is expensive, and
  // a 1MB run of those shapes used to spend seconds on it.
  const trimmed = decoded.trimEnd();
  if (trimmed.charCodeAt(0) !== 123 || trimmed.charCodeAt(trimmed.length - 1) !== 125) {
    return false;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  const record = parsed as Record<string, unknown>;
  if (typeof record.alg === 'string' && record.alg.length > 0) return true;
  if (mode === 'strict') return false;
  return record.typ === 'JWT';
}

/**
 * Repeated adversarial headers are the same short string. Remember the
 * last answer so a 1MB run does not decode it once per copy. The answer
 * depends only on the header and the mode.
 */
let cachedHeader = '';
let cachedMode: JwtMaskMode | null = null;
let cachedHeaderOk = false;

function headerIsJwt(header: string, mode: JwtMaskMode): boolean {
  if (header.length > 256) return headerIsJwtUncached(header, mode);
  if (header === cachedHeader && mode === cachedMode) return cachedHeaderOk;
  const ok = headerIsJwtUncached(header, mode);
  cachedHeader = header;
  cachedMode = mode;
  cachedHeaderOk = ok;
  return ok;
}

/**
 * Three segments, header.payload.signature. Signature may be empty (`alg:none`).
 * Payload must be non-empty. Segments may be shorter than 8 characters and may
 * use standard base64 (`+`, `/`, `=`) as well as base64url.
 */
function isJwtToken(token: string, mode: JwtMaskMode): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const header = parts[0] ?? '';
  const payload = parts[1] ?? '';
  const signature = parts[2] ?? '';
  if (!isBase64Segment(header, false)) return false;
  if (!isBase64Segment(payload, false)) return false;
  if (!isBase64Segment(signature, true)) return false;
  return headerIsJwt(header, mode);
}

function isLetterCode(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

/**
 * A dictionary word, all-lowercase or Capitalized. All-caps and mixed
 * internals are token alphabet, not words. Short stopwords stay out unless
 * they are listed (`then` is; `the` and `a` are not).
 */
function isClearHyphenWord(segment: string): boolean {
  const n = segment.length;
  if (n < 3 || n > 12) return false;
  for (let i = 0; i < n; i += 1) {
    if (!isLetterCode(segment.charCodeAt(i))) return false;
  }
  const lower = segment.toLowerCase();
  const title = lower[0].toUpperCase() + lower.slice(1);
  if (segment !== lower && segment !== title) return false;
  return HYPHEN_WORD_SUFFIXES.has(lower);
}

/**
 * Trailing `-piece` run. `clear` is true only when every piece is a whole
 * dictionary word. Otherwise the run is token material and must be consumed
 * in full, including a dictionary word that sits after a non-word piece.
 * The index is the first hyphen of the run.
 */
function hyphenSuffixRun(span: string): { index: number; clear: boolean } | null {
  let i = span.length;
  let clear = true;
  let parts = 0;
  while (i > 0) {
    let j = i;
    while (j > 0) {
      const code = span.charCodeAt(j - 1);
      const digit = code >= 48 && code <= 57;
      if (!isLetterCode(code) && !digit) break;
      j -= 1;
    }
    if (j === i) break;
    if (j === 0 || span.charCodeAt(j - 1) !== 45) break;
    if (!isClearHyphenWord(span.slice(j, i))) clear = false;
    parts += 1;
    i = j - 1;
  }
  if (parts === 0) return null;
  return { index: i, clear };
}

/**
 * How much of `span` to replace. `keep` characters at the end stay
 * (`_x`, a lone `_` or `-`, or a whole-word suffix such as `-then`,
 * `-Then`, or `-config-file`). Anything else after a real token is
 * consumed, including `-suffix`, `-low`, `-the`, and `-word9`.
 */
function jwtMaskCut(span: string, mode: JwtMaskMode): { cut: number; keep: number } | null {
  const preserve = JWT_PRESERVE_SUFFIX.exec(span);
  if (preserve && preserve.index > 0 && isJwtToken(span.slice(0, preserve.index), mode)) {
    return { cut: preserve.index, keep: preserve[0].length };
  }
  const run = hyphenSuffixRun(span);
  if (run && run.index > 0 && isJwtToken(span.slice(0, run.index), mode)) {
    if (run.clear) return { cut: run.index, keep: span.length - run.index };
    return { cut: span.length, keep: 0 };
  }
  if (isJwtToken(span, mode)) return { cut: span.length, keep: 0 };
  return null;
}

function readJwtSegment(text: string, from: number): { end: number; tooLong: boolean } {
  const n = text.length;
  const cap = Math.min(n, from + JWT_SEGMENT_MAX);
  let j = from;
  while (j < cap && isJwtTokenCode(text.charCodeAt(j))) j += 1;
  const tooLong = j === from + JWT_SEGMENT_MAX && j < n && isJwtTokenCode(text.charCodeAt(j));
  return { end: j, tooLong };
}

/**
 * Where to resume after a segment that cannot complete a JWT at `start`.
 * A run with no dot is skipped once. A dot after an over-long segment
 * resumes within one cap of that dot, which is the first start that
 * could still fit.
 */
function resumeAfterJwtRun(text: string, start: number, segEnd: number, tooLong: boolean): number {
  const n = text.length;
  let k = segEnd;
  if (tooLong) {
    while (k < n && isJwtTokenCode(text.charCodeAt(k))) k += 1;
  }
  if (tooLong && k < n && text.charCodeAt(k) === JWT_DOT) {
    return Math.max(start + 1, k - JWT_SEGMENT_MAX);
  }
  return Math.max(k, start + 1);
}

interface JwtStructure {
  end: number;
  dot1: number;
}

function readJwtStructure(text: string, start: number): JwtStructure | { resume: number } {
  const n = text.length;
  const seg1 = readJwtSegment(text, start);
  if (seg1.end === start) return { resume: start + 1 };
  if (seg1.tooLong || seg1.end >= n || text.charCodeAt(seg1.end) !== JWT_DOT) {
    return { resume: resumeAfterJwtRun(text, start, seg1.end, seg1.tooLong) };
  }
  const dot1 = seg1.end;
  const seg2 = readJwtSegment(text, dot1 + 1);
  if (seg2.tooLong || seg2.end >= n || text.charCodeAt(seg2.end) !== JWT_DOT) {
    return { resume: resumeAfterJwtRun(text, start, seg2.end, seg2.tooLong) };
  }
  const seg3 = readJwtSegment(text, seg2.end + 1);
  if (seg3.tooLong) {
    return { resume: resumeAfterJwtRun(text, start, seg3.end, true) };
  }
  return { end: seg3.end, dot1 };
}

function nextBoundaryEyJ(text: string, from: number): number {
  const n = text.length;
  let i = from;
  while (i < n) {
    const found = text.indexOf('eyJ', i);
    if (found < 0) return -1;
    if (found === 0 || !isAsciiAlnum(text.charCodeAt(found - 1))) return found;
    i = found + 3;
  }
  return -1;
}

function nextInteriorEyJ(text: string, from: number, dot: number): number {
  let i = from + 3;
  while (i < dot) {
    const found = text.indexOf('eyJ', i);
    if (found < 0 || found >= dot) return -1;
    if (!isAsciiAlnum(text.charCodeAt(found - 1))) return found;
    i = found + 3;
  }
  return -1;
}

/**
 * Last `eyJ` that starts at or after `from` and before `end`, not after an
 * alphanumeric. One backward pass. Repeating `lastIndexOf` is quadratic when
 * every `eyJ` sits after a letter.
 */
function lastBoundaryEyJ(text: string, from: number, end: number): number {
  const stop = Math.min(end, text.length);
  for (let i = stop - 3; i >= from; i -= 1) {
    if (text.charCodeAt(i) !== 101 || text.charCodeAt(i + 1) !== 121 || text.charCodeAt(i + 2) !== 74) {
      continue;
    }
    if (i === 0 || !isAsciiAlnum(text.charCodeAt(i - 1))) return i;
  }
  return -1;
}

/**
 * Last `eyJ` in the signature segment that is glued on with one `-`, `_`,
 * `=`, `+`, or `/`. Those five are token characters, so the next header is
 * swallowed into this signature and the other token's payload stays in
 * the clear. One backward pass. No slice of the segment.
 */
function lastJoinedEyJ(text: string, from: number, end: number): number {
  const stop = Math.min(end, text.length);
  for (let i = stop - 3; i >= from; i -= 1) {
    if (text.charCodeAt(i) !== 101 || text.charCodeAt(i + 1) !== 121 || text.charCodeAt(i + 2) !== 74) {
      continue;
    }
    const prev = i > 0 ? text.charCodeAt(i - 1) : 0;
    if (prev !== 45 && prev !== 95 && prev !== 61 && prev !== 43 && prev !== 47) continue;
    return i;
  }
  return -1;
}

/**
 * Unpadded base64url length of a JWS signature:
 * HS256 43, HS384 64, HS512 86, RS/PS256 342, RS/PS384 512, RS/PS512 683.
 * A shorter base64url run that then hits `+` or `/` is still inside an
 * unpadded standard-base64 signature, not a path boundary.
 */
const JWS_SIGNATURE_LENGTHS = new Set([43, 64, 86, 342, 512, 683]);

/**
 * First `=` at or after `from`, and before `end`. Stops at the first
 * character that cannot be signature or padding, so a token with no `=`
 * does not scan the rest of the buffer. `String.indexOf` has no end index;
 * using it here made every candidate walk to EOF.
 */
function indexOfPaddingEquals(text: string, from: number, end: number): number {
  const stop = Math.min(end, text.length);
  for (let i = from; i < stop; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 61) return i;
    if (!isJwtTokenCode(code)) return -1;
  }
  return -1;
}

/** Base64url alphabet, including `-`. Standard-base64 `+` `/` `=` are not included. */
function isBase64UrlChar(code: number): boolean {
  return isAsciiAlnum(code) || code === 95 || code === 45;
}

/**
 * A short filename extension after the segment dot. A longer base64url run
 * is another token segment, not `.ts`.
 */
function extensionAfter(text: string, segEnd: number): boolean {
  if (segEnd >= text.length || text.charCodeAt(segEnd) !== JWT_DOT) return false;
  let i = segEnd + 1;
  let n = 0;
  while (i < text.length && n < 8) {
    if (!isAsciiAlnum(text.charCodeAt(i))) break;
    i += 1;
    n += 1;
  }
  if (n < 1) return false;
  if (i < text.length && isBase64UrlChar(text.charCodeAt(i))) return false;
  return true;
}

/**
 * True when [at, segEnd) is a path glued with `/` or `+`, not more signature.
 * A clear path has a second slash, or one slash plus a file extension after
 * the segment dot. A `+` joiner needs a slash or that extension. A `+`
 * inside the tail is still signature alphabet, so it is not a path.
 */
function isClearGluedPath(text: string, at: number, segEnd: number): boolean {
  const next = text.charCodeAt(at);
  if (next !== 47 && next !== 43) return false;
  let slashes = 0;
  for (let k = at; k < segEnd; k += 1) {
    const code = text.charCodeAt(k);
    if (code === 47) {
      slashes += 1;
      continue;
    }
    // The leading '+' is the joiner. Another '+' is still signature alphabet.
    if (code === 43) {
      if (k !== at) return false;
      continue;
    }
    if (!isBase64UrlChar(code)) return false;
  }
  const ext = extensionAfter(text, segEnd);
  if (next === 43) return slashes >= 1 || ext;
  return slashes >= 2 || (slashes >= 1 && ext);
}

/**
 * Index where a base64url JWT ends and a glued path begins.
 * The signature is the longest base64url run. `/` and `+` are not in that
 * alphabet, so a path can sit outside the token. A header or payload that
 * already uses `+`, `/`, or `=` is standard base64; the signature may use
 * those too, and this split stays out so signature bytes are not left behind.
 * An unpadded standard-base64 signature also contains `+` or `/`. Splitting
 * at the first one leaves the rest of the signature in the clear. The split
 * is allowed only when the base64url signature is a standard JWS length
 * (43/64/86/342/512/683). A `+` or `/` earlier than that is still signature.
 * Returns -1 when the boundary is not clear.
 */
function clearPathSplit(
  text: string,
  cursor: number,
  dot1: number,
  end: number,
  mode: JwtMaskMode,
): number {
  const dot2 = text.indexOf('.', dot1 + 1);
  if (dot2 < 0 || dot2 >= end) return -1;
  const header = text.slice(cursor, dot1);
  const payload = text.slice(dot1 + 1, dot2);
  if (
    header.includes('+') || header.includes('/') || header.includes('=') ||
    payload.includes('+') || payload.includes('/') || payload.includes('=')
  ) {
    return -1;
  }
  let i = dot2 + 1;
  while (i < end && isBase64UrlChar(text.charCodeAt(i))) i += 1;
  if (i === dot2 + 1 || i >= end) return -1;
  if (!JWS_SIGNATURE_LENGTHS.has(i - (dot2 + 1))) return -1;
  if (!isClearGluedPath(text, i, end)) return -1;
  if (!isJwtToken(text.slice(cursor, i), mode)) return -1;
  return i;
}

/**
 * Index where a padded JWT ends and the text after the padding begins.
 * Padding `=` cannot sit in the middle of a segment, so text after a valid
 * pad is not signature. The `=` search stops at the end of this token.
 * `-then` and `-suffix` are not this trailer; the hyphen rule still owns
 * those. A joiner (`+` `/` `_` `=`) after the padding stays. Plain text
 * glued on after the padding stays too, so `=text` on an unpadded token
 * is masked through that pad and `text` remains. Returns -1 when the pad
 * is the end of the span or the next character is a hyphen.
 */
function paddedTrailerEnd(
  text: string,
  cursor: number,
  dot1: number,
  end: number,
  mode: JwtMaskMode,
): number {
  const dot2 = text.indexOf('.', dot1 + 1);
  if (dot2 < 0 || dot2 >= end) return -1;
  const sigStart = dot2 + 1;
  const eq = indexOfPaddingEquals(text, sigStart, end);
  if (eq <= sigStart) return -1;
  for (const pads of [1, 2]) {
    const total = eq + pads;
    if (total > end) continue;
    let padsOk = true;
    for (let k = 0; k < pads; k += 1) {
      if (text.charCodeAt(eq + k) !== 61) padsOk = false;
    }
    if (!padsOk) continue;
    const segLen = total - sigStart;
    if (segLen % 4 !== 0) continue;
    if (total >= end) continue;
    // Hyphen suffixes stay with jwtMaskCut (`-then` kept, `-suffix` consumed).
    if (text.charCodeAt(total) === 45) continue;
    if (!isJwtToken(text.slice(cursor, total), mode)) continue;
    return total;
  }
  return -1;
}

/**
 * Index of a second compact JWT glued onto this one with a single `-`,
 * `_`, `=`, `+`, or `/`. The joiner stays between the two masks.
 */
function gluedJwtSplit(
  text: string,
  cursor: number,
  dot1: number,
  end: number,
  mode: JwtMaskMode,
): number {
  const dot2 = text.indexOf('.', dot1 + 1);
  if (dot2 < 0 || dot2 >= end) return -1;
  // Only the third segment. Searching past `end` would rescan a long tail
  // on every failed candidate.
  const ey = lastJoinedEyJ(text, dot2 + 1, end);
  if (ey <= cursor) return -1;
  if (!isJwtToken(text.slice(cursor, ey - 1), mode)) return -1;
  const right = readJwtStructure(text, ey);
  if (!('end' in right)) return -1;
  // A third token glued with `=` makes the whole right span fail base64
  // (`=` is only padding at the end). Validate the right token up to that
  // next joiner so the pair still splits, and the following iteration
  // masks the rest. `_` and `-` stay valid inside a signature, so a clean
  // pair is unchanged.
  let rightEnd = right.end;
  const sigDot = text.indexOf('.', right.dot1 + 1);
  if (sigDot > right.dot1 && sigDot < right.end) {
    const next = lastJoinedEyJ(text, sigDot + 1, right.end);
    if (next > sigDot) rightEnd = next - 1;
  }
  const decided = jwtMaskCut(text.slice(ey, rightEnd), mode);
  if (!decided || decided.cut + decided.keep <= 0) return -1;
  return ey;
}

/**
 * True when [start, end) is only `eyJ-`, `eyJ_`, `eyJ=`, `eyJ+`, or `eyJ/`
 * chunks. That shape decodes to a repeating byte pattern, or it has `=`
 * in the middle, so it is never a JWT header. Skipping it avoids a decode
 * per chunk on a 1MB run of nine `eyJ-` prefixes plus a dot. The same skip
 * keeps a `+` or `/` run linear. A real header after those prefixes has
 * other characters and is not skipped.
 */
function isPureEyJPrefixRun(text: string, start: number, end: number): boolean {
  const len = end - start;
  if (len < 4 || len % 4 !== 0) return false;
  for (let i = start; i < end; i += 4) {
    if (text.charCodeAt(i) !== 101 || text.charCodeAt(i + 1) !== 121 || text.charCodeAt(i + 2) !== 74) {
      return false;
    }
    const sep = text.charCodeAt(i + 3);
    if (sep !== 45 && sep !== 95 && sep !== 61 && sep !== 43 && sep !== 47) return false;
  }
  return true;
}

/**
 * Mask compact JWTs. One left-to-right scan, no nested quantifier, so a
 * long run of `eyJ.` cannot backtrack. A failed candidate does not restart
 * at every interior `eyJ` after `-`, `_`, or `=`. Those restarts are
 * capped. After the cap, the last `eyJ` before the header dot is tried
 * once, so a real token after a long glued prefix is still masked.
 * Two JWTs joined by one `-`, `_`, `=`, `+`, or `/` are masked separately.
 * The joiner stays. A padded token followed by one of `+` `/` `_` `=` and
 * more text, or by plain text (`=text`), is masked only through the padding,
 * so the trailer stays and the token does not. The search for that padding
 * stops at the end of the token. A base64url token keeps a path glued on
 * with `/` or `+` when the signature is a standard JWS length and that path
 * is clearly a path. An unpadded standard-base64 signature that contains
 * `+` or `/` is not split there. Dotted text whose header does not
 * decode as a JWT (`eyJsee.the.docs`, versions, filenames) is left alone.
 * `_x`, a lone `_` or `-`, and a whole-word suffix such as `-then`,
 * `-Then`, or `-config-file` stay. A token tail, a short stopword, and a
 * mixed tail are consumed. A header that is only `eyJ-` / `eyJ_` / `eyJ=` /
 * `eyJ+` / `eyJ/` chunks is skipped in one pass.
 */
export function maskJwtTokens(text: string, mode: JwtMaskMode = 'general'): string {
  const n = text.length;
  let out = '';
  let last = 0;
  let i = 0;
  while (i < n) {
    const start = nextBoundaryEyJ(text, i);
    if (start < 0) break;
    const structure = readJwtStructure(text, start);
    if (!('end' in structure)) {
      i = structure.resume > start ? structure.resume : start + 1;
      continue;
    }
    if (isPureEyJPrefixRun(text, start, structure.dot1)) {
      i = structure.dot1 + 1;
      continue;
    }
    let cursor = start;
    let matched = false;
    let restarts = 0;
    let triedLast = false;
    while (cursor < structure.dot1) {
      // A JWT header is at least 15 characters. Shorter tails (`-eyJ`) cannot
      // match, and slicing them on every copy of a 1MB run dominates.
      if (structure.dot1 - cursor < 15) break;
      const glued = gluedJwtSplit(text, cursor, structure.dot1, structure.end, mode);
      if (glued > cursor) {
        const leftSpan = text.slice(cursor, glued - 1);
        const left = jwtMaskCut(leftSpan, mode);
        if (left && left.cut + left.keep > 0) {
          out += text.slice(last, cursor);
          out += `[REDACTED]${leftSpan.slice(left.cut, left.cut + left.keep)}`;
          last = cursor + left.cut + left.keep;
          i = last;
          matched = true;
          break;
        }
      }
      // Padding, then a base64url path. Both cut only the JWT. A joined
      // second token was already taken above, so this trailer is not a JWT.
      const trailer = paddedTrailerEnd(text, cursor, structure.dot1, structure.end, mode);
      const pathAt = trailer > cursor
        ? -1
        : clearPathSplit(text, cursor, structure.dot1, structure.end, mode);
      const boundary = trailer > cursor ? trailer : pathAt;
      if (boundary > cursor && isJwtToken(text.slice(cursor, boundary), mode)) {
        out += text.slice(last, cursor);
        out += '[REDACTED]';
        last = boundary;
        i = boundary;
        matched = true;
        break;
      }
      const span = text.slice(cursor, structure.end);
      const decided = jwtMaskCut(span, mode);
      if (decided && decided.cut + decided.keep > 0) {
        out += text.slice(last, cursor);
        out += `[REDACTED]${span.slice(decided.cut, decided.cut + decided.keep)}`;
        last = cursor + decided.cut + decided.keep;
        i = last;
        matched = true;
        break;
      }
      if (restarts >= JWT_INTERIOR_RESTART_CAP) {
        if (triedLast) break;
        triedLast = true;
        const lastStart = lastBoundaryEyJ(text, cursor + 3, structure.dot1);
        if (lastStart > cursor) {
          cursor = lastStart;
          continue;
        }
        break;
      }
      const interior = nextInteriorEyJ(text, cursor, structure.dot1);
      if (interior < 0) break;
      cursor = interior;
      restarts += 1;
    }
    if (!matched) i = structure.dot1 + 1;
  }
  out += text.slice(last);
  return out;
}

export function redactSecretsInText(text: string): string {
  let out = redactSecretAssignments(text);
  out = maskJwtTokens(out);
  for (const { re, replacement } of SECRET_VALUE_PATTERNS) {
    out = typeof replacement === 'function'
      ? out.replace(re, replacement)
      : out.replace(re, replacement);
  }
  return out;
}

/**
 * Session id after redaction. A bare `[REDACTED]` is stamped with
 * sha256-12 of the original id so two secret-looking ids (including
 * `ghp_` tokens that share one mask) stay two sessions. `AKIA` and
 * `ASIA` already stamp the key and are left as that stamp. The stamp
 * is not reversible. After import the raw id does not find the copy.
 */
export function maskSessionId(id: string): string {
  const masked = redactSecretsInText(id);
  if (masked === id || !masked.includes('[REDACTED]')) return masked;
  return masked.replaceAll('[REDACTED]', `[REDACTED:${secretMaskStamp(id)}]`);
}

/**
 * Redact one file path. Each segment is stamped the same way a
 * secret-shaped session id is, so a `ghp_` filename becomes
 * `ghp_[REDACTED:<sha256-12>]` from that segment. The raw token is not
 * in the stamp. A segment that is not secret-shaped is unchanged.
 * `AKIA` and `ASIA` keep the key stamp from `redactSecretsInText`.
 */
export function maskSecretPath(path: string): string {
  if (!path.includes('/')) return maskSessionId(path);
  return path.split('/').map((part) => maskSessionId(part)).join('/');
}

/**
 * Redact a full Markdown receipt body (before Integrity).
 * - Masks secret values in diffs and prose
 * - Masks high/secret risk detail cells
 * - Omits nested prior-receipt / index diff bodies (avoids re-embedding secrets)
 * - Inserts a redaction notice under Session when not already present
 * - Masks an explicit Host label (`[REDACTED]`) unless `maskHost` is false.
 *   Session, parent, and agent stay as fields. A secret-shaped value on
 *   those lines, including a JWT-shaped session id, is masked with the
 *   other secret patterns. The Session value is stamped when that mask
 *   would otherwise be a bare `[REDACTED]`, so two ids do not merge.
 *   Capture passes `maskHost: false` so a local
 *   `--host` survives secret redaction. share / export mask it unless
 *   `--include-host`.
 */
export function redactMarkdownBody(
  markdown: string,
  opts: { maskHost?: boolean } = {},
): string {
  const maskHost = opts.maskHost !== false;
  const normalized = markdown.replace(/\r\n/g, '\n');
  const all = normalized.split('\n');
  const lines = all.slice(0, integrityCutIndex(all));
  const out: string[] = [];
  let inDiffFence = false;
  let inNestedArtifactDiff = false;
  let nestedOmitted = false;
  let inRiskTable = false;
  let sawRedactionNotice = false;
  let currentDiffPath: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.includes('**Redacted**:') || line.includes('Snapshot is redacted')) {
      sawRedactionNotice = true;
    }

    if (maskHost && /^- \*\*Host\*\*:/.test(line)) {
      out.push('- **Host**: [REDACTED]');
      continue;
    }

    // Header field only. A copy of this line inside a diff stays on the
    // diff path (nested receipt bodies are omitted, not stamped).
    if (!inDiffFence && !inRiskTable) {
      const sessionField = /^- \*\*Session\*\*:\s*(.*)$/.exec(line);
      if (sessionField) {
        out.push(`- **Session**: ${maskSessionId(sessionField[1])}`);
        continue;
      }
    }

    // Track ### `path` under Diff summaries
    const pathHeader = line.match(/^###\s+`([^`]+)`\s*$/);
    if (pathHeader) {
      // Keep the original path for nested-receipt detection. The heading
      // that is published is stamped per segment, same as a secret-shaped
      // session id, so a ghp_ filename is not raw in share text or HTML.
      currentDiffPath = pathHeader[1];
      out.push(`### \`${maskSecretPath(pathHeader[1])}\``);
      continue;
    }

    if (line.startsWith('## Risk findings')) {
      inRiskTable = true;
      out.push(line);
      continue;
    }
    if (inRiskTable && line.startsWith('## ')) {
      inRiskTable = false;
    }

    if (line.trim() === '```diff' || line.trim() === '```') {
      if (line.trim() === '```diff') {
        inDiffFence = true;
        inNestedArtifactDiff = Boolean(
          currentDiffPath && isReceiptArtifactPath(currentDiffPath),
        );
        nestedOmitted = false;
        out.push(line);
        continue;
      }
      if (inDiffFence && line.trim() === '```') {
        if (inNestedArtifactDiff && !nestedOmitted) {
          out.push('+[REDACTED — nested receipt/index body omitted]');
        }
        inDiffFence = false;
        inNestedArtifactDiff = false;
        nestedOmitted = false;
        out.push(line);
        continue;
      }
      out.push(line);
      continue;
    }

    if (inDiffFence) {
      if (inNestedArtifactDiff) {
        if (!nestedOmitted) {
          out.push('+[REDACTED — nested receipt/index body omitted]');
          nestedOmitted = true;
        }
        continue;
      }
      out.push(redactSecretsInText(line));
      continue;
    }

    if (inRiskTable && line.startsWith('|')) {
      // | sev | `code` | detail |
      const cells = splitTableRow(line);
      if (cells.length >= 3 && cells[0] !== 'Sev' && !/^-+$/.test(cells[0])) {
        const sev = cells[0].trim().toLowerCase();
        const codeCell = cells[1].trim();
        const codeMatch = codeCell.match(/`([^`]+)`/);
        const code = codeMatch?.[1] ?? codeCell;
        const isSecret = sev === 'high' || HIGH_SECRET_CODES.has(code);
        if (isSecret) {
          const detail = redactSecretsInText(cells.slice(2).join('|')).replace(
            /[A-Za-z0-9/+=_-]{16,}/g,
            '[REDACTED]',
          );
          out.push(
            `| ${cells[0].trim()} | ${cells[1].trim()} | ${containsRedactionMark(detail) ? detail : '[REDACTED — secret detail masked]'} |`,
          );
          continue;
        }
      }
      out.push(redactSecretsInText(line));
      continue;
    }

    // What to review lines for high secrets
    if (/^\d+\.\s+\*\*high\*\*/.test(line)) {
      out.push(redactSecretsInText(line).replace(/—\s+.+$/, '— [REDACTED — secret detail masked]'));
      continue;
    }

    out.push(redactSecretsInText(line));
  }

  // Drop trailing blanks, then inject redaction notice after Session block if needed
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();

  if (!sawRedactionNotice) {
    const sessionIdx = out.findIndex((l) => l === '## Session');
    if (sessionIdx >= 0) {
      // Find end of Session section (next ## or end)
      let insertAt = sessionIdx + 1;
      while (insertAt < out.length && !out[insertAt].startsWith('## ')) {
        insertAt++;
      }
      // Insert before the blank line preceding next section if present
      let at = insertAt;
      if (at > 0 && out[at - 1].trim() === '') at = at - 1;
      out.splice(at, 0, '- **Redacted**: yes — high/secret findings masked for safer sharing');
    } else {
      out.unshift(
        '> **Redacted** — high/secret findings masked for safer sharing',
        '',
      );
    }
  }

  return out.join('\n') + '\n';
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return trimmed.split('|').map((c) => c.trim());
}

/**
 * Apply redaction to a full receipt (with or without Integrity) and return
 * body ready for appendHashFooter.
 */
export function prepareRedactedBody(
  markdown: string,
  opts: { maskHost?: boolean } = {},
): string {
  return redactMarkdownBody(markdown, opts);
}

/**
 * Share's publish path. Session export calls this unless `--include-host`.
 * One function so the two cannot drift:
 * - secret values masked (`redactSecretsInText`)
 * - nested receipt / index diff bodies replaced with
 *   `[REDACTED — nested receipt/index body omitted]`
 * - Host line replaced with `[REDACTED]` unless `maskHost` is false
 * - body re-hashed
 * `maskHost: false` is share `--include-host` (secrets and nested bodies
 * still go). Session export `--include-host` does not call this at all.
 */
export function publishRedactedReceipt(
  markdown: string,
  opts: { maskHost?: boolean } = {},
): string {
  return appendHashFooter(prepareRedactedBody(markdown, opts));
}
