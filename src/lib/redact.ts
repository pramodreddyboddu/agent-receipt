/**
 * Redaction helpers for safer sharing of receipts.
 * Masks high-signal secrets in Markdown/HTML bodies, then callers re-hash.
 */
import { appendHashFooter, integrityCutIndex, sha256Hex } from './hash.js';
import { humpWordAt } from './hump-words.js';

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
    // Handled by redactPrivateKeyBlocks. The old lazy `[\s\S]*?` scan
    // walked to EOF once per unterminated BEGIN, which is quadratic.
    // The source prefix marks this slot so the block stays in pattern order.
    re: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/,
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
 * First three base64 chars of a JSON object header.
 * `{"` is `eyJ`. `{` plus space (or another byte whose top bits are 00,
 * which `"` and JSON whitespace have) is `eyA`. `{\n` is `ewo`, `{\r` is
 * `ew0`, `{\t` is `ewk`, when the next byte is `"` or whitespace.
 * A header that does not start with one of these (a UTF-8 BOM, or any
 * other leading byte) is not scanned. Scanning every base64 run would
 * mask ordinary base64.
 */
function isJwtHeaderPrefixAt(text: string, i: number): boolean {
  if (i < 0 || i + 2 >= text.length) return false;
  if (text.charCodeAt(i) !== 101) return false;
  const second = text.charCodeAt(i + 1);
  const third = text.charCodeAt(i + 2);
  if (second === 121) return third === 74 || third === 65;
  if (second === 119) return third === 111 || third === 48 || third === 107;
  return false;
}

/**
 * Header decodes to a JSON object. `general` and `strict` accept a
 * non-empty string `alg` or a non-empty string `kid` (kid-only, or `alg`
 * after `kid`). `general` also accepts `typ` exactly `JWT`. `strict` still
 * rejects `typ: JWT` with no `alg` and no string `kid`. A non-string `kid`
 * is not a header. A valid header is at least 15 characters (`{"alg":"a"}`).
 * `alg` is that string when it is non-empty, otherwise null. The path
 * split uses it and does not guess a signature length. A kid-only token
 * has no alg, so a glued path stays inside the mask.
 */
interface JwtHeaderInfo {
  ok: boolean;
  alg: string | null;
}

const JWT_HEADER_MISS: JwtHeaderInfo = { ok: false, alg: null };

function jwtHeaderInfoUncached(header: string, mode: JwtMaskMode): JwtHeaderInfo {
  if (header.length < 15 || !isJwtHeaderPrefixAt(header, 0)) return JWT_HEADER_MISS;
  const decoded = decodeBase64Segment(header);
  if (!decoded) return JWT_HEADER_MISS;
  // Compact JWT headers are one JSON object. Reject anything that does
  // not end at `}` before JSON.parse. A near-miss such as `eyJ-` repeated,
  // or a real header with `-eyJ` glued on, decodes to text that still
  // starts with `{` and then fails to parse. The throw is expensive, and
  // a 1MB run of those shapes used to spend seconds on it.
  const trimmed = decoded.trimEnd();
  if (trimmed.charCodeAt(0) !== 123 || trimmed.charCodeAt(trimmed.length - 1) !== 125) {
    return JWT_HEADER_MISS;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return JWT_HEADER_MISS;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return JWT_HEADER_MISS;
  const record = parsed as Record<string, unknown>;
  const alg = typeof record.alg === 'string' && record.alg.length > 0 ? record.alg : null;
  if (alg) return { ok: true, alg };
  if (typeof record.kid === 'string' && record.kid.length > 0) return { ok: true, alg: null };
  if (mode === 'strict') return JWT_HEADER_MISS;
  if (record.typ === 'JWT') return { ok: true, alg: null };
  return JWT_HEADER_MISS;
}

/**
 * Repeated adversarial headers are the same short string. Remember the
 * last answer so a 1MB run does not decode it once per copy. The answer
 * depends only on the header and the mode.
 */
let cachedHeader = '';
let cachedMode: JwtMaskMode | null = null;
let cachedHeaderInfo: JwtHeaderInfo = JWT_HEADER_MISS;

function jwtHeaderInfo(header: string, mode: JwtMaskMode): JwtHeaderInfo {
  if (header.length > 256) return jwtHeaderInfoUncached(header, mode);
  if (header === cachedHeader && mode === cachedMode) return cachedHeaderInfo;
  const info = jwtHeaderInfoUncached(header, mode);
  cachedHeader = header;
  cachedMode = mode;
  cachedHeaderInfo = info;
  return info;
}

function headerIsJwt(header: string, mode: JwtMaskMode): boolean {
  return jwtHeaderInfo(header, mode).ok;
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
 * How much of `span` to replace. A whole-word hyphen suffix stays
 * (`-then`, `-Then`, `-config-file`). A base64url tail split on `_` or
 * `-` does not: 1, 2, or 3 raw characters (`_`, `-`, `_x`, `_ab`) are
 * part of the token. Anything else after a real token is consumed,
 * including `-suffix`, `-low`, `-the`, and `-word9`.
 */
function jwtMaskCut(span: string, mode: JwtMaskMode): { cut: number; keep: number } | null {
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

/**
 * Next header prefix at or after `from`, not after an alphanumeric.
 * One `indexOf('e')` plus a 3-char check. Separate searches for `eyJ`,
 * `eyA`, `ewo`, `ew0`, and `ewk` would each walk the rest of the buffer.
 */
function nextBoundaryEyJ(text: string, from: number): number {
  const n = text.length;
  let i = from;
  while (i < n) {
    const found = text.indexOf('e', i);
    if (found < 0) return -1;
    if ((found === 0 || !isAsciiAlnum(text.charCodeAt(found - 1))) && isJwtHeaderPrefixAt(text, found)) {
      return found;
    }
    i = found + 1;
  }
  return -1;
}

function nextInteriorEyJ(text: string, from: number, dot: number): number {
  let i = from + 1;
  while (i < dot) {
    const found = text.indexOf('e', i);
    if (found < 0 || found >= dot) return -1;
    if (!isAsciiAlnum(text.charCodeAt(found - 1)) && isJwtHeaderPrefixAt(text, found)) return found;
    i = found + 1;
  }
  return -1;
}

/**
 * Last header prefix that starts at or after `from` and before `end`, not
 * after an alphanumeric. One backward pass. Repeating `lastIndexOf` is
 * quadratic when every prefix sits after a letter. The same prefixes as
 * the forward scan, so a spaced header after a long `eyA-` / `eyJ-` run
 * is still found.
 */
function lastBoundaryEyJ(text: string, from: number, end: number): number {
  const stop = Math.min(end, text.length);
  for (let i = stop - 3; i >= from; i -= 1) {
    if (!isJwtHeaderPrefixAt(text, i)) continue;
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
    if (!isJwtHeaderPrefixAt(text, i)) continue;
    const prev = i > 0 ? text.charCodeAt(i - 1) : 0;
    if (prev !== 45 && prev !== 95 && prev !== 61 && prev !== 43 && prev !== 47) continue;
    return i;
  }
  return -1;
}

/**
 * Unpadded base64url length (`url`) and padded standard-base64 length
 * (`std`) of a JWS signature for that header's own `alg`.
 * HS256 43/44; HS384 64/64; HS512 and ES256 86/88; ES256K 86/88;
 * EdDSA is Ed25519 86/88 or Ed448 152/152; ES384 128/128; ES512 176/176.
 * RS* and PS* are the RSA modulus size: 342/344, 512/512, or 683/684
 * (2048, 3072, or 4096). The path split uses `url` only. `std` is at
 * least `url`, so a run that reaches the padded form has reached that
 * size. An alg with no row here never splits.
 */
interface SigSize {
  url: number;
  std: number;
}

const SIG_HS256: SigSize[] = [{ url: 43, std: 44 }];
const SIG_HS384: SigSize[] = [{ url: 64, std: 64 }];
const SIG_86_88: SigSize[] = [{ url: 86, std: 88 }];
const SIG_ES384: SigSize[] = [{ url: 128, std: 128 }];
const SIG_ES512: SigSize[] = [{ url: 176, std: 176 }];
/** Ed25519 (86) and Ed448 (152). Both use alg EdDSA. */
const SIG_EDDSA: SigSize[] = [
  { url: 86, std: 88 },
  { url: 152, std: 152 },
];
const SIG_RSA: SigSize[] = [
  { url: 342, std: 344 },
  { url: 512, std: 512 },
  { url: 683, std: 684 },
];
/**
 * Longest in-segment tail still treated as a glued path after an exact RSA
 * signature (`/src/app` is 8). A longer tail is the rest of the signature.
 * 48 is under the shortest non-standard remainder called out for 1.0.53
 * (600 − 512 = 88) and under 511 − 342. The tail itself is one bounded
 * scan. A run of 8 or more is signature unless it is one repeated
 * character or an ordinary path word (`components`, `utilities`). A tail
 * of 3 to 7 characters, measured without the leading `/` or `+`, stays
 * only when a 2-to-4 letter extension follows and every segment of 3 or
 * more letters is a path atom or an ordinary word. A 7-letter segment
 * is short (`/Ahsqowx` is 7, not 8). One- and two-letter lowercase
 * pieces still stay (`/ab`, `/a/b`). `/Ahs`, `/Qow`, `/hnw/x`,
 * `/Ahsqowx`, `/OHALMQO`, and `/QZXWVKT` are signature. Any uppercase
 * letter stays only when the tail is a filename path, that extension
 * follows, and the same per-segment word check passes.
 * A longer lowercase tail stays when it is a grounded filename and that
 * extension follows, when every segment is a path word (`/src/index`,
 * `/bin/run`), or when the tail is one repeated character.
 * An extension by itself is not enough: `/Qx7.ts` and `/K.ts` are signature.
 * Filename words (`user`, `repo`, `package`, `get`, `service`), PascalCase
 * and camelCase humps of those words (`UserProfile`, `formatDate`,
 * `MyClass`, `HomeView`, `getUser`, `UserService`, `UserController`),
 * and `Dockerfile` also stay. `.swift` is an extension. One lowercase name
 * stays when another segment is a path word (`/Users/pramod/repo`). A
 * filename with no slash stays only when that suffix is one of those names.
 * `/Ahsqowx`, `/OHALMQO`, `/QZXWVKT`, and `/Makefile` stay masked.
 * `/Views/HomeView.swift`, `/Sources/App/AppDelegate.swift`,
 * `/Models/User.cs`, `/components/NavBar.vue`, `/lib/parseJSON.ts`,
 * `/src/api/getUser.js`, `UserService.java`, `UserController.php`,
 * `/LICENSE`, `/CHANGELOG.md`, and `/tsconfig.json` stay.
 */
const RSA_GLUED_PATH_MAX = 48;
/** Fast reject before a header decode. Unknown lengths never split. */
const SPLITTABLE_SIGNATURE_LENGTHS = new Set([43, 64, 86, 128, 152, 176, 342, 512, 683]);

function signatureSizesForAlg(alg: string | null): SigSize[] | null {
  switch (alg) {
    case 'HS256':
      return SIG_HS256;
    case 'HS384':
      return SIG_HS384;
    case 'HS512':
    case 'ES256':
    case 'ES256K':
      return SIG_86_88;
    case 'EdDSA':
      return SIG_EDDSA;
    case 'ES384':
      return SIG_ES384;
    case 'ES512':
      return SIG_ES512;
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return SIG_RSA;
    default:
      return null;
  }
}

/** True when `runLen` is an RSA signature end: 342/344, 512, or 683/684. */
function rsaRunEndsExactly(runLen: number): boolean {
  for (const size of SIG_RSA) {
    if (runLen === size.url || runLen === size.std) return true;
  }
  return false;
}

function isRsaUrlLength(len: number): boolean {
  for (const size of SIG_RSA) {
    if (len === size.url) return true;
  }
  return false;
}

/**
 * Longest unpadded signature length this third segment has reached.
 * RSA splits only when the measured run ends on a known length. A run
 * longer than 342 or 512 that does not end on 342/344, 512, or 683/684
 * is not a split point, so a `/` or `+` at 342 or 512 inside a 511, 600,
 * or 682 character signature stays inside the mask. A short glued path is
 * measured as the base64url prefix by the caller, so `/src/app.ts` after
 * an exact signature still splits. Other algs keep the reached-length
 * rule: a 684-style padded run uses the unpadded length, and Ed448 (152)
 * is not split at Ed25519 (86). One pass over a fixed table.
 */
function longestSignatureLength(alg: string | null, runLen: number): number | null {
  const sizes = signatureSizesForAlg(alg);
  if (!sizes) return null;
  if (sizes === SIG_RSA) {
    let best: number | null = null;
    for (const size of sizes) {
      if (runLen !== size.url && runLen !== size.std) continue;
      if (best === null || size.url > best) best = size.url;
    }
    return best;
  }
  let best: number | null = null;
  for (const size of sizes) {
    // `std` is the padded length and is never shorter than `url`. A run
    // that reaches the padded form has reached that size. 88 and 684 are
    // not split points; the base64url scan stops at `=`.
    if (size.std < size.url) continue;
    if (runLen >= size.url && (best === null || size.url > best)) best = size.url;
  }
  return best;
}

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
 * Filename extension after the segment dot: 2 to 4 ASCII letters
 * (`.ts`, `.tsx`, `.md`, `.js`, `.json`). Digits and a 1-letter tail stay
 * out, so a signature fragment is not kept just because `.x` follows.
 * One bounded scan, at most 5 characters.
 */
function filenameExtensionAfter(text: string, segEnd: number): boolean {
  if (segEnd >= text.length || text.charCodeAt(segEnd) !== JWT_DOT) return false;
  let i = segEnd + 1;
  let n = 0;
  // 5 letters is read so `.swift` can match and a 6th letter still fails
  // the base64url check below. Any other 5-letter tail is not an extension.
  while (i < text.length && n < 5) {
    if (!isLetterCode(text.charCodeAt(i))) break;
    i += 1;
    n += 1;
  }
  if (n < 2 || n > 5) return false;
  if (n === 5) {
    const swift = 'swift';
    for (let k = 0; k < 5; k += 1) {
      let code = text.charCodeAt(segEnd + 1 + k);
      if (code >= 65 && code <= 90) code += 32;
      if (code !== swift.charCodeAt(k)) return false;
    }
  }
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
 * Lowercase filename segment, 1 to 7 characters (`src`, `app`, `my-app`).
 * A `-` or `_` may follow a letter. Digits stay out, so `x7` is signature.
 * One scan of a segment already bounded by the 48-character tail cap.
 */
function lowercaseFilenameSegment(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 1 || n > 7) return false;
  let letters = 0;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 97 && code <= 122) {
      letters += 1;
      continue;
    }
    if ((code === 45 || code === 95) && letters > 0) continue;
    return false;
  }
  return letters >= 1;
}

/**
 * Capitalized word of 3 to 7 letters (`App`) or all-caps of 4 to 7 (`README`).
 * A single capital (`K`), `AB`, `XYZ`, and mixed internals (`Qx`, `aB`) are
 * signature alphabet. Letters only.
 */
function titledFilenameSegment(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 3 || n > 7) return false;
  let upper = 0;
  let lower = 0;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 65 && code <= 90) upper += 1;
    else if (code >= 97 && code <= 122) lower += 1;
    else return false;
  }
  if (lower === 0) return upper >= 4;
  if (upper !== 1) return false;
  const first = text.charCodeAt(from);
  return first >= 65 && first <= 90;
}

/**
 * Ordinary directory words of 8 to 24 letters (`components`, `utilities`).
 * A single leading capital is allowed. Digits, a second capital, and a
 * run that is not in this set stay signature, so `abcdefgh` is not a path.
 * One bounded scan of a segment already inside the 48-character tail.
 */
const ORDINARY_PATH_WORDS = new Set([
  'abstractions',
  'adapters',
  'arguments',
  'attributes',
  'builders',
  'changelog',
  'clients',
  'component',
  'components',
  'configurations',
  'constants',
  'containers',
  'contexts',
  'controller',
  'controllers',
  'dependencies',
  'documents',
  'environments',
  'exceptions',
  'factories',
  'formatters',
  'frontend',
  'functions',
  'handlers',
  'helpers',
  'implementations',
  'interfaces',
  'internal',
  'javascript',
  'listeners',
  'middleware',
  'migrations',
  'modules',
  'packages',
  'parameters',
  'parsers',
  'plugins',
  'properties',
  'providers',
  'publishers',
  'repositories',
  'repository',
  'resources',
  'routers',
  'schemas',
  'selectors',
  'serializers',
  'servers',
  'services',
  'settings',
  'subscribers',
  'templates',
  'tsconfig',
  'typescript',
  'utilities',
  'validators',
  'workers',
]);

/**
 * Short names that ground a lowercase path (`src`, `app`, `docs`).
 * One- and two-letter pieces stay out, so `/ab/cd/ef` is not a filename.
 * `home`, `runner`, `work`, `run`, `scripts`, and `deploy` keep common
 * checkout paths (`/home/runner/work/a/b.ts`, `/bin/run`, `/scripts/deploy.sh`).
 */
const PATH_ATOMS = new Set([
  'admin',
  'api',
  'app',
  'auth',
  'bin',
  'button',
  'cli',
  'cmd',
  'com',
  'core',
  'data',
  'demo',
  'deploy',
  'dist',
  'doc',
  'docs',
  'example',
  'file',
  'files',
  'guide',
  'home',
  'hooks',
  'http',
  'index',
  'java',
  'json',
  'lib',
  'main',
  'mock',
  'pages',
  'pkg',
  'readme',
  'run',
  'runner',
  'scripts',
  'server',
  'spec',
  'specs',
  'src',
  'state',
  'store',
  'test',
  'tests',
  'tool',
  'tools',
  'types',
  'use',
  'util',
  'utils',
  'web',
  'work',
]);

/**
 * Ordinary filename and path words that are not already atoms.
 * Title case or all-lowercase. All-caps stays out of this set so a
 * 7-letter uppercase tail (`OHALMQO`, `QZXWVKT`) is not a word.
 * A word shorter than 4 (`my`, `nav`, `bar`, `get`) is only a hump
 * inside `MyClass`, `NavBar`, or `getUser`. Alone, `/nav.ts` is a
 * 3-character signature fragment and stays masked.
 */
const FILENAME_WORDS = new Set([
  'bar',
  'class',
  'date',
  'delegate',
  'file',
  'format',
  'get',
  'my',
  'nav',
  'package',
  'parse',
  'profile',
  'repo',
  'service',
  'user',
  'users',
  'view',
]);

function pathWordLower(lower: string): boolean {
  return PATH_ATOMS.has(lower) || ORDINARY_PATH_WORDS.has(lower) || FILENAME_WORDS.has(lower);
}

function ordinaryWordAt(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 8 || n > 24) return false;
  let lower = '';
  let vowel = false;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 97 && code <= 122) {
      lower += String.fromCharCode(code);
    } else if (code >= 65 && code <= 90) {
      if (i !== from) return false;
      lower += String.fromCharCode(code + 32);
    } else {
      return false;
    }
    const letter = lower.charCodeAt(lower.length - 1);
    if (letter === 97 || letter === 101 || letter === 105 || letter === 111 || letter === 117 || letter === 121) {
      vowel = true;
    }
  }
  if (!vowel) return false;
  return ORDINARY_PATH_WORDS.has(lower);
}

function segmentIsAtom(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 2 || n > 7) return false;
  let word = '';
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 97 && code <= 122) word += String.fromCharCode(code);
    else if (code >= 65 && code <= 90) word += String.fromCharCode(code + 32);
    else return false;
  }
  return PATH_ATOMS.has(word);
}

function lettersOnly(text: string, from: number, to: number): boolean {
  if (to <= from) return false;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (!((code >= 65 && code <= 90) || (code >= 97 && code <= 122))) return false;
  }
  return true;
}

/**
 * A hyphenated segment longer than 7 (`my-component`). Each piece is
 * letters. An 8+ piece must be an ordinary word. At least one piece is
 * an atom, an ordinary word, or 4 letters or more, so `ab-cd` stays out.
 */
function hyphenatedFilenameSegment(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 8 || n > 48) return false;
  let pieces = 0;
  let grounded = false;
  let pieceFrom = from;
  let sawJoin = false;
  const take = (pieceTo: number): boolean => {
    if (pieceTo <= pieceFrom) return false;
    if (!lettersOnly(text, pieceFrom, pieceTo)) return false;
    pieces += 1;
    const len = pieceTo - pieceFrom;
    const ordinary = ordinaryWordAt(text, pieceFrom, pieceTo);
    if (len >= 8 && !ordinary) return false;
    if (ordinary || segmentIsAtom(text, pieceFrom, pieceTo) || len >= 4) grounded = true;
    return true;
  };
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code !== 45 && code !== 95) continue;
    sawJoin = true;
    if (!take(i)) return false;
    pieceFrom = i + 1;
  }
  if (!sawJoin || !take(to)) return false;
  return pieces >= 2 && grounded;
}

/**
 * camelCase of path atoms (`useAuth` is `use` + `Auth`). The segment must
 * start with a lowercase letter and contain an internal capital. Each hump
 * is an atom, so a random capital in the middle stays signature.
 * One pass over a segment already inside the 48-character tail.
 */
function camelHumpsAreAtoms(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 4 || n > 48) return false;
  if (text.charCodeAt(from) < 97 || text.charCodeAt(from) > 122) return false;
  let humpFrom = from;
  let humps = 0;
  let broke = false;
  for (let i = from; i <= to; i += 1) {
    if (i < to) {
      const code = text.charCodeAt(i);
      const upper = code >= 65 && code <= 90;
      const lower = code >= 97 && code <= 122;
      if (!upper && !lower) return false;
      if (i > from && upper) {
        if (!segmentIsAtom(text, humpFrom, i)) return false;
        humps += 1;
        humpFrom = i;
        broke = true;
      }
      continue;
    }
    if (!broke || !segmentIsAtom(text, humpFrom, to)) return false;
    humps += 1;
  }
  return humps >= 2;
}

/**
 * A path word in the atom, ordinary-word, or filename set.
 * All-lowercase and a single leading capital match. All-caps matches only
 * an atom or an ordinary word (`README`), not a short filename word, so
 * `OHALMQO` and `QZXWVKT` stay signature. A filename word shorter than 4
 * (`my`, `nav`, `bar`, `get`) matches only as a hump. A 3-letter known
 * directory (`src`, `app`, `com`) is an atom and still matches alone.
 * Mixed internals stay out. One scan of a segment already inside the
 * 48-character tail.
 */
function dictionaryWordAt(text: string, from: number, to: number, asHump = false): boolean {
  const n = to - from;
  if (n < 2 || n > 24) return false;
  let lower = '';
  let uppers = 0;
  let lowers = 0;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 97 && code <= 122) {
      lowers += 1;
      lower += String.fromCharCode(code);
    } else if (code >= 65 && code <= 90) {
      uppers += 1;
      lower += String.fromCharCode(code + 32);
    } else {
      return false;
    }
  }
  if (uppers > 0 && lowers > 0) {
    if (uppers !== 1) return false;
    const first = text.charCodeAt(from);
    if (first < 65 || first > 90) return false;
  }
  if (uppers === n && !PATH_ATOMS.has(lower) && !ORDINARY_PATH_WORDS.has(lower)) return false;
  // `nav` is a hump inside `NavBar`. Alone, `/nav.ts` stays signature.
  if (!asHump && n < 4 && !PATH_ATOMS.has(lower) && !ORDINARY_PATH_WORDS.has(lower)) return false;
  return pathWordLower(lower);
}

/**
 * PascalCase or camelCase whose humps are path words (`UserProfile`,
 * `formatDate`, `MyClass`, `HomeView`). A hump of one letter, a digit,
 * and a random capital (`AbCdEfGh`, `Ahsqowx`) stay out. One pass.
 */
function dictionaryHumps(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 4 || n > 48) return false;
  const first = text.charCodeAt(from);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) return false;
  let humpFrom = from;
  let humps = 0;
  let broke = false;
  for (let i = from; i <= to; i += 1) {
    if (i < to) {
      const code = text.charCodeAt(i);
      const upper = code >= 65 && code <= 90;
      const lower = code >= 97 && code <= 122;
      if (!upper && !lower) return false;
      if (i > from && upper) {
        if (!dictionaryWordAt(text, humpFrom, i, true)) return false;
        humps += 1;
        humpFrom = i;
        broke = true;
      }
      continue;
    }
    if (!broke || !dictionaryWordAt(text, humpFrom, to, true)) return false;
    humps += 1;
  }
  return humps >= 2;
}

/**
 * camelCase with an all-caps hump (`parseJSON` is `parse` + `JSON`).
 * A run of capitals is one hump. When that run is followed by a lowercase
 * word, the last capital starts the word (`JSONParser` is `JSON` + `Parser`).
 * Every hump is a path word, and at least one hump is two or more capitals,
 * so `HomeView` stays on the single-capital check. One pass over a segment
 * already inside the 48-character tail.
 */
function acronymHumps(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 4 || n > 48) return false;
  const first = text.charCodeAt(from);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) return false;
  let humps = 0;
  let acronym = false;
  let i = from;
  const take = (humpFrom: number, humpTo: number): boolean => {
    if (humpTo - humpFrom < 2) return false;
    if (!dictionaryWordAt(text, humpFrom, humpTo, true)) return false;
    let uppers = 0;
    for (let k = humpFrom; k < humpTo; k += 1) {
      if (text.charCodeAt(k) >= 65 && text.charCodeAt(k) <= 90) uppers += 1;
    }
    if (uppers >= 2) acronym = true;
    humps += 1;
    return true;
  };
  while (i < to) {
    const code = text.charCodeAt(i);
    if (code >= 97 && code <= 122) {
      const start = i;
      i += 1;
      while (i < to) {
        const next = text.charCodeAt(i);
        if (next < 97 || next > 122) break;
        i += 1;
      }
      if (!take(start, i)) return false;
      continue;
    }
    if (code < 65 || code > 90) return false;
    const start = i;
    i += 1;
    while (i < to) {
      const next = text.charCodeAt(i);
      if (next < 65 || next > 90) break;
      i += 1;
    }
    const followedByLower = i < to && text.charCodeAt(i) >= 97 && text.charCodeAt(i) <= 122;
    if (followedByLower && i - start >= 2) {
      if (!take(start, i - 1)) return false;
      const wordStart = i - 1;
      i += 1;
      while (i < to) {
        const next = text.charCodeAt(i);
        if (next < 97 || next > 122) break;
        i += 1;
      }
      if (!take(wordStart, i)) return false;
      continue;
    }
    if (!take(start, i)) return false;
  }
  return humps >= 2 && acronym;
}

/** `Dockerfile` or `dockerfile`. `Makefile` is not this name. */
function knownFilename(text: string, from: number, to: number): boolean {
  if (to - from !== 10) return false;
  const word = 'dockerfile';
  const first = text.charCodeAt(from);
  if (first !== 68 && first !== 100) return false;
  for (let i = 1; i < 10; i += 1) {
    if (text.charCodeAt(from + i) !== word.charCodeAt(i)) return false;
  }
  return true;
}

/** `LICENSE` exactly. `license` and `License` are not this name. */
function knownLicense(text: string, from: number, to: number): boolean {
  if (to - from !== 7) return false;
  const word = 'LICENSE';
  for (let i = 0; i < 7; i += 1) {
    if (text.charCodeAt(from + i) !== word.charCodeAt(i)) return false;
  }
  return true;
}

/**
 * Lowercase name of 4 to 7 letters (`pramod`) used only when another
 * segment is a path word. A vowel is required. `q` must be followed by
 * `u`. A consonant run longer than 2 stays signature, so `abcdefgh`
 * and `bcdf` do not pass. Three letters stay out, so `nav` is not a
 * name. Digits and capitals stay out.
 */
function looseName(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 4 || n > 7) return false;
  let vowels = 0;
  let cluster = 0;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 97 || code > 122) return false;
    const vowel = code === 97 || code === 101 || code === 105 || code === 111 || code === 117;
    if (vowel) {
      vowels += 1;
      cluster = 0;
      continue;
    }
    cluster += 1;
    if (cluster > 2) return false;
    if (code === 113) {
      const next = i + 1 < to ? text.charCodeAt(i + 1) : 0;
      if (next !== 117) return false;
    }
  }
  return vowels >= 1;
}

/** True when the tail is only `Dockerfile`, `dockerfile`, or `LICENSE`, optional `+` and one slash. */
function isKnownExtensionlessTail(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  for (let k = i; k < segEnd; k += 1) {
    if (text.charCodeAt(k) === 47) return false;
  }
  return knownFilename(text, i, segEnd) || knownLicense(text, i, segEnd);
}

/** Lowercase letters only, length in [min, max]. */
function isLowercaseLetters(text: string, from: number, to: number, min: number, max: number): boolean {
  const n = to - from;
  if (n < min || n > max) return false;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 97 || code > 122) return false;
  }
  return true;
}

/**
 * A 3-letter filename word (`nav`, `bar`, `get`). It is a hump inside
 * `NavBar` or `getUser`. Alone it is a signature fragment. It is a
 * directory word only when another segment grounds the path.
 */
function isShortFilenameWord(text: string, from: number, to: number): boolean {
  if (to - from !== 3) return false;
  let lower = '';
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 97 || code > 122) return false;
    lower += String.fromCharCode(code);
  }
  return FILENAME_WORDS.has(lower);
}

/**
 * A glued path whose segments are path words, one lowercase name, or
 * one- and two-letter lowercase pieces. A name stays only when some
 * other segment is a path word (`/Users/pramod/repo/x`). A path of only
 * short pieces (`/ab/cd/ef`) stays out. A 3-letter filename word stays
 * when another segment grounds the path (`/o/nav`, `/lib/nav`). One pass
 * over the tail.
 */
function ordinaryAnchoredPath(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  let segFrom = i;
  let names = 0;
  let anchors = 0;
  let shorts = 0;
  let shortWords = 0;
  let any = false;
  const take = (from: number, to: number): boolean => {
    if (to <= from) return false;
    any = true;
    if (
      dictionaryWordAt(text, from, to) ||
      ordinaryWordAt(text, from, to) ||
      segmentIsAtom(text, from, to) ||
      dictionaryHumps(text, from, to) ||
      knownFilename(text, from, to) ||
      camelHumpsAreAtoms(text, from, to) ||
      acronymHumps(text, from, to)
    ) {
      anchors += 1;
      return true;
    }
    if (looseName(text, from, to)) {
      names += 1;
      return true;
    }
    if (isShortFilenameWord(text, from, to)) {
      shortWords += 1;
      return true;
    }
    if (to - from > 2) return false;
    for (let q = from; q < to; q += 1) {
      const code = text.charCodeAt(q);
      if (code < 97 || code > 122) return false;
    }
    shorts += 1;
    return true;
  };
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (!take(segFrom, k)) return false;
    segFrom = k + 1;
  }
  if (!any || names > 1) return false;
  // `nav` needs a real neighbor. `/nav` has none. `/o/nav` has `o`.
  if (shortWords > 0 && anchors < 1 && shorts < 1) return false;
  if (anchors < 1 && shortWords < 1) return false;
  if (anchors < 1) return shortWords > 0 && shorts > 0 && names === 0;
  return true;
}

/**
 * Title-case directory names that are not already path atoms
 * (`Views`, `Sources`, `Models`). All-caps and a lowercase copy stay out,
 * so a signature fragment is not kept just because the letters match.
 */
const CAPITAL_DIRECTORIES = new Set(['models', 'sources', 'views']);

function capitalDirectorySegment(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 3 || n > 16) return false;
  const first = text.charCodeAt(from);
  if (first < 65 || first > 90) return false;
  let lower = String.fromCharCode(first + 32);
  for (let i = from + 1; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 97 || code > 122) return false;
    lower += String.fromCharCode(code);
  }
  return CAPITAL_DIRECTORIES.has(lower);
}

function filenameSegment(text: string, from: number, to: number): boolean {
  return (
    lowercaseFilenameSegment(text, from, to) ||
    titledFilenameSegment(text, from, to) ||
    ordinaryWordAt(text, from, to) ||
    hyphenatedFilenameSegment(text, from, to) ||
    camelHumpsAreAtoms(text, from, to) ||
    dictionaryWordAt(text, from, to) ||
    dictionaryHumps(text, from, to) ||
    knownFilename(text, from, to) ||
    acronymHumps(text, from, to)
  );
}

/**
 * True when [at, segEnd) is a filename path. Every segment is a filename.
 * Uppercase is allowed for a single segment (`/App`, `/README`) or when a
 * directory segment has 2 or more lowercase letters (`/src/App`,
 * `/docs/README`, `/Src/lib/App`), or is a title-case directory name
 * (`Views`, `Sources`, `Models`). One pass over a tail already capped at
 * 48 characters. No slice of the segment.
 */
function realFilenameTail(text: string, at: number, segEnd: number, sawUpper: boolean): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  const segs: Array<{ from: number; to: number }> = [];
  let segFrom = i;
  for (let k = i; k <= segEnd; k += 1) {
    if (k === segEnd || text.charCodeAt(k) === 47) {
      segs.push({ from: segFrom, to: k });
      segFrom = k + 1;
    }
  }
  if (segs.length === 0) return false;
  for (let s = 0; s < segs.length; s += 1) {
    const seg = segs[s];
    if (seg.to <= seg.from || !filenameSegment(text, seg.from, seg.to)) return false;
  }
  if (!sawUpper || segs.length === 1) return true;
  for (let s = 0; s < segs.length - 1; s += 1) {
    const seg = segs[s];
    if (ordinaryWordAt(text, seg.from, seg.to)) return true;
    if (capitalDirectorySegment(text, seg.from, seg.to)) return true;
    if (!lowercaseFilenameSegment(text, seg.from, seg.to)) continue;
    let letters = 0;
    for (let k = seg.from; k < seg.to; k += 1) {
      const code = text.charCodeAt(k);
      if (code >= 97 && code <= 122) letters += 1;
    }
    if (letters >= 2) return true;
  }
  return false;
}

/**
 * True when some segment is a path atom or an ordinary word.
 * One pass over a tail already capped at 48 characters.
 */
function tailIsGrounded(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  let segFrom = i;
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (k > segFrom) {
      if (ordinaryWordAt(text, segFrom, k) || segmentIsAtom(text, segFrom, k)) return true;
      let pieceFrom = segFrom;
      for (let p = segFrom; p <= k; p += 1) {
        const boundary = p === k || text.charCodeAt(p) === 45 || text.charCodeAt(p) === 95;
        if (!boundary) continue;
        if (p > pieceFrom && (ordinaryWordAt(text, pieceFrom, p) || segmentIsAtom(text, pieceFrom, p))) {
          return true;
        }
        pieceFrom = p + 1;
      }
    }
    segFrom = k + 1;
  }
  return false;
}

/**
 * One segment of a 3-to-7 character tail. A piece of 3 or more letters
 * must be a path atom or an ordinary word (`App`, `README`, `src`).
 * One or two lowercase letters stay (`ab`, `a`, `b`), including the
 * pieces of `my-app`. A titled fragment that is not a path word
 * (`Ahs`, `Qow`) does not.
 */
function shortSegmentIsReal(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 1) return false;
  if (n < 3) {
    for (let i = from; i < to; i += 1) {
      const code = text.charCodeAt(i);
      if (code < 97 || code > 122) return false;
    }
    return true;
  }
  if (
    segmentIsAtom(text, from, to) ||
    ordinaryWordAt(text, from, to) ||
    camelHumpsAreAtoms(text, from, to) ||
    dictionaryWordAt(text, from, to) ||
    dictionaryHumps(text, from, to) ||
    knownFilename(text, from, to) ||
    capitalDirectorySegment(text, from, to) ||
    acronymHumps(text, from, to)
  ) {
    return true;
  }
  let pieceFrom = from;
  let sawJoin = false;
  for (let p = from; p <= to; p += 1) {
    const code = p < to ? text.charCodeAt(p) : 0;
    if (p !== to && code !== 45 && code !== 95) continue;
    if (p !== to) sawJoin = true;
    if (p <= pieceFrom) return false;
    const len = p - pieceFrom;
    if (len >= 3) {
      if (!segmentIsAtom(text, pieceFrom, p) && !ordinaryWordAt(text, pieceFrom, p)) return false;
    } else {
      for (let q = pieceFrom; q < p; q += 1) {
        const pieceCode = text.charCodeAt(q);
        if (pieceCode < 97 || pieceCode > 122) return false;
      }
    }
    pieceFrom = p + 1;
  }
  return sawJoin;
}

/** True when every segment of a short tail is a real path piece. */
function shortTailWordsAreReal(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  let segFrom = i;
  let any = false;
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (k <= segFrom) return false;
    any = true;
    if (!shortSegmentIsReal(text, segFrom, k)) return false;
    segFrom = k + 1;
  }
  return any;
}

/**
 * True when every segment is a path atom or an ordinary word.
 * One- and two-letter pieces do not count, so `/ab/cd/ef` stays out
 * and `/src/index` stays.
 */
function everySegmentIsPathWord(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  let segFrom = i;
  let any = false;
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (k <= segFrom) return false;
    any = true;
    if (!segmentIsAtom(text, segFrom, k) && !ordinaryWordAt(text, segFrom, k)) return false;
    segFrom = k + 1;
  }
  return any;
}

/**
 * True when this segment lets a 3-letter filename word stay.
 * An atom, an ordinary word, a 1–2 letter piece, or a 4–7 letter
 * lowercase word grounds the path. `nav` does not ground itself.
 */
function segmentAllowsShortWord(text: string, from: number, to: number): boolean {
  if (segmentIsAtom(text, from, to) || ordinaryWordAt(text, from, to)) return true;
  if (dictionaryWordAt(text, from, to) || dictionaryHumps(text, from, to)) return true;
  if (camelHumpsAreAtoms(text, from, to) || acronymHumps(text, from, to)) return true;
  if (knownFilename(text, from, to) || capitalDirectorySegment(text, from, to)) return true;
  if (isLowercaseLetters(text, from, to, 1, 2) || isLowercaseLetters(text, from, to, 4, 7)) return true;
  let pieceFrom = from;
  let saw = false;
  let pieceAllows = false;
  for (let p = from; p <= to; p += 1) {
    const code = p < to ? text.charCodeAt(p) : 0;
    if (p !== to && code !== 45 && code !== 95) continue;
    if (p !== to) saw = true;
    if (p <= pieceFrom) return false;
    if (
      segmentIsAtom(text, pieceFrom, p) ||
      ordinaryWordAt(text, pieceFrom, p) ||
      isLowercaseLetters(text, pieceFrom, p, 1, 2) ||
      isLowercaseLetters(text, pieceFrom, p, 4, 7)
    ) {
      pieceAllows = true;
    }
    pieceFrom = p + 1;
  }
  return saw && pieceAllows;
}

/** `_` or `-` pieces of real words (`node_modules` is `node` + `modules`). */
function joinedRealPieces(text: string, from: number, to: number, allowShort: boolean): boolean {
  let saw = false;
  let pieceFrom = from;
  const pieceOk = (start: number, end: number): boolean => {
    if (end <= start) return false;
    if (isLowercaseLetters(text, start, end, 1, 2)) return true;
    if (isLowercaseLetters(text, start, end, 4, 7)) return true;
    if (segmentIsAtom(text, start, end) || ordinaryWordAt(text, start, end)) return true;
    if (allowShort && isShortFilenameWord(text, start, end)) return true;
    return false;
  };
  for (let p = from; p <= to; p += 1) {
    const code = p < to ? text.charCodeAt(p) : 0;
    if (p !== to && code !== 45 && code !== 95) continue;
    if (p !== to) saw = true;
    if (!pieceOk(pieceFrom, p)) return false;
    pieceFrom = p + 1;
  }
  return saw;
}

function longSegmentOk(text: string, from: number, to: number, allowShort: boolean): boolean {
  if (shortSegmentIsReal(text, from, to)) return true;
  if (isLowercaseLetters(text, from, to, 4, 7)) return true;
  if (allowShort && isShortFilenameWord(text, from, to)) return true;
  return joinedRealPieces(text, from, to, allowShort);
}

/**
 * Every segment is a real path word. One- and two-letter lowercase
 * pieces stay (`a`, `b`, `ab`). A segment of 4 to 7 lowercase letters
 * is a real word (`redact`). A joined segment stays when each piece is
 * (`node_modules`). A 3-letter filename word (`nav`, `bar`, `get`) stays
 * when another segment grounds the path, so `/lib/nav` and `/src/nav/x`
 * stay and `/nav` stays out. `my-app` stays. Two passes over a tail
 * already capped at 48 characters.
 */
function everySegmentIsRealWord(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  let segFrom = i;
  let any = false;
  let allowShort = false;
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (k <= segFrom) return false;
    any = true;
    if (segmentAllowsShortWord(text, segFrom, k)) allowShort = true;
    segFrom = k + 1;
  }
  if (!any) return false;
  segFrom = i;
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (!longSegmentOk(text, segFrom, k, allowShort)) return false;
    segFrom = k + 1;
  }
  return true;
}

function isRepeatedRun(text: string, from: number, to: number): boolean {
  const first = text.charCodeAt(from);
  for (let i = from + 1; i < to; i += 1) {
    if (text.charCodeAt(i) !== first) return false;
  }
  return true;
}

/**
 * RSA short tail that is a path, not the rest of the signature.
 * One pass over [at, segEnd) for the run rules, then one pass for the
 * filename shape when that is the only thing that can keep the tail.
 * The caller already caps that span at `RSA_GLUED_PATH_MAX`.
 *
 * A run of 8 or more is signature unless every character is the same,
 * or the run is an ordinary path word. A tail that is one repeated
 * character stays (`/${'a'.repeat(46)}/` is 48).
 *
 * A tail of 3 to 7 characters, measured without the leading `/` or `+`,
 * stays only when a filename extension follows (2 to 4 letters, or
 * `.swift`), the tail is a filename, and every segment of 3 or more
 * letters is a path word. `/Ahsqowx` is 7, not 8. `/ab`, `/a/b`, `/App`,
 * and `/README` stay. `/Ahs`, `/Qow`, `/hnw/x`, `/Ahsqowx`, `/OHALMQO`,
 * and `/QZXWVKT` do not: those segments are not path words, and the check
 * does not use a digit. A tail with an uppercase letter uses that same
 * word check even when it is longer than 7. Path words include atoms,
 * ordinary directory words, and filename words (`user`, `profile`,
 * `repo`, `get`, `service`). PascalCase and camelCase humps of those
 * words stay (`UserProfile`, `formatDate`, `MyClass`, `HomeView`,
 * `getUser`, `UserService`, `UserController`). `Dockerfile`
 * stays with no extension. One lowercase name of 3 to 7 letters stays
 * when another segment is a path word (`/Users/pramod/repo/x`).
 * `/src/App`, `/docs/README`, `/Src/lib/App`, `/src/components/Button`,
 * and `/src/hooks/useAuth` stay. `/Jrq/kl/x` and `/qb/Zrh/x` do not.
 * An extension alone does not keep the tail: `/Qx7.ts`, `/aB3k9.md`,
 * `/XYZ12.md`, and `/K.ts` are signature. `/My.ts` is signature.
 *
 * A longer lowercase tail stays when that extension follows, every segment
 * is a real path word, and some segment is a path atom or an ordinary word.
 * A segment of 4 to 7 lowercase letters is a real word (`redact` in
 * `/src/lib/redact`). A word of 8 or more letters is real only when it is
 * an ordinary directory word. A joined segment whose pieces are 4 to 7
 * letters stays when another segment grounds the path
 * (`/node_modules/pkg/index`). A 3-letter filename word (`nav`, `bar`,
 * `get`) is a directory word when another segment grounds the path, so
 * `/lib/nav`, `/o/nav`, `/src/nav/x`, `/src/bar/index`, and `/src/nav`
 * stay. Alone, `/nav`, `/bar`, and `/get` stay signature, and so do
 * `/xyz` and `/abc/def`. `/src/app.ts`, `/src/utilities/format.ts`,
 * `/packages/frontend/main.ts`, `/internal/handlers/api.go`,
 * `/home/runner/work/a/b.ts`, and `/scripts/deploy.sh` stay. A deep
 * project path stays too, with or without a leading slash:
 * `src/main/java/com/example/service/UserService.java` and
 * `app/Http/Controllers/Admin/UserController.php`. The same tail
 * stays with no extension when every segment is a path word: `/src/index`
 * and `/bin/run`. `/ab/cd/ef`, `/tonaxc/u1`, and `/abcdefgh/x.ts` are
 * signature. `/Makefile` and `/AbCdEfGh/x` have no filename extension.
 * A 3-letter directory word `bin` (`/Bin`, `/bin`, `/BIN`, `.bin`) does
 * not ground a path by itself. Another known directory, a joined repo
 * segment such as `node_modules`, or a deeper path has to ground it, so
 * `/bin/cli`, `/bin/run`, `src/bin/main`, and `node_modules/.bin/tsc` stay
 * and `/Bin` does not.
 */
/**
 * `bin`, `Bin`, `BIN`, or `.bin`. A directory word, not a filename.
 * One pass over a segment already inside the 48-character tail.
 */
function isBinDirSegment(text: string, from: number, to: number): boolean {
  let start = from;
  if (start < to && text.charCodeAt(start) === 46) start += 1;
  if (to - start !== 3) return false;
  const word = 'bin';
  for (let i = 0; i < 3; i += 1) {
    let code = text.charCodeAt(start + i);
    if (code >= 65 && code <= 90) code += 32;
    if (code !== word.charCodeAt(i)) return false;
  }
  return true;
}

/**
 * A segment other than `bin` that grounds a path: an atom, an ordinary
 * word, a path-word hump, a known filename, or a joined name
 * (`node_modules`). A file extension is not part of the name. One pass
 * over a segment already inside the 48-character tail.
 */
function segmentGroundsPath(text: string, from: number, to: number): boolean {
  if (to <= from || isBinDirSegment(text, from, to)) return false;
  let nameFrom = from;
  let nameTo = to;
  if (text.charCodeAt(nameFrom) === 46) {
    nameFrom += 1;
    if (nameFrom >= nameTo) return false;
  }
  let dot = -1;
  for (let i = nameFrom; i < nameTo; i += 1) {
    if (text.charCodeAt(i) === 46) dot = i;
  }
  if (dot > nameFrom) {
    const ext = nameTo - dot - 1;
    let letters = true;
    for (let i = dot + 1; i < nameTo; i += 1) {
      if (!isLetterCode(text.charCodeAt(i))) letters = false;
    }
    if (letters && ext >= 2 && ext <= 4) nameTo = dot;
  }
  if (nameTo <= nameFrom || isBinDirSegment(text, nameFrom, nameTo)) return false;
  if (segmentIsAtom(text, nameFrom, nameTo) || ordinaryWordAt(text, nameFrom, nameTo)) return true;
  if (dictionaryWordAt(text, nameFrom, nameTo) || dictionaryHumps(text, nameFrom, nameTo)) return true;
  if (camelHumpsAreAtoms(text, nameFrom, nameTo) || acronymHumps(text, nameFrom, nameTo)) return true;
  if (knownFilename(text, nameFrom, nameTo) || capitalDirectorySegment(text, nameFrom, nameTo)) return true;
  return joinedRealPieces(text, nameFrom, nameTo, false);
}

/**
 * True when `bin` is a segment and no other segment grounds the path.
 * `/Bin` and `/o/bin` are that shape. `/bin/cli`, `/src/bin`, and
 * `/bin/run` are not. One pass over a tail already capped at 48 characters.
 */
function binDirNeedsMoreGround(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  let segFrom = i;
  let sawBin = false;
  let grounds = 0;
  for (let k = i; k <= segEnd; k += 1) {
    if (k !== segEnd && text.charCodeAt(k) !== 47) continue;
    if (k <= segFrom) return false;
    if (isBinDirSegment(text, segFrom, k)) sawBin = true;
    else if (segmentGroundsPath(text, segFrom, k)) grounds += 1;
    segFrom = k + 1;
  }
  return sawBin && grounds < 1;
}

/**
 * A 3-letter path atom (`src`, `app`, `bin`, `lib`). Any letter case.
 * A leading dot (`.bin`) is not part of the name. One pass over a
 * segment already inside the 48-character tail.
 */
function isThreeLetterAtomName(text: string, from: number, to: number): boolean {
  let start = from;
  if (start < to && text.charCodeAt(start) === 46) start += 1;
  if (to - start !== 3) return false;
  let word = '';
  for (let i = start; i < to; i += 1) {
    let code = text.charCodeAt(i);
    if (code >= 65 && code <= 90) code += 32;
    else if (code < 97 || code > 122) return false;
    word += String.fromCharCode(code);
  }
  return PATH_ATOMS.has(word);
}

/**
 * One segment, and that segment is a 3-letter directory atom
 * (`/Src`, `/App`, `/Bin`, `/lib`). The same second ground `bin` needs:
 * `/Src.ts` and `/App.ts` stay masked, and `/src/app`, `src/App`, and
 * `app/src/index` have another segment so they stay. One pass over a
 * tail already capped at 48 characters.
 */
function loneThreeLetterDir(text: string, at: number, segEnd: number): boolean {
  let i = at;
  if (i < segEnd && text.charCodeAt(i) === 43) i += 1;
  if (i < segEnd && text.charCodeAt(i) === 47) i += 1;
  if (i >= segEnd) return false;
  for (let k = i; k < segEnd; k += 1) {
    if (text.charCodeAt(k) === 47) return false;
  }
  return isThreeLetterAtomName(text, i, segEnd);
}

/**
 * A project path glued on with no leading `/` or `+`
 * (`src/main/java/com/example/service/UserService`). The first character
 * is a letter and a later character is `/`. A `+` is still signature
 * alphabet. One pass over a tail already capped at 48 characters.
 */
function isUnslashedDeepPath(text: string, at: number, segEnd: number): boolean {
  if (at >= segEnd || !isLetterCode(text.charCodeAt(at))) return false;
  let slash = false;
  for (let k = at; k < segEnd; k += 1) {
    const code = text.charCodeAt(k);
    if (code === 47) {
      slash = true;
      continue;
    }
    if (code === 43) return false;
    if (!isBase64UrlChar(code)) return false;
  }
  return slash;
}

function rsaShortTailIsClearPath(text: string, at: number, segEnd: number): boolean {
  if (binDirNeedsMoreGround(text, at, segEnd)) return false;
  if (loneThreeLetterDir(text, at, segEnd)) return false;
  if (
    !isClearGluedPath(text, at, segEnd) &&
    !isKnownExtensionlessTail(text, at, segEnd) &&
    !isUnslashedDeepPath(text, at, segEnd)
  ) return false;
  const ext = filenameExtensionAfter(text, segEnd);
  const inclusiveLen = segEnd - at;
  let bodyFrom = at;
  if (bodyFrom < segEnd && text.charCodeAt(bodyFrom) === 43) bodyFrom += 1;
  if (bodyFrom < segEnd && text.charCodeAt(bodyFrom) === 47) bodyFrom += 1;
  const bodyLen = segEnd - bodyFrom;
  let internalSlash = false;
  let runStart = -1;
  let runs = 0;
  let longRun = false;
  let sawUpper = false;
  const finish = (end: number): boolean => {
    const len = end - runStart;
    if (len >= 8) {
      if (isRepeatedRun(text, runStart, end)) longRun = true;
      else if (
        !ordinaryWordAt(text, runStart, end) &&
        !dictionaryWordAt(text, runStart, end) &&
        !dictionaryHumps(text, runStart, end) &&
        !knownFilename(text, runStart, end) &&
        !acronymHumps(text, runStart, end)
      ) return false;
    }
    runs += 1;
    return true;
  };
  for (let k = at; k < segEnd; k += 1) {
    const code = text.charCodeAt(k);
    if (k >= bodyFrom && code === 47) internalSlash = true;
    if (code >= 65 && code <= 90) sawUpper = true;
    if (isAsciiAlnum(code)) {
      if (runStart < 0) runStart = k;
      continue;
    }
    if (runStart >= 0) {
      if (!finish(k)) return false;
      runStart = -1;
    }
  }
  if (runStart >= 0 && !finish(segEnd)) return false;
  if (longRun && runs !== 1) return false;
  if (longRun && runs === 1) return true;
  // The leading `/` or `+` is not part of the length. `/Ahsqowx` is 7.
  // An internal slash is not that case, so `/bin/run` stays on the long path.
  const short =
    (!internalSlash && bodyLen >= 2 && bodyLen <= 7) ||
    (inclusiveLen >= 3 && inclusiveLen <= 7);
  if (short || sawUpper) {
    if (!ext) {
      if (isKnownExtensionlessTail(text, at, segEnd)) return true;
      return false;
    }
    if (!realFilenameTail(text, at, segEnd, sawUpper)) return false;
    if (!shortTailWordsAreReal(text, at, segEnd)) {
      if (ordinaryAnchoredPath(text, at, segEnd)) return true;
      return false;
    }
    return true;
  }
  if (inclusiveLen < 8) return false;
  if (!realFilenameTail(text, at, segEnd, sawUpper)) return false;
  if (!ext) return everySegmentIsPathWord(text, at, segEnd);
  if (!everySegmentIsRealWord(text, at, segEnd)) return false;
  return tailIsGrounded(text, at, segEnd);
}

/**
 * Index where a base64url JWT ends and a glued path begins.
 * The signature is the longest base64url run. `/` and `+` are not in that
 * alphabet, so a path can sit outside the token. A header or payload that
 * already uses `+`, `/`, or `=` is standard base64; the signature may use
 * those too, and this split stays out so signature bytes are not left behind.
 * An unpadded standard-base64 signature also contains `+` or `/`. Splitting
 * at the first one leaves the rest of the signature in the clear. The split
 * is allowed only when the base64url prefix is the longest unpadded length
 * for this token's own `alg` that the third segment actually reaches.
 * A `+` or `/` at 342 inside a 512 or 683 RSA signature stays inside the
 * mask. The same rule keeps Ed448 (152) from splitting at the Ed25519
 * length (86). An RS* or PS* run that is longer than a known RSA length
 * and does not end on one (511, 600, 682, and any other non-exact length)
 * is not split at 342 or 512. The whole run is redacted. A short glued
 * path after an exact RSA base64url length still splits when the tail is
 * a clear path. A run of 8 or more stays inside the mask unless it is
 * one repeated character or an ordinary path word. A tail of 3 to 7
 * characters, measured without the leading `/` or `+`, splits only when
 * a 2-to-4 letter extension follows and every segment of 3 or more
 * letters is a path word (`/README.md`, `/ab.ts`). A lone 3-letter
 * directory atom (`/App.md`, `/Src.ts`) stays inside the mask. A 7-letter
 * segment is that short tail. `/Ahs.ts`, `/Qow.md`, `/hnw/x.ts`,
 * `/Ahsqowx.ts`, `/OHALMQO.ts`, and `/QZXWVKT.md` stay inside the mask.
 * A tail with an uppercase letter splits only when that extension follows
 * and the same word check passes (`/src/App.tsx`, `/docs/README.md`,
 * `/src/components/Button.tsx`, `/src/hooks/useAuth.ts`). `/Jrq/kl/x.ts`
 * and `/qb/Zrh/x.ts` stay inside the mask. A longer lowercase tail splits
 * when that extension follows and the path is grounded
 * (`/home/runner/work/a/b.ts`, `/scripts/deploy.sh`,
 * `/packages/frontend/main.ts`), or when every segment is a path word
 * (`/src/index`, `/bin/run`). An extension alone does not split, so
 * `/Qx7.ts`, `/aB3k9.md`, `/XYZ12.md`, and `/K.ts` stay inside the mask.
 * `/ab/cd/ef` and `/tonaxc/u1` stay inside the mask. A `/` or `+` at
 * 342, 512, or 683 cannot leave that tail in the clear. An odd run
 * whose tail only looks like a path is redacted whole.
 * An unknown or undecodable `alg` never splits. Returns -1 when the
 * boundary is not clear.
 * A filename with no slash (`UserProfile.tsx`, `formatDate.ts`,
 * `package.json`, `Dockerfile`) is still base64url, so the measured run
 * is longer than an exact RSA length. The suffix is kept when it is an
 * ordinary filename and, unless it is `Dockerfile`, a filename extension
 * follows. A random mixed-case suffix stays inside the mask. The header
 * is decoded only after that suffix matches. One pass over the suffix,
 * which is capped at 48 characters.
 */
function rsaUngluedFilenameCut(
  text: string,
  sigStart: number,
  sigEnd: number,
  sigLen: number,
): number {
  let best = -1;
  for (let s = 0; s < SIG_RSA.length; s += 1) {
    const url = SIG_RSA[s].url;
    const tailLen = sigLen - url;
    if (tailLen < 4 || tailLen > RSA_GLUED_PATH_MAX) continue;
    const at = sigStart + url;
    if (at <= sigStart || at >= sigEnd) continue;
    if (knownFilename(text, at, sigEnd)) {
      best = at;
      continue;
    }
    // A lone 3-letter directory atom (`Src.ts`, `App.ts`) is the same
    // fragment as `/Src.ts`. It stays inside the mask.
    if (isThreeLetterAtomName(text, at, sigEnd)) continue;
    if (!filenameExtensionAfter(text, sigEnd)) continue;
    if (dictionaryWordAt(text, at, sigEnd) || dictionaryHumps(text, at, sigEnd) || acronymHumps(text, at, sigEnd)) {
      best = at;
    }
  }
  return best;
}

/**
 * Cut where an exact RSA signature ends and a deep path begins, when the
 * first segment was absorbed into the base64url run
 * (`src/main/java/...`, `app/Http/Controllers/...`). The `/` is not
 * base64url, so the measured run is longer than 342, 512, or 683. The
 * tail from that exact length must be a clear path of at most 48
 * characters. The longest matching length wins, so a 512 signature is
 * not split at 342. Shape is checked before the header is decoded.
 * Returns -1 when the tail is not a path.
 */
function rsaDeepPathCut(
  text: string,
  cursor: number,
  dot1: number,
  dot2: number,
  slashAt: number,
  end: number,
  mode: JwtMaskMode,
): number {
  if (slashAt >= end || text.charCodeAt(slashAt) !== 47) return -1;
  const sigStart = dot2 + 1;
  let best = -1;
  for (let s = 0; s < SIG_RSA.length; s += 1) {
    const url = SIG_RSA[s].url;
    const cut = sigStart + url;
    if (cut <= sigStart || cut >= slashAt) continue;
    const tailLen = end - cut;
    if (tailLen < 4 || tailLen > RSA_GLUED_PATH_MAX) continue;
    if (!isUnslashedDeepPath(text, cut, end)) continue;
    if (!filenameExtensionAfter(text, end)) continue;
    if (!rsaShortTailIsClearPath(text, cut, end)) continue;
    best = cut;
  }
  if (best < 0) return -1;
  const header = text.slice(cursor, dot1);
  if (signatureSizesForAlg(jwtHeaderInfo(header, mode).alg) !== SIG_RSA) return -1;
  if (!isJwtToken(text.slice(cursor, best), mode)) return -1;
  return best;
}

/**
 * A filename after `/.bin/`. `tsc` and `cli.js` stay. A second dot, a
 * non-letter extension, or a run longer than 16 characters is signature.
 * One pass, bounded by the caller.
 */
function dottedBinFileOk(text: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 1 || n > 16) return false;
  let dot = -1;
  for (let i = from; i < to; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 46) {
      if (dot >= 0) return false;
      dot = i;
      continue;
    }
    if (!isAsciiAlnum(code)) return false;
  }
  if (dot < 0) return true;
  if (dot === from || dot === to - 1) return false;
  const ext = to - dot - 1;
  if (ext < 2 || ext > 4) return false;
  for (let i = dot + 1; i < to; i += 1) {
    if (!isLetterCode(text.charCodeAt(i))) return false;
  }
  return true;
}

/**
 * True when `marker` matches at `at`, with `bin` in any letter case.
 * `marker` is `/.bin/`. One pass over those six characters.
 */
function dottedBinMarkerAt(text: string, at: number): boolean {
  const marker = '/.bin/';
  if (at + marker.length > text.length) return false;
  for (let k = 0; k < marker.length; k += 1) {
    let code = text.charCodeAt(at + k);
    if (k >= 2 && k <= 4 && code >= 65 && code <= 90) code += 32;
    if (code !== marker.charCodeAt(k)) return false;
  }
  return true;
}

/**
 * Cut where an exact RSA signature ends and `node_modules/.bin/tsc`
 * begins. The first segment grounds the path. An optional `/` may sit
 * in front of it (`/node_modules/.bin/tsc`). `/.bin/` follows that
 * segment, then a short filename. The JWT segment stops on the dot, so
 * this scan reads at most `RSA_GLUED_PATH_MAX` characters past the cut.
 * A filename that runs into that cap is still signature. Returns -1 when
 * the tail is not that path. Shape only: the caller checks the header.
 */
function rsaDottedBinCut(text: string, sigStart: number): number {
  let best = -1;
  for (let s = 0; s < SIG_RSA.length; s += 1) {
    const at = sigStart + SIG_RSA[s].url;
    if (at <= sigStart || at >= text.length) continue;
    const limit = Math.min(text.length, at + RSA_GLUED_PATH_MAX);
    let dirFrom = at;
    if (text.charCodeAt(dirFrom) === 47) dirFrom += 1;
    if (dirFrom >= limit) continue;
    let dirTo = dirFrom;
    while (dirTo < limit) {
      const code = text.charCodeAt(dirTo);
      if (code === 47) break;
      if (!isAsciiAlnum(code) && code !== 95 && code !== 45) break;
      dirTo += 1;
    }
    if (dirTo === dirFrom || dirTo >= limit || text.charCodeAt(dirTo) !== 47) continue;
    if (!segmentGroundsPath(text, dirFrom, dirTo)) continue;
    if (!dottedBinMarkerAt(text, dirTo)) continue;
    const nameFrom = dirTo + 6;
    if (nameFrom > limit) continue;
    let nameTo = nameFrom;
    while (nameTo < limit) {
      const code = text.charCodeAt(nameTo);
      if (!isAsciiAlnum(code) && code !== 46 && code !== 95 && code !== 45) break;
      nameTo += 1;
    }
    if (nameTo === nameFrom || !dottedBinFileOk(text, nameFrom, nameTo)) continue;
    if (nameTo === limit && limit < text.length) continue;
    best = at;
  }
  return best;
}

/**
 * Cut where an exact signature for this token's own `alg` ends and a
 * clear path begins. The signature may contain standard-base64 `+` or
 * `/`, so the base64url scan stops inside it. An unslashed path
 * (`src/App.tsx`, `app/src/index.ts`) is included for every alg, not
 * only RSA. The longest exact length wins. A `+` or `/` at a shorter
 * length inside a longer signature is not a split: the tail is longer
 * than a glued path, or it is not a clear path. Ed448 is not split at
 * the Ed25519 length. An odd run (511, 600, 682) is not split at the
 * next exact length when that cut falls inside a short clear path that
 * already started at the base64url stop (`B`×511 then `/Users/...`
 * must not split at 512). Shape is checked before the header is decoded.
 * Returns -1 when no tail is a clear path.
 */
function exactAlgPathCut(
  text: string,
  cursor: number,
  dot1: number,
  dot2: number,
  end: number,
  mode: JwtMaskMode,
  urlEnd: number,
): number {
  const sigStart = dot2 + 1;
  // `urlEnd` is where the base64url scan stopped. When that stop is
  // itself a short clear path, a later exact length is inside the path.
  const stoppedTail = end - urlEnd;
  const pathStartsAtStop =
    urlEnd > sigStart &&
    urlEnd < end &&
    stoppedTail >= 4 &&
    stoppedTail <= RSA_GLUED_PATH_MAX &&
    rsaShortTailIsClearPath(text, urlEnd, end);
  const tables: SigSize[][] = [
    SIG_HS256,
    SIG_HS384,
    SIG_86_88,
    SIG_ES384,
    SIG_ES512,
    SIG_EDDSA,
    SIG_RSA,
  ];
  let shaped = false;
  for (let t = 0; t < tables.length && !shaped; t += 1) {
    const table = tables[t];
    for (let s = 0; s < table.length; s += 1) {
      const cut = sigStart + table[s].url;
      if (cut <= sigStart || cut >= end) continue;
      if (pathStartsAtStop && cut > urlEnd) continue;
      const tailLen = end - cut;
      if (tailLen < 4 || tailLen > RSA_GLUED_PATH_MAX) continue;
      if (!rsaShortTailIsClearPath(text, cut, end)) continue;
      shaped = true;
      break;
    }
  }
  if (!shaped) return -1;
  const sizes = signatureSizesForAlg(jwtHeaderInfo(text.slice(cursor, dot1), mode).alg);
  if (!sizes) return -1;
  let best = -1;
  for (let s = 0; s < sizes.length; s += 1) {
    const cut = sigStart + sizes[s].url;
    if (cut <= sigStart || cut >= end) continue;
    if (pathStartsAtStop && cut > urlEnd) continue;
    const tailLen = end - cut;
    if (tailLen < 4 || tailLen > RSA_GLUED_PATH_MAX) continue;
    if (!rsaShortTailIsClearPath(text, cut, end)) continue;
    if (!isJwtToken(text.slice(cursor, cut), mode)) continue;
    if (cut > best) best = cut;
  }
  return best;
}

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
  if (i === dot2 + 1) return -1;
  // `+` or `/` inside the signature, or an unslashed path, stops the
  // base64url scan before the segment ends. Split only at this alg's
  // own exact length when the tail is a clear path.
  if (i < end) {
    const exact = exactAlgPathCut(text, cursor, dot1, dot2, end, mode, i);
    if (exact >= 0) return exact;
  }
  const sigLen = i - (dot2 + 1);
  // Reject before decoding. A space-separated token ends on base64url, so
  // this returns without reading the header. A longer run is a filename
  // only when the whole third segment is that base64url prefix plus an
  // ordinary filename stem. A `/` or `+` still inside the segment is the
  // path rule below, and an odd length stays masked.
  if (!SPLITTABLE_SIGNATURE_LENGTHS.has(sigLen)) {
    if (i !== end) {
      const deep = rsaDeepPathCut(text, cursor, dot1, dot2, i, end, mode);
      if (deep >= 0) return deep;
    }
    let cut = i === end ? rsaUngluedFilenameCut(text, dot2 + 1, i, sigLen) : -1;
    if (cut < 0) cut = rsaDottedBinCut(text, dot2 + 1);
    if (cut < 0) return -1;
    if (signatureSizesForAlg(jwtHeaderInfo(header, mode).alg) !== SIG_RSA) return -1;
    if (!isJwtToken(text.slice(cursor, cut), mode)) return -1;
    return cut;
  }
  // The third segment is already the std-base64 run (`+` `/` `=` included).
  // No second scan of the buffer. RSA uses one length compare on that run.
  const runLen = end - (dot2 + 1);
  const alg = jwtHeaderInfo(header, mode).alg;
  const shaped = isClearGluedPath(text, i, end) || isKnownExtensionlessTail(text, i, end);
  // A lone 3-letter directory atom needs a second segment, on every alg.
  // `/Bin.ts` already used that rule for RSA. `/Src.ts` and `/App.ts` do too.
  const clearPath =
    shaped && !binDirNeedsMoreGround(text, i, end) && !loneThreeLetterDir(text, i, end);
  let measure = runLen;
  if (signatureSizesForAlg(alg) === SIG_RSA) {
    const tailLen = runLen - sigLen;
    // Exact signature plus a short clear path. Measure the signature.
    // A tail that is still signature alphabet stays the whole segment.
    // That includes a 2-character tail after 342: `/K` makes the run 344,
    // which is the padded RSA-2048 length, so the exact-length check alone
    // would split. One pass over that tail.
    const glued =
      isRsaUrlLength(sigLen) && tailLen > 0 && tailLen <= RSA_GLUED_PATH_MAX;
    if (glued && rsaShortTailIsClearPath(text, i, end)) {
      measure = sigLen;
    } else if (glued && rsaRunEndsExactly(runLen)) {
      measure = 0;
    }
  }
  const wanted = longestSignatureLength(alg, measure);
  if (wanted !== null && sigLen === wanted && clearPath) {
    if (!isJwtToken(text.slice(cursor, i), mode)) return -1;
    return i;
  }
  // `node_modules/.bin/tsc` with a leading `/` is an exact signature
  // length plus a path the segment dot cuts in half. The same shape
  // check as the odd-length branch. One bounded scan.
  if (signatureSizesForAlg(alg) !== SIG_RSA) return -1;
  const dotted = rsaDottedBinCut(text, dot2 + 1);
  if (dotted < 0) return -1;
  if (!isJwtToken(text.slice(cursor, dotted), mode)) return -1;
  return dotted;
}

/**
 * Index where a padded JWT ends and the text after the padding begins.
 * Padding `=` cannot sit in the middle of a segment, so text after a valid
 * pad is not signature. The `=` search stops at the end of this token.
 * One `=` is padding when the signature length is 3 mod 4 (43, 683).
 * `==` is padding when the length is 2 mod 4 (86, 342). A length that is
 * 0 mod 4 (64, 128, 176, 512) takes no padding. `-then` and `-suffix` are
 * not this trailer; the hyphen rule still owns those. A joiner (`+` `/`
 * `_` `=`) after the padding stays. Plain text glued on after the padding
 * stays too. Returns -1 when the pad is the end of the span, the next
 * character is a hyphen, or the `=` is not valid padding.
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
 * Index of a `=` that follows a valid JWT when that `=` is not valid
 * padding. The JWT is the text before the `=`. The `=` and the trailing
 * text stay. The search stops at the end of this token, same as the
 * padding scan, so a buffer with no `=` is not walked to EOF. Returns -1
 * when the prefix is not a JWT. Callers try real padding first, and they
 * try the hyphen rule before this, so `-then` and a real `=` / `==` pad
 * stay on those paths.
 */
function equalsJwtBoundary(
  text: string,
  cursor: number,
  dot1: number,
  end: number,
  mode: JwtMaskMode,
): number {
  const dot2 = text.indexOf('.', dot1 + 1);
  if (dot2 < 0 || dot2 >= end) return -1;
  const eq = indexOfPaddingEquals(text, dot2 + 1, end);
  if (eq < dot2 + 1) return -1;
  if (!isJwtToken(text.slice(cursor, eq), mode)) return -1;
  return eq;
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
 * capped. After the cap, the last header prefix (`eyJ`, `eyA`, `ewo`,
 * `ew0`, or `ewk`) before the header dot is tried once, so a real token
 * after a long glued prefix is still masked.
 * Two JWTs joined by one `-`, `_`, `=`, `+`, or `/` are masked separately.
 * The joiner stays. A padded token followed by one of `+` `/` `_` `=` and
 * more text, or by plain text after valid padding, is masked only through
 * that padding, so the trailer stays. A `=` after any valid JWT is a
 * boundary even when it is not valid padding: the JWT is masked and the
 * `=` plus the trailing text stay. The search for that `=` stops at the
 * end of the token. A base64url token keeps a path glued on with `/` or
 * `+` only when that prefix is the longest unpadded signature length for
 * the token's own `alg` that the third segment reaches, and the tail is
 * clearly a path. A `+` or `/` at a shorter RSA or EdDSA length stays
 * inside the mask. An unknown or undecodable `alg` never splits. Dotted
 * text whose header does not decode as a JWT (`eyJsee.the.docs`, versions,
 * filenames) is left alone.
 * A whole-word suffix such as `-then`, `-Then`, or `-config-file` stays.
 * A short tail split on `_` or `-` does not: 1, 2, or 3 raw characters
 * (`_`, `-`, `_x`, `_ab`) stay inside the mask. A token tail, a short
 * stopword, and a mixed tail are consumed. A header that is only `eyJ-` / `eyJ_` / `eyJ=` /
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
      // Padding and hyphen suffixes already missed. A `=` whose prefix is
      // a valid JWT still ends the token, for every signature length.
      const eqAt = equalsJwtBoundary(text, cursor, structure.dot1, structure.end, mode);
      if (eqAt > cursor) {
        out += text.slice(last, cursor);
        out += '[REDACTED]';
        last = eqAt;
        i = eqAt;
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

const PEM_BEGIN = '-----BEGIN ';
const PEM_END = '-----END ';
const PEM_TAIL = 'PRIVATE KEY-----';
/** Longer kinds first. `EC ` is not a prefix of `ENCRYPTED `. */
const PEM_KINDS = ['ENCRYPTED ', 'OPENSSH ', 'RSA ', 'DSA ', 'EC ', ''];
const PEM_BLOCK_REPLACEMENT = '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----';

/** End index of a private-key header or footer starting at `at`, or -1. */
function pemPrivateKeyEnd(text: string, at: number): number {
  for (let i = 0; i < PEM_KINDS.length; i += 1) {
    const header = PEM_KINDS[i] + PEM_TAIL;
    if (text.startsWith(header, at)) return at + header.length;
  }
  return -1;
}

/**
 * A private-key body line is base64, and it is not a short prose word.
 * 16 characters is the usual minimum (`Next`, `README`, `npm`, `test`,
 * and `TODO` stay). A shorter line still counts when it is a multiple of
 * 4 and contains a digit, `+`, `/`, or `=`. That includes a 12-character
 * padded fragment such as `QUJDREVGR0g=` and a 4-character fragment such
 * as `YQ==`. A letter-only line shorter than 16 (`QUJD`, `abcdefghijkl`)
 * is not key material.
 */
const PEM_BODY_MIN = 16;
const PEM_BODY_SHORT_MIN = 4;

function isBase64Code(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 43 ||
    code === 47 ||
    code === 61
  );
}

function isPemKeyChar(code: number): boolean {
  return code === 43 || code === 47 || code === 61 || (code >= 48 && code <= 57);
}

/** True when [start, end) is key-shaped base64, not a short prose word. */
function isKeyMaterialSpan(line: string, start: number, end: number): boolean {
  const n = end - start;
  if (n < PEM_BODY_SHORT_MIN) return false;
  if (n < PEM_BODY_MIN && n % 4 !== 0) return false;
  let shaped = n >= PEM_BODY_MIN;
  for (let i = start; i < end; i += 1) {
    const code = line.charCodeAt(i);
    if (!isBase64Code(code)) return false;
    if (isPemKeyChar(code)) shaped = true;
  }
  return shaped;
}

/**
 * How a leading diff marker is removed before key text is read.
 * 0: none. A leading `+` is base64.
 * 1: one leading `+` or `-`, and not `++` or `--`. File markers stay.
 * 2: inside an `@@` hunk. One leading space, `+`, or `-` is a marker
 * on any line, including when the next character is the same mark.
 * The BEGIN line does not have to carry the prefix.
 */
const PEM_MARK_NONE = 0;
const PEM_MARK_SIGN = 1;
const PEM_MARK_HUNK = 2;

/**
 * Index after one unified-diff marker. A single leading `+` or `-` is
 * not part of the key line. `+++` and `---` stay, so a file marker is
 * not stripped into key material. The caller has already skipped
 * leading space and tab, and only calls this when the block is a diff
 * that is not an `@@` hunk. One comparison.
 */
function pemDiffContentStart(line: string, start: number, end: number): number {
  if (start >= end) return start;
  const mark = line.charCodeAt(start);
  if (mark !== 43 && mark !== 45) return start;
  const next = start + 1;
  if (next < end && line.charCodeAt(next) === mark) return start;
  return next;
}

/** True when the trimmed line opens with one `+` or one `-`, not `++` or `--`. */
function hasSingleDiffMark(line: string): boolean {
  const span = pemBodySpan(line);
  return pemDiffContentStart(line, span.start, span.end) !== span.start;
}

/**
 * Where key text starts. `PEM_MARK_SIGN` skips one `+` or `-`.
 * `PEM_MARK_HUNK` skips one space, `+`, or `-`. A leading `+` in a
 * normal PEM line is base64.
 */
function pemKeyStart(line: string, start: number, end: number, mark: number): number {
  if (mark === PEM_MARK_NONE || start >= end) return start;
  const code = line.charCodeAt(start);
  if (mark === PEM_MARK_HUNK) {
    if (code === 32 || code === 43 || code === 45) return start + 1;
    return start;
  }
  return pemDiffContentStart(line, start, end);
}

function isBase64UrlCode(code: number): boolean {
  return isBase64Code(code) || code === 45 || code === 95;
}

/**
 * One piece of a hyphenated or underscored line. A real word, or a short
 * letter run with a vowel and no long consonant cluster. A repeated
 * character run is not this.
 */
function isWordLikeSegment(line: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 1) return true;
  if (identifierWordAt(line, from, to)) return true;
  if (n > 24) return false;
  let vowel = false;
  let run = 0;
  for (let i = from; i < to; i += 1) {
    let code = line.charCodeAt(i);
    if (code >= 65 && code <= 90) code += 32;
    else if (code < 97 || code > 122) return false;
    if (
      code === 97 || code === 101 || code === 105 || code === 111 ||
      code === 117 || code === 121 || code === 119
    ) {
      vowel = true;
      run = 0;
    } else {
      run += 1;
      if (run > 4) return false;
    }
  }
  if (n >= 5 && !vowel) return false;
  return true;
}

/** True when every `-` / `_` piece of the span is a word-like segment. */
function segmentsAreWords(line: string, start: number, end: number): boolean {
  let from = start;
  let any = false;
  for (let i = start; i <= end; i += 1) {
    const split = i === end || line.charCodeAt(i) === 45 || line.charCodeAt(i) === 95;
    if (!split) continue;
    if (i > from) {
      any = true;
      if (!isWordLikeSegment(line, from, i)) return false;
    }
    from = i + 1;
  }
  return any;
}

/**
 * A key line that uses base64url `-` or `_`. A line that begins or ends
 * with either character is body. An interior mark is body unless every
 * piece is a word, so `user_profile_settings_name` stays and a run of
 * key characters with one `_` does not end the block.
 */
function isUrlKeySpan(line: string, start: number, end: number): boolean {
  const n = end - start;
  if (n < PEM_BODY_MIN) return false;
  let url = false;
  for (let i = start; i < end; i += 1) {
    const code = line.charCodeAt(i);
    if (!isBase64UrlCode(code)) return false;
    if (code === 45 || code === 95) url = true;
  }
  if (!url) return false;
  const first = line.charCodeAt(start);
  const last = line.charCodeAt(end - 1);
  if (first === 45 || first === 95 || last === 45 || last === 95) return true;
  return !segmentsAreWords(line, start, end);
}

/**
 * A path run that is a real identifier, not a shape-only letter string.
 * Shape alone kept a random 16-letter run glued to a path, so the next
 * secret line stayed visible. A dictionary word, an identifier word,
 * camelCase or an acronym whose humps are those words, or a digit name
 * such as `sha256DigestValue` still counts. A camelCase run stays only
 * when every hump is a dictionary word or a documented identifier
 * variant. One dictionary hump does not keep the neighboring humps.
 * A hump of 7 or more letters does not keep the run on shape.
 * One pass per check.
 */
function isKeptGluedRun(line: string, from: number, to: number): boolean {
  if (to - from < 2) return false;
  if (isDigitBearingName(line, from, to)) return true;
  if (identifierWordAt(line, from, to)) return true;
  if (humpWordAt(line, from, to)) return true;
  if (isSingleCapIdentifier(line, from, to)) return true;
  if (to - from >= 4 && isAcronymWordIdentifier(line, from, to)) return true;
  return isWordShapedCamelIdentifier(line, from, to);
}

/**
 * Base64 glued to a path (`CCCCCCCC/src/app.ts`, `./src/app.ts` plus a
 * key run). A real path whose segments are words stays a stopping line.
 * `/` and `.` split the span, so a `+` or `=` inside a shorter segment
 * is still key material. A run of 16 or more characters is key material
 * unless it is a real identifier: a dictionary word, or camelCase whose
 * every hump is a dictionary word or a documented identifier variant.
 * One dictionary hump does not keep random neighbors. A hump of 7 or
 * more letters does not keep the run on shape. One pass over the span.
 */
function isGluedKeyPathSpan(line: string, start: number, end: number): boolean {
  if (end - start < PEM_BODY_MIN) return false;
  let sawPath = false;
  let runFrom = -1;
  let runKey = false;
  let bad = false;
  const finish = (runEnd: number): void => {
    if (runFrom < 0) return;
    const n = runEnd - runFrom;
    if (runKey || (n >= PEM_BODY_MIN && !isKeptGluedRun(line, runFrom, runEnd))) bad = true;
    runFrom = -1;
    runKey = false;
  };
  for (let i = start; i <= end; i += 1) {
    if (i === end) {
      finish(end);
      break;
    }
    const code = line.charCodeAt(i);
    if (code === 32 || code === 9 || code === 13) return false;
    if (code === 47 || code === 46) {
      sawPath = true;
      finish(i);
      continue;
    }
    if (!isBase64UrlCode(code)) return false;
    if (runFrom < 0) runFrom = i;
    if (code === 43 || code === 61) runKey = true;
  }
  return sawPath && bad;
}

function isExtendedPemSpan(line: string, start: number, end: number): boolean {
  return isUrlKeySpan(line, start, end) || isGluedKeyPathSpan(line, start, end);
}

/**
 * A full PEM body line: key-shaped base64 only, after ASCII space, tab,
 * and CR. A line that begins or ends with `-` or `_`, or a key run glued
 * to a path, is still body. A word-like underscored name is not.
 * Inside an `@@` hunk the first space, `+`, or `-` is the diff
 * marker and is not trimmed as indentation before that check, so a
 * second `+` stays base64.
 */
function isPemBodyLine(line: string, mark: number): boolean {
  let start = 0;
  let end = line.length;
  while (end > start) {
    const code = line.charCodeAt(end - 1);
    if (code !== 32 && code !== 9 && code !== 13) break;
    end -= 1;
  }
  if (mark === PEM_MARK_HUNK && start < end) {
    const code = line.charCodeAt(start);
    if (code === 32 || code === 43 || code === 45) start += 1;
  }
  while (start < end) {
    const code = line.charCodeAt(start);
    if (code !== 32 && code !== 9 && code !== 13) break;
    start += 1;
  }
  start = pemKeyStart(line, start, end, mark === PEM_MARK_HUNK ? PEM_MARK_NONE : mark);
  if (end <= start) return false;
  if (isKeyMaterialSpan(line, start, end)) return true;
  return isExtendedPemSpan(line, start, end) && !isCamelOrPascalIdentifier(line, mark);
}

/**
 * Key text of one hunk payload line, after one diff marker.
 * A leading `+` that is the marker is not part of the span.
 */
function hunkKeySpan(line: string): { start: number; end: number } {
  let start = 0;
  let end = line.length;
  while (end > start) {
    const code = line.charCodeAt(end - 1);
    if (code !== 32 && code !== 9 && code !== 13) break;
    end -= 1;
  }
  if (start < end) {
    const code = line.charCodeAt(start);
    if (code === 32 || code === 43 || code === 45) start += 1;
  }
  while (start < end) {
    const code = line.charCodeAt(start);
    if (code !== 32 && code !== 9 && code !== 13) break;
    start += 1;
  }
  return { start, end };
}

/**
 * A short ordinary token such as `Zm9v`. It is base64-shaped and has a
 * digit, and it has no `+`, `/`, or `=`, so it is not a padded key
 * fragment. A letter-only line is not this: that line is already prose.
 */
function isShortOrdinaryBase64Span(line: string, start: number, end: number): boolean {
  const n = end - start;
  if (n < PEM_BODY_SHORT_MIN || n >= PEM_BODY_MIN || n % 4 !== 0) return false;
  let digit = false;
  for (let i = start; i < end; i += 1) {
    const code = line.charCodeAt(i);
    if (!isBase64Code(code)) return false;
    if (code === 43 || code === 47 || code === 61) return false;
    if (code >= 48 && code <= 57) digit = true;
  }
  return digit;
}

/**
 * End index of a key-shaped base64 run at the start of `line`, when prose
 * follows on that same line. -1 when the line is a full body line or the
 * run is not key material. The prose must start with ASCII space or tab.
 * A path such as `/src/components/Button.tsx` is not a partial key line.
 * Leading ASCII space and tab are not part of the run. When the block
 * is a diff, one leading `+` or `-` is a marker and is part of the
 * redacted run. The prose, including the space before it, stays.
 */
function pemPartialCut(line: string, mark: number): number {
  let i = 0;
  if (mark === PEM_MARK_HUNK && i < line.length) {
    const code = line.charCodeAt(i);
    if (code === 32 || code === 43 || code === 45) i += 1;
  }
  while (i < line.length) {
    const code = line.charCodeAt(i);
    if (code !== 32 && code !== 9) break;
    i += 1;
  }
  i = pemKeyStart(line, i, line.length, mark === PEM_MARK_HUNK ? PEM_MARK_NONE : mark);
  const start = i;
  while (i < line.length && isBase64Code(line.charCodeAt(i))) i += 1;
  if (i === start || i >= line.length) return -1;
  const boundary = line.charCodeAt(i);
  if (boundary !== 32 && boundary !== 9) return -1;
  let prose = false;
  for (let k = i; k < line.length; k += 1) {
    const code = line.charCodeAt(k);
    if (code !== 32 && code !== 9 && code !== 13) {
      prose = true;
      break;
    }
  }
  if (!prose) return -1;
  if (!isKeyMaterialSpan(line, start, i)) return -1;
  return i;
}

/** Trimmed bounds of a PEM body span. ASCII space, tab, and CR only. */
function pemBodySpan(line: string): { start: number; end: number } {
  let start = 0;
  let end = line.length;
  while (start < end) {
    const code = line.charCodeAt(start);
    if (code !== 32 && code !== 9 && code !== 13) break;
    start += 1;
  }
  while (end > start) {
    const code = line.charCodeAt(end - 1);
    if (code !== 32 && code !== 9 && code !== 13) break;
    end -= 1;
  }
  return { start, end };
}

function isHexDigitCode(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  );
}

function pemTrimWidth(line: string, mark: number): number {
  const span = pemBodySpan(line);
  const start = pemKeyStart(line, span.start, span.end, mark);
  return span.end - start;
}

/** Trimmed span is only hex digits. A sha256 line is this shape. A diff mark is not part of the span when the block is a diff. */
function isPureHexLine(line: string, mark: number): boolean {
  const span = pemBodySpan(line);
  const start = pemKeyStart(line, span.start, span.end, mark);
  if (span.end <= start) return false;
  for (let i = start; i < span.end; i += 1) {
    if (!isHexDigitCode(line.charCodeAt(i))) return false;
  }
  return true;
}

/**
 * A hex digest sitting in prose: MD5 32, SHA-1 40, SHA-256 64, SHA-384 96,
 * SHA-512 128. Other hex widths are body-shaped, not digests.
 */
function isHexDigestLine(line: string, mark: number): boolean {
  if (!isPureHexLine(line, mark)) return false;
  const n = pemTrimWidth(line, mark);
  return n === 32 || n === 40 || n === 64 || n === 96 || n === 128;
}

function hasPemKeyPunctuation(line: string, mark: number): boolean {
  const span = pemBodySpan(line);
  const start = pemKeyStart(line, span.start, span.end, mark);
  for (let i = start; i < span.end; i += 1) {
    const code = line.charCodeAt(i);
    if (code === 43 || code === 47 || code === 61) return true;
  }
  return false;
}

/**
 * Index where a trailing digit run starts, or `end` when there are no
 * digits. -1 when a digit sits before a later letter. Digits mixed into
 * a name are key material (`abcDe12fghijklmn`). A trailing run is a
 * counter (`IdentifierValue16`). One pass.
 */
function trailingDigitCut(line: string, start: number, end: number): number {
  let digitAt = -1;
  for (let i = start; i < end; i += 1) {
    const code = line.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      if (digitAt < 0) digitAt = i;
      continue;
    }
    if (digitAt >= 0) return -1;
  }
  if (digitAt < 0) return end;
  return digitAt;
}

/**
 * Prose words that are not path atoms. They do not ground a path.
 * A hump of one letter is only `a` or `i`. One lookup per hump.
 * A camelCase hump counts only when it is one of these words, so a
 * random vowel-consonant hump stays key material.
 */
const IDENTIFIER_WORDS = new Set([
  'a',
  'access',
  'account',
  'active',
  'adapter',
  'add',
  'allocate',
  'allow',
  'allowed',
  'application',
  'apply',
  'arguments',
  'asset',
  'asynchronous',
  'atob',
  'audit',
  'autoscaler',
  'background',
  'backoff',
  'backup',
  'badge',
  'balance',
  'block',
  'body',
  'bootstrap',
  'breaker',
  'broker',
  'build',
  'bulkhead',
  'bundle',
  'by',
  'cache',
  'calculation',
  'callback',
  'camel',
  'canonicalized',
  'capture',
  'case',
  'certificate',
  'change',
  'check',
  'checkout',
  'checksum',
  'circuit',
  'claim',
  'class',
  'clear',
  'client',
  'collect',
  'command',
  'compile',
  'compose',
  'compute',
  'configure',
  'connection',
  'consumer',
  'control',
  'controller',
  'cookie',
  'coverage',
  'create',
  'crypto',
  'customer',
  'dashboard',
  'database',
  'decode',
  'decompress',
  'dependency',
  'deployment',
  'deserialize',
  'details',
  'dev',
  'dir',
  'discount',
  'display',
  'docker',
  'document',
  'downstream',
  'downward',
  'email',
  'enqueue',
  'environment',
  'error',
  'eslint',
  'event',
  'export',
  'feature',
  'fetch',
  'file',
  'files',
  'fingerprint',
  'flag',
  'format',
  'frame',
  'gateway',
  'generate',
  'get',
  'grant',
  'graph',
  'graphql',
  'group',
  'handle',
  'horizontal',
  'host',
  'html',
  'i',
  'identifier',
  'identity',
  'image',
  'incoming',
  'indexed',
  'ingress',
  'install',
  'invalidate',
  'invoice',
  'is',
  'isolation',
  'javascript',
  'jwt',
  'kafka',
  'key',
  'kubelet',
  'kubernetes',
  'limiter',
  'list',
  'listener',
  'load',
  'loader',
  'lock',
  'long',
  'manager',
  'manifest',
  'match',
  'measure',
  'message',
  'middleware',
  'module',
  'msg',
  'name',
  'nginx',
  'normalize',
  'notes',
  'notification',
  'now',
  'oauth',
  'object',
  'open',
  'order',
  'package',
  'parse',
  'password',
  'path',
  'paths',
  'pattern',
  'payload',
  'payment',
  'performance',
  'permission',
  'persistent',
  'personal',
  'pod',
  'policy',
  'postgres',
  'postgresql',
  'preferences',
  'producer',
  'profile',
  'project',
  'prometheus',
  'publish',
  'query',
  'random',
  'rate',
  'read',
  'receipt',
  'record',
  'redis',
  'refresh',
  'refs',
  'register',
  'rel',
  'release',
  'render',
  'report',
  'repository',
  'request',
  'resize',
  'resolve',
  'resolver',
  'response',
  'result',
  'results',
  'retry',
  'revoke',
  'rotate',
  'route',
  'save',
  'scrape',
  'screenshot',
  'security',
  'send',
  'serialize',
  'server',
  'service',
  'session',
  'set',
  'settings',
  'share',
  'sheet',
  'shutdown',
  'signature',
  'signing',
  'site',
  'socket',
  'span',
  'specifier',
  'start',
  'stop',
  'storage',
  'store',
  'strength',
  'style',
  'stylesheet',
  'synchronization',
  'task',
  'telemetry',
  'template',
  'test',
  'this',
  'throughput',
  'toggle',
  'token',
  'trace',
  'trusted',
  'typescript',
  'uncommitted',
  'update',
  'upstream',
  'user',
  'validate',
  'value',
  'verify',
  'very',
  'view',
  'volume',
  'web',
  'webhook',
  'webpack',
  'websocket',
  'worker',
  'workload',
  'write',
  'yaml',
  // v1.0.62 code-word humps. These are not path atoms.
  'auth',
  'btn',
  'cfg',
  'ctx',
  'descriptor',
  'dst',
  'enum',
  'env',
  'executable',
  'idx',
  'impl',
  'init',
  'len',
  'logger',
  'num',
  'params',
  'pkg',
  'reducer',
  'repo',
  'req',
  'res',
  'selector',
  'src',
  'str',
  'tmp',
  'util',
  'widget',
]);

/**
 * Abbreviations kept in any letter case (`JSON`, `Url`, `id`, `HTTP`).
 * They do not ground a path. `json` and `http` are also path atoms;
 * `url` and `id` are not.
 */
const IDENTIFIER_ABBREVS = new Set([
  'api',
  'db',
  'fn',
  'http',
  'id',
  'json',
  'url',
  'uuid',
]);

/**
 * A real word or a common abbreviation. Path words and `config` count.
 * `config` is not a path atom: adding it there would keep a signature
 * fragment. All-caps matches an abbreviation or a path atom, not an
 * ordinary word, so a random capital run stays key material. A hump of
 * one letter is only `a` or `i`. One pass over a hump already cut from
 * one line.
 */
function identifierWordAt(line: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 1 || n > 24) return false;
  if (n === 1) {
    let code = line.charCodeAt(from);
    if (code >= 65 && code <= 90) code += 32;
    return code === 97 || code === 105;
  }
  if (dictionaryWordAt(line, from, to, true)) return true;
  if (n === 6) {
    const config = 'config';
    let match = true;
    for (let i = 0; i < 6; i += 1) {
      let code = line.charCodeAt(from + i);
      if (code >= 65 && code <= 90) code += 32;
      if (code !== config.charCodeAt(i)) match = false;
    }
    if (match) return true;
  }
  let lower = '';
  let uppers = 0;
  for (let i = from; i < to; i += 1) {
    const code = line.charCodeAt(i);
    if (code >= 97 && code <= 122) lower += String.fromCharCode(code);
    else if (code >= 65 && code <= 90) {
      uppers += 1;
      lower += String.fromCharCode(code + 32);
    } else return false;
  }
  if (IDENTIFIER_ABBREVS.has(lower)) return true;
  if (uppers === n || uppers > 1) return false;
  if (uppers === 1 && (line.charCodeAt(from) < 65 || line.charCodeAt(from) > 90)) return false;
  return IDENTIFIER_WORDS.has(lower);
}

/**
 * camelCase or PascalCase whose every hump is a real word
 * (`veryLongCamelCaseIdentifier`, `thisIsAVeryLongCamelCaseIdentifierName`).
 * A capital starts a hump, including a one-letter word (`A`). Two
 * capitals in a row are a one-letter hump, not a reason to reject the
 * shape. The span is letters only; the caller strips a trailing digit
 * run. One pass.
 */
function isSingleCapIdentifier(line: string, start: number, end: number): boolean {
  if (end - start < 2) return false;
  const first = line.charCodeAt(start);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) return false;
  let humps = 0;
  let humpFrom = start;
  for (let i = start + 1; i <= end; i += 1) {
    const split = i === end || (line.charCodeAt(i) >= 65 && line.charCodeAt(i) <= 90);
    if (!split) {
      const code = line.charCodeAt(i);
      if (code < 97 || code > 122) return false;
      continue;
    }
    if (!identifierWordAt(line, humpFrom, i)) return false;
    humps += 1;
    humpFrom = i;
  }
  return humps >= 2;
}

/**
 * An acronym name (`HTTPServerConfig` is `HTTP` + `Server` + `Config`,
 * `parseJSONResponse` is `parse` + `JSON` + `Response`). A run of capitals
 * is one hump. When lowercase follows, the last capital starts the next
 * word. Every hump is a real word or abbreviation, and at least one hump
 * is two or more capitals, so a random capital pair stays key material.
 * A one-letter hump is only `a` or `i`. One pass over a letter span
 * already cut from one line.
 */
function isAcronymWordIdentifier(line: string, start: number, end: number): boolean {
  if (end - start < 4) return false;
  const first = line.charCodeAt(start);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) return false;
  let humps = 0;
  let acronym = false;
  let i = start;
  const take = (from: number, to: number, caps: number): boolean => {
    if (to <= from) return false;
    if (!identifierWordAt(line, from, to)) return false;
    if (caps >= 2) acronym = true;
    humps += 1;
    return true;
  };
  while (i < end) {
    const code = line.charCodeAt(i);
    if (code >= 97 && code <= 122) {
      const from = i;
      i += 1;
      while (i < end) {
        const next = line.charCodeAt(i);
        if (next < 97 || next > 122) break;
        i += 1;
      }
      if (!take(from, i, 0)) return false;
      continue;
    }
    if (code < 65 || code > 90) return false;
    const from = i;
    i += 1;
    while (i < end) {
      const next = line.charCodeAt(i);
      if (next < 65 || next > 90) break;
      i += 1;
    }
    const caps = i - from;
    const followedByLower = i < end && line.charCodeAt(i) >= 97 && line.charCodeAt(i) <= 122;
    if (followedByLower && caps >= 2) {
      if (!take(from, i - 1, caps - 1)) return false;
      const wordFrom = i - 1;
      i += 1;
      while (i < end) {
        const next = line.charCodeAt(i);
        if (next < 97 || next > 122) break;
        i += 1;
      }
      if (!take(wordFrom, i, 1)) return false;
      continue;
    }
    if (followedByLower && caps === 1) {
      const wordFrom = from;
      i += 1;
      while (i < end) {
        const next = line.charCodeAt(i);
        if (next < 97 || next > 122) break;
        i += 1;
      }
      if (!take(wordFrom, i, 1)) return false;
      continue;
    }
    if (!take(from, i, caps)) return false;
  }
  return humps >= 2 && acronym;
}

/**
 * snake_case whose every part is a real word (`user_profile_settings_name`).
 * A digit in a part is not a word. One pass.
 */
function isSnakeCaseIdentifier(line: string, start: number, end: number): boolean {
  if (line.charCodeAt(start) === 95 || line.charCodeAt(end - 1) === 95) return false;
  let parts = 0;
  let i = start;
  while (i < end) {
    if (line.charCodeAt(i) === 95) return false;
    const from = i;
    while (i < end && line.charCodeAt(i) !== 95) i += 1;
    if (!identifierWordAt(line, from, i)) return false;
    parts += 1;
    if (i < end) i += 1;
  }
  return parts >= 2;
}

/**
 * Letter pairs from ordinary words and code names. Bit (a * 26 + b) is
 * set when that lowercase pair may sit inside a camelCase hump. A random
 * run such as `bc` in `abcdefgh` is unset. 85 bytes. One lookup per pair.
 */
const IDENTIFIER_PAIR_BITS: Uint8Array = Buffer.from(
  '7r/+RW5bVNvt0Ve2Rf/7/8c1exSd59FF/Ed//a5GBBHRlc7BXjJPH/kU9P3/9vbv32e3TwAIEPT3+1Xf/9V/vnd/+Q5EBQEQmedABSRCU/lMRAABAA==',
  'base64',
);

function identifierPair(first: number, second: number): boolean {
  if (first < 97 || first > 122 || second < 97 || second > 122) return false;
  const index = (first - 97) * 26 + (second - 97);
  const byte = IDENTIFIER_PAIR_BITS[index >> 3] ?? 0;
  return (byte & (1 << (index & 7))) !== 0;
}

/**
 * One hump of a word-shaped camelCase name. A hump of one letter is only
 * `a` or `i`. A hump of 2 to 4 letters may be an abbreviation without a
 * vowel (`Msg`, `Jwt`, `Html`). A longer hump is at most 16 letters,
 * contains a vowel (`w` counts), has no consonant run longer than 4, and every letter
 * pair is an ordinary pair. The capital, when present, is the first
 * letter. Shape alone is not a dictionary word. The caller also requires
 * every hump to be a dictionary word or a documented identifier variant.
 * One pass.
 */
function shapedCamelHump(line: string, from: number, to: number): boolean {
  const n = to - from;
  if (n === 1) {
    let code = line.charCodeAt(from);
    if (code >= 65 && code <= 90) code += 32;
    return code === 97 || code === 105;
  }
  if (n < 2 || n > 16) return false;
  let vowel = false;
  let run = 0;
  let maxRun = 0;
  let prev = 0;
  for (let i = from; i < to; i += 1) {
    let code = line.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      if (i !== from) return false;
      code += 32;
    } else if (code < 97 || code > 122) {
      return false;
    }
    // `w` counts with the vowels. It breaks clusters such as `wnstr`
    // in `downstream` without making a random run of five consonants a word.
    if (
      code === 97 || code === 101 || code === 105 || code === 111 ||
      code === 117 || code === 121 || code === 119
    ) {
      vowel = true;
      run = 0;
    } else {
      run += 1;
      if (run > maxRun) maxRun = run;
    }
    if (i > from && !identifierPair(prev, code)) return false;
    prev = code;
  }
  if (n >= 5 && !vowel) return false;
  if (n > 4 && maxRun > 4) return false;
  return true;
}

/**
 * camelCase whose humps are word-shaped, not a random capital
 * (`getUserProfileById`, `fetchAccountBalance`, `handleWebSocketMsg`).
 * At least two humps, and at least one hump is 4 or more letters. The
 * name is mostly lowercase. Two capitals in a row are an acronym, not
 * this shape. Every hump is still word-shaped, so a random
 * vowel-consonant run stays key material. Every hump also has to be a
 * dictionary word or a documented variant. A documented variant is an
 * identifier word, a code word, or an abbreviation already accepted by
 * `identifierWordAt`: `config`, `api`, `db`, `fn`, `http`, `id`, `json`,
 * `url`, `uuid`, and the one-letter words `a` and `i`. One dictionary
 * hump does not keep the neighboring humps, so `TosiliWibuHandler` stays
 * key material and `initLoggerReducer` stays visible. A hump of 7 or
 * more letters does not stay on shape. One pass over a letter span
 * already cut from one line.
 */
function isWordShapedCamelIdentifier(line: string, start: number, end: number): boolean {
  if (end - start < 2) return false;
  const first = line.charCodeAt(start);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) return false;
  let humps = 0;
  let longHump = false;
  let lowers = 0;
  let uppers = 0;
  let allDict = true;
  let humpFrom = start;
  for (let i = start + 1; i <= end; i += 1) {
    const atEnd = i === end;
    const code = atEnd ? 0 : line.charCodeAt(i);
    const upper = code >= 65 && code <= 90;
    if (!atEnd && !upper) {
      if (code < 97 || code > 122) return false;
      continue;
    }
    if (!atEnd && line.charCodeAt(i - 1) >= 65 && line.charCodeAt(i - 1) <= 90) return false;
    if (!shapedCamelHump(line, humpFrom, i)) return false;
    const n = i - humpFrom;
    if (!humpWordAt(line, humpFrom, i) && !identifierWordAt(line, humpFrom, i)) allDict = false;
    if (n >= 4) longHump = true;
    for (let k = humpFrom; k < i; k += 1) {
      const humpCode = line.charCodeAt(k);
      if (humpCode >= 97 && humpCode <= 122) lowers += 1;
      else uppers += 1;
    }
    humps += 1;
    humpFrom = i;
  }
  if (!(humps >= 2 && longHump && lowers > uppers)) return false;
  return allDict;
}

/**
 * camelCase, PascalCase, or snake_case (`veryLongCamelCaseIdentifier`,
 * `IdentifierValue16`, `HTTPServerConfig`, `parseJSONResponse`,
 * `getUserProfileById`, `handleClickEvent`). A name stays when every
 * part is a dictionary word or a common abbreviation, or when it is
 * word-shaped camelCase: at least two humps of 2 to 16 letters, mostly
 * lowercase, each hump of 5 or more letters containing a vowel. Every
 * hump has to be a dictionary word or a documented identifier variant.
 * One dictionary hump does not keep the other humps. A hump of 7 or
 * more letters does not keep the name on shape. Digits in a camelCase or PascalCase name are only
 * a trailing run, so a digit mixed into the line stays key material, except a
 * hump that is exactly `k8s`, `sha256`, or `base64` beside real words
 * (`k8sNamespaceName`, `sha256DigestValue`, `base64UrlEncoded`).
 * One leading `+` or `-` is a diff marker only when the block is a diff.
 * `+++` and `---` are not stripped. One pass over the trimmed line, then
 * one pass over its parts.
 */
/**
 * Digit humps that are real names, not key text. Anything else with a
 * digit in the middle stays redacted (`abcDe12fghijklmn`).
 */
const DIGIT_NAME_HUMPS = new Set(['base64', 'k8s', 'sha256']);

/** Words used only beside those digit humps. They do not widen the general keep. */
const DIGIT_NAME_WORDS = new Set(['digest', 'encoded', 'namespace']);

function lowerHump(line: string, from: number, to: number): string {
  let lower = '';
  for (let i = from; i < to; i += 1) {
    const code = line.charCodeAt(i);
    if (code >= 65 && code <= 90) lower += String.fromCharCode(code + 32);
    else lower += String.fromCharCode(code);
  }
  return lower;
}

/**
 * One hump of a digit-bearing name. A hump with a digit must be the
 * whole token `k8s`, `sha256`, or `base64`. A letter hump is a real
 * word, or `namespace`, `digest`, or `encoded`.
 */
function digitNameHump(line: string, from: number, to: number): boolean {
  let digit = false;
  for (let i = from; i < to; i += 1) {
    const code = line.charCodeAt(i);
    if (code >= 48 && code <= 57) digit = true;
    else if (!((code >= 65 && code <= 90) || (code >= 97 && code <= 122))) return false;
  }
  if (digit) return DIGIT_NAME_HUMPS.has(lowerHump(line, from, to));
  if (identifierWordAt(line, from, to)) return true;
  return DIGIT_NAME_WORDS.has(lowerHump(line, from, to));
}

/**
 * `k8sNamespaceName`, `sha256DigestValue`, `base64UrlEncoded`.
 * A capital starts a hump. Digits stay in the current hump. At least
 * one hump has a digit, and every hump is a known token. One pass.
 */
function isDigitBearingName(line: string, start: number, end: number): boolean {
  if (end - start < 16) return false;
  const first = line.charCodeAt(start);
  if (!((first >= 65 && first <= 90) || (first >= 97 && first <= 122))) return false;
  let humps = 0;
  let sawDigit = false;
  let humpFrom = start;
  for (let i = start + 1; i <= end; i += 1) {
    const code = i === end ? 0 : line.charCodeAt(i);
    if (i !== end && !(code >= 65 && code <= 90)) {
      const ok = (code >= 97 && code <= 122) || (code >= 48 && code <= 57);
      if (!ok) return false;
      if (code >= 48 && code <= 57) sawDigit = true;
      continue;
    }
    if (!digitNameHump(line, humpFrom, i)) return false;
    humps += 1;
    humpFrom = i;
  }
  return humps >= 2 && sawDigit;
}

function isCamelOrPascalIdentifier(line: string, mark: number): boolean {
  const span = pemBodySpan(line);
  const start = pemKeyStart(line, span.start, span.end, mark);
  const end = span.end;
  if (end - start < 16) return false;
  for (let i = start; i < end; i += 1) {
    if (line.charCodeAt(i) === 95) return isSnakeCaseIdentifier(line, start, end);
  }
  const letterEnd = trailingDigitCut(line, start, end);
  if (letterEnd < 0) return isDigitBearingName(line, start, end);
  if (letterEnd <= start) return false;
  if (isSingleCapIdentifier(line, start, letterEnd)) return true;
  if (isAcronymWordIdentifier(line, start, letterEnd)) return true;
  return isWordShapedCamelIdentifier(line, start, letterEnd);
}

/**
 * A base64 line that continues a truncated key after a gap.
 * It is at least as wide as the first body line, or the same width.
 * A shorter final line still continues when it contains `+`, `/`, or `=`,
 * or when it is base64-only and at least 16 characters. That line is the
 * key's last line, including 16 to 19 characters and a longer
 * alphanumeric line. A camelCase or PascalCase word does not continue
 * when this line follows the gap directly: every camelCase, PascalCase,
 * or snake_case part is a real word or a common abbreviation
 * (`HTTPServerConfig`, `parseJSONResponse`) or word-shaped camelCase
 * (`getUserProfileById`, `kubeletConfigPath`). A random capital is not
 * enough. Digits in a camelCase or PascalCase name are only a trailing
 * run. Digits mixed into the line do continue, except
 * `k8sNamespaceName`, `sha256DigestValue`, and `base64UrlEncoded`.
 * One leading `+` or `-`
 * is a diff marker only when the block is a diff. A 48-hex or 56-hex
 * string does not continue. A hex digest does not continue: 40-hex and
 * 64-hex stay prose. One pass over the trimmed line. The caller uses
 * this only while the gap is still open. A line that follows a resumed
 * body line is body, not this exception: a hex digest there is also a
 * legal key line.
 */
function resumesAfterPemGap(line: string, bodyWidth: number, mark: number): boolean {
  if (bodyWidth < 1 || !isPemBodyLine(line, mark) || isHexDigestLine(line, mark)) return false;
  const n = pemTrimWidth(line, mark);
  if (isPureHexLine(line, mark) && (n === 48 || n === 56)) return false;
  if (n >= bodyWidth) return true;
  if (isCamelOrPascalIdentifier(line, mark)) return false;
  if (hasPemKeyPunctuation(line, mark)) return true;
  return n >= 16;
}

/** Trimmed bounds of a PEM line. ASCII space and tab only. */
function pemTrimmed(line: string): { start: number; end: number } {
  let start = 0;
  let end = line.length;
  while (start < end) {
    const code = line.charCodeAt(start);
    if (code !== 32 && code !== 9) break;
    start += 1;
  }
  while (end > start) {
    const code = line.charCodeAt(end - 1);
    if (code !== 32 && code !== 9) break;
    end -= 1;
  }
  return { start, end };
}

/**
 * A line the body scan may cross. Blank, or 1 to 15 characters after
 * ASCII space and tab are removed. A key line is classified first, so
 * `YQ==` and `QUJDREVGR0g=` are body, not a gap.
 */
function isShortOrBlankPemLine(line: string): boolean {
  const span = pemTrimmed(line);
  return span.end - span.start <= 15;
}

function pemStartsWith(line: string, from: number, end: number, prefix: string): boolean {
  if (end - from < prefix.length) return false;
  for (let i = 0; i < prefix.length; i += 1) {
    if (line.charCodeAt(from + i) !== prefix.charCodeAt(i)) return false;
  }
  return true;
}

/**
 * Traditional OpenSSL encryption headers that sit between BEGIN and the
 * base64 body: `Proc-Type: 4,ENCRYPTED` and `DEK-Info: <ALGO>,<hex>`.
 * The algorithm is uppercase letters, digits, and hyphens. The IV is an
 * even run of at least 8 hex digits. Anything else is prose.
 */
function isLegacyPemHeader(line: string): boolean {
  const span = pemTrimmed(line);
  const proc = 'Proc-Type: 4,ENCRYPTED';
  if (span.end - span.start === proc.length && pemStartsWith(line, span.start, span.end, proc)) {
    return true;
  }
  const dek = 'DEK-Info: ';
  if (!pemStartsWith(line, span.start, span.end, dek)) return false;
  let i = span.start + dek.length;
  let algo = 0;
  while (i < span.end) {
    const code = line.charCodeAt(i);
    const ok = (code >= 65 && code <= 90) || (code >= 48 && code <= 57) || code === 45;
    if (!ok) break;
    algo += 1;
    i += 1;
  }
  if (algo < 1 || i >= span.end || line.charCodeAt(i) !== 44) return false;
  i += 1;
  const hexStart = i;
  while (i < span.end) {
    const code = line.charCodeAt(i);
    const ok =
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 70) ||
      (code >= 97 && code <= 102);
    if (!ok) return false;
    i += 1;
  }
  const hex = i - hexStart;
  return hex >= 8 && hex % 2 === 0;
}

interface PemLineBreak {
  contentEnd: number;
  next: number;
  breakAt: number;
  hasBreak: boolean;
}

/**
 * One PEM line. LF, CRLF, and a lone CR are breaks. A CR that is part of
 * CRLF is not its own line. `breakAt` is the first break character, which
 * stays in the output when more text follows the body.
 */
function readPemLine(text: string, i: number): PemLineBreak {
  let k = i;
  const n = text.length;
  while (k < n) {
    const code = text.charCodeAt(k);
    if (code === 10 || code === 13) break;
    k += 1;
  }
  if (k >= n) return { contentEnd: k, next: k, breakAt: k, hasBreak: false };
  let next = k + 1;
  if (text.charCodeAt(k) === 13 && next < n && text.charCodeAt(next) === 10) next += 1;
  return { contentEnd: k, next, breakAt: k, hasBreak: true };
}

/**
 * Index where the private-key body that follows a header ends.
 * `from` is the first character after the header. Blank space on the header
 * line is skipped. A full key line is consumed. A partial line consumes
 * only its leading base64 run when prose follows a space, so the trailing
 * prose stays. A path on its own line is not a partial key line. The break
 * after the last consumed body line stays when more text follows (LF,
 * CRLF, or a lone CR), and it is consumed when that break is the end of
 * the input.
 * A short line (1 to 15 characters) or a blank line does not end the body
 * when a key line follows it. Those gap lines are inside the replaced
 * span. The same is true of a `Proc-Type: 4,ENCRYPTED` line and a
 * `DEK-Info` line. After a gap, masking resumes on any base64 line that
 * is at least as wide as the block's first body line, or the same width,
 * including 44 and 76. A shorter final line resumes when it contains
 * `+`, `/`, or `=`, or when it is base64-only and at least 16 characters
 * (the key's last line). That includes an alphanumeric line of 16 to 43
 * characters after one or two resumed full-width body lines, even when
 * the line looks like a name. A camelCase, PascalCase, or snake_case word
 * does not resume when it follows the gap and no body line has resumed.
 * It stays when every part is a real word or a common abbreviation
 * (`JSON`, `URL`, `ID`, `HTTP`), or when it is word-shaped camelCase:
 * at least two humps, mostly lowercase, each longer hump containing a
 * vowel (`getUserProfileById`, `fetchAccountBalance`). A random capital
 * is not enough. Digits in a camelCase or PascalCase word are only a
 * trailing run. An acronym of real words (`HTTPServerConfig`,
 * `parseJSONResponse`) does not resume in that same place. A single
 * leading `+` or `-` is a diff marker when the BEGIN line carries
 * that prefix or every body line does. Inside an `@@` hunk, one leading
 * space, `+`, or `-` is a marker on any line, and the BEGIN line does
 * not have to carry it. `+++` and `---` are not stripped.
 * A `+` that starts a short final key line in a normal PEM block is
 * base64 and stays inside the block. A name that
 * follows a resumed body line does resume: the identifier keep does not
 * apply there. A 48-hex or 56-hex string does not resume while the gap
 * is open. A hex digest (32, 40, 64, 96, or 128 hex digits) does not
 * resume while the gap is open, and a hex-only line that is body-shaped
 * does not end the block: the scan keeps going, so a later body line is
 * not left raw. A hex digest directly after a resumed body line is body,
 * because that line is also a legal key line. The first other line stops
 * the scan, so a 64-hex or 40-hex hash, a 16-character identifier, a longer
 * camelCase or snake_case name, a 48-hex or 56-hex string,
 * `/src/components/Button.tsx`, and `ok` before a sha stay when they
 * follow the gap. Words with spaces, punctuation, and paths stay too.
 * A short line ends the body when the next line is prose or the input
 * ends, so `Next`, `README`, `npm`, `test`, `TODO`, and a short mixed-case
 * line such as `Ab1` stay, and so does a letter-only fragment such as
 * `QUJD`. The scan does not read past the line that stops it. Returns
 * `from` when there is no body line. One forward pass, plus one look at
 * the BEGIN line and the body lines to decide whether a leading `+` or
 * `-` is a diff mark. Inside an `@@` hunk that look is skipped: one
 * leading space, `+`, or `-` on any line is a marker, and the BEGIN
 * line does not have to carry it.
 */
function pemHeaderLine(text: string, headerEnd: number): string {
  let lineStart = headerEnd;
  while (lineStart > 0) {
    const code = text.charCodeAt(lineStart - 1);
    if (code === 10 || code === 13) break;
    lineStart -= 1;
  }
  const br = readPemLine(text, lineStart);
  return text.slice(lineStart, br.contentEnd);
}

/** A key line with no diff mark. An identifier is not a key line. */
function isUnmarkedKeyLine(line: string): boolean {
  if (hasSingleDiffMark(line)) return false;
  if (isCamelOrPascalIdentifier(line, PEM_MARK_NONE)) return false;
  return isPemBodyLine(line, PEM_MARK_NONE) || pemPartialCut(line, PEM_MARK_NONE) >= 0;
}

/**
 * A key line whose single leading `+` or `-` is a diff mark.
 * A line that is already key text without stripping is base64 that
 * starts with `+`, not evidence of a diff. One or two such lines do
 * not make the block a diff.
 */
function isMarkedKeyLine(line: string): boolean {
  if (!hasSingleDiffMark(line)) return false;
  if (isPemBodyLine(line, PEM_MARK_NONE) || pemPartialCut(line, PEM_MARK_NONE) >= 0) return false;
  if (isCamelOrPascalIdentifier(line, PEM_MARK_SIGN)) return false;
  return isPemBodyLine(line, PEM_MARK_SIGN) || pemPartialCut(line, PEM_MARK_SIGN) >= 0;
}

/**
 * True when every key line after the header carries one diff mark.
 * A short gap and a legacy header do not count. The walk stops at the
 * first other line, so it does not read past this block. False when no
 * key line was seen.
 */
function everyDiffBodyLineIsMarked(text: string, from: number): boolean {
  let i = from;
  let onHeaderLine = true;
  let saw = false;
  while (i < text.length) {
    const br = readPemLine(text, i);
    if (br.next === i) break;
    const line = text.slice(i, br.contentEnd);
    if (onHeaderLine) {
      onHeaderLine = false;
      let onlySpace = true;
      for (let p = 0; p < line.length; p += 1) {
        const code = line.charCodeAt(p);
        if (code !== 32 && code !== 9 && code !== 13) {
          onlySpace = false;
          break;
        }
      }
      if (onlySpace) {
        i = br.next;
        continue;
      }
    }
    if (isUnmarkedKeyLine(line)) return false;
    if (isMarkedKeyLine(line)) {
      saw = true;
      if (!br.hasBreak) break;
      i = br.next;
      continue;
    }
    if (isShortOrBlankPemLine(line) || isLegacyPemHeader(line)) {
      if (!br.hasBreak) break;
      i = br.next;
      continue;
    }
    break;
  }
  return saw;
}

function pemBodyEnd(text: string, from: number, inHunk: boolean): number {
  // Inside an @@ hunk every line may carry its own marker. A context
  // space on BEGIN, or a mix of space, +, and -, is still one block.
  let mark = PEM_MARK_NONE;
  if (inHunk) mark = PEM_MARK_HUNK;
  else if (hasSingleDiffMark(pemHeaderLine(text, from))) mark = PEM_MARK_SIGN;
  else if (everyDiffBodyLineIsMarked(text, from)) mark = PEM_MARK_SIGN;
  let i = from;
  let consumed = from;
  let onHeaderLine = true;
  let seenBody = false;
  let pendingGap = false;
  let bodyWidth = 0;
  while (i < text.length) {
    const br = readPemLine(text, i);
    if (br.next === i) break;
    const line = text.slice(i, br.contentEnd);
    if (onHeaderLine) {
      onHeaderLine = false;
      let onlySpace = true;
      for (let p = 0; p < line.length; p += 1) {
        const code = line.charCodeAt(p);
        if (code !== 32 && code !== 9 && code !== 13) {
          onlySpace = false;
          break;
        }
      }
      if (onlySpace) {
        i = br.next;
        continue;
      }
    }
    if (isPemBodyLine(line, mark)) {
      // The identifier keep applies only while the gap is still open.
      // A line that follows a resumed body line is the key's next line,
      // even when it looks like a camelCase name.
      if (seenBody && pendingGap && !resumesAfterPemGap(line, bodyWidth, mark)) {
        // A hex-only body-shaped line is not prose and not a stopping
        // line. Keep the gap open so a later body line is still masked.
        // A 48-hex or 56-hex string does not resume. With only prose
        // after it, that line stays. A later body line is still masked,
        // and the hex line stays inside that span.
        // A digest with only prose after it is not consumed.
        if (isPureHexLine(line, mark)) {
          if (!br.hasBreak) break;
          pendingGap = true;
          i = br.next;
          continue;
        }
        break;
      }
      if (bodyWidth === 0) bodyWidth = pemTrimWidth(line, mark);
      if (!br.hasBreak || br.next >= text.length) {
        consumed = br.next;
        break;
      }
      consumed = br.breakAt;
      seenBody = true;
      pendingGap = false;
      i = br.next;
      continue;
    }
    const partial = pemPartialCut(line, mark);
    if (partial >= 0) {
      if (seenBody && pendingGap) break;
      consumed = i + partial;
      break;
    }
    if (isShortOrBlankPemLine(line) || isLegacyPemHeader(line)) {
      if (!br.hasBreak) break;
      if (seenBody) pendingGap = true;
      i = br.next;
      continue;
    }
    break;
  }
  return consumed;
}

/** Digits at `i`, or `i` when there are none. */
function readPemDecimal(line: string, i: number): number {
  const start = i;
  const n = line.length;
  while (i < n) {
    const code = line.charCodeAt(i);
    if (code < 48 || code > 57) break;
    i += 1;
  }
  return i === start ? start : i;
}

/**
 * Index just after the closing `@@` of a hunk header, or -1.
 * `@@ -1,5 +1,5 @@` and `@@ -1 +1 @@` both match. Function-context
 * text after the closing `@@` is allowed. One forward pass.
 */
function unifiedHunkHeadEnd(line: string): number {
  const n = line.length;
  if (n < 8 || line.charCodeAt(0) !== 64 || line.charCodeAt(1) !== 64 || line.charCodeAt(2) !== 32) {
    return -1;
  }
  let i = 3;
  if (line.charCodeAt(i) !== 45) return -1;
  const first = readPemDecimal(line, i + 1);
  if (first === i + 1) return -1;
  i = first;
  if (i < n && line.charCodeAt(i) === 44) {
    const after = readPemDecimal(line, i + 1);
    if (after === i + 1) return -1;
    i = after;
  }
  if (i + 1 >= n || line.charCodeAt(i) !== 32 || line.charCodeAt(i + 1) !== 43) return -1;
  const plus = i + 2;
  i = readPemDecimal(line, plus);
  if (i === plus) return -1;
  if (i < n && line.charCodeAt(i) === 44) {
    const after = readPemDecimal(line, i + 1);
    if (after === i + 1) return -1;
    i = after;
  }
  if (i + 2 < n && line.charCodeAt(i) === 32 && line.charCodeAt(i + 1) === 64 && line.charCodeAt(i + 2) === 64) {
    return i + 3;
  }
  return -1;
}

/** A unified-diff hunk header: `@@ -1,5 +1,5 @@` or `@@ -1 +1 @@`. */
function isUnifiedHunkHeader(line: string): boolean {
  return unifiedHunkHeadEnd(line) >= 0;
}

/** A diff body line. A space, `+`, `-`, or `\` keeps the current hunk open. */
function isUnifiedDiffPayload(line: string): boolean {
  if (line.length < 1) return false;
  const code = line.charCodeAt(0);
  return code === 32 || code === 43 || code === 45 || code === 92;
}

/**
 * Hunk state after `line`. Only an `@@` header opens a hunk. A payload
 * line keeps it open. Any other line closes it, so a later PEM block
 * outside the hunk is not marked.
 */
function hunkStateAfterLine(line: string, inHunk: boolean): boolean {
  if (isUnifiedHunkHeader(line)) return true;
  if (isUnifiedDiffPayload(line)) return inHunk;
  return false;
}

/**
 * Replace private-key PEM blocks. One left-to-right scan.
 * A complete block, BEGIN through a private-key END, is replaced. The END
 * kind does not have to match the BEGIN kind. A header with no matching
 * END is replaced from the header through the base64 body. A body line is
 * key-shaped base64: 16 characters, or a shorter multiple of 4 that
 * contains a digit, `+`, `/`, or `=` (including 4 characters, such as
 * `YQ==`). LF, CRLF, and a lone CR are line breaks. A short or blank line
 * stays inside the block when a key line follows it, and so
 * does `Proc-Type: 4,ENCRYPTED` and a `DEK-Info` header. After a gap,
 * masking resumes on a base64 line at least as wide as the first body
 * line, or the same width, on a shorter final line that contains `+`,
 * `/`, or `=`, and on a base64-only final line of at least 16 characters.
 * That final line stays redacted after one or two resumed full-width
 * body lines, including when it looks like an identifier. A single
 * leading `+` or `-` on a body line is a diff marker when the BEGIN
 * line carries that prefix or every body line does. Inside an `@@` hunk
 * a leading space, `+`, or `-` is a diff marker on any line, so a
 * context BEGIN and a mix of those prefixes are still one block. The
 * hunk may end before the END line. A private key in an unfenced unified
 * diff is still one block. `+++` and `---` are file markers and are not
 * stripped. A leading `+` on a short final line of a normal PEM block is
 * key text, so that line stays inside the block. A line that is already
 * key text without stripping is not evidence that the block is a diff.
 * A hex digest
 * stays visible when it follows the gap. A 48-hex or 56-hex string does
 * not resume while the gap is open, so it stays visible when prose
 * follows, and it does not end the block when a later body line still
 * has to be masked. Directly after a resumed body line, a hex digest is
 * body, because it is also a legal key line. A camelCase, PascalCase, or
 * snake_case word ends the block when it follows the gap and no body line
 * has resumed. It ends the block when every part is a real word or a
 * common abbreviation (`JSON`, `URL`, `ID`, `HTTP`), and also when the
 * name is word-shaped camelCase (`getUserProfileById`,
 * `fetchAccountBalance`, `handleWebSocketMsg`). A random capital is not
 * enough. Digits in a camelCase or PascalCase word are only a trailing
 * run. An acronym of real words (`HTTPServerConfig`, `parseJSONResponse`)
 * ends the block in that same place.
 * A hex-only body-shaped line does not end the block. The first
 * other line stops the scan and stays visible, including a 64-hex or
 * 40-hex hash, a 16-character identifier, a longer camelCase or
 * snake_case name, a path, and `ok` before a sha, when those follow
 * the gap. Words with spaces and punctuation stay too.
 * A short line ends the block when prose or the
 * end of the input follows, so `Next`, `README`, `npm`, `test`, `TODO`,
 * and `Ab1` stay, and so does a letter-only fragment such as `QUJD`. A
 * partial line redacts its leading base64 run when a space separates the
 * prose. The break after the block stays when more text follows,
 * so that text does not glue to the marker. A truncated block at the end
 * of the input is still replaced. A header with no body line is copied
 * through. The END search never rewinds: a miss covers the rest of the buffer.
 * A later hunk of the same file can have no BEGIN line. That pass does
 * not see it. `redactKeyHunkLines` redacts those body lines when the
 * file has a key block or a private-key-block, secret-looking-path, or
 * high-entropy-secret finding. The `@@` function context is redacted
 * only when that context is base64-like.
 */
function redactPrivateKeyBlocks(
  text: string,
  keyPaths?: readonly string[],
  secretFilePaths?: readonly string[],
): string {
  const parts: string[] = [];
  let i = 0;
  // Next -----END at or after endCursor. -2 means none remains.
  let endCursor = 0;
  let nextEnd = -1;
  // Lines already classified for the hunk state. One forward pass.
  let hunkScan = 0;
  let inHunk = false;
  const syncHunk = (to: number): void => {
    while (hunkScan < to) {
      const br = readPemLine(text, hunkScan);
      if (br.contentEnd >= to) break;
      inHunk = hunkStateAfterLine(text.slice(hunkScan, br.contentEnd), inHunk);
      if (!br.hasBreak) {
        hunkScan = br.next;
        break;
      }
      hunkScan = br.next;
    }
  };
  const peekEnd = (from: number): number => {
    if (nextEnd === -2) return -1;
    if (nextEnd >= from) return nextEnd;
    const found = text.indexOf(PEM_END, Math.max(from, endCursor));
    if (found < 0) {
      nextEnd = -2;
      endCursor = text.length;
      return -1;
    }
    nextEnd = found;
    endCursor = found + PEM_END.length;
    return found;
  };
  while (i < text.length) {
    const start = text.indexOf(PEM_BEGIN, i);
    if (start < 0) {
      parts.push(text.slice(i));
      break;
    }
    syncHunk(start);
    parts.push(text.slice(i, start));
    const headerAt = start + PEM_BEGIN.length;
    const headerEnd = pemPrivateKeyEnd(text, headerAt);
    if (headerEnd < 0) {
      parts.push(PEM_BEGIN);
      i = headerAt;
      continue;
    }
    const beginInHunk = inHunk;
    let cursor = headerEnd;
    let matched = false;
    while (cursor < text.length) {
      const endAt = peekEnd(cursor);
      if (endAt < 0) break;
      const endStop = pemPrivateKeyEnd(text, endAt + PEM_END.length);
      if (endStop >= 0) {
        parts.push(PEM_BLOCK_REPLACEMENT);
        i = endStop;
        matched = true;
        if (nextEnd === endAt) nextEnd = -1;
        break;
      }
      cursor = endAt + PEM_END.length;
      if (nextEnd === endAt) nextEnd = -1;
    }
    if (!matched) {
      const bodyEnd = pemBodyEnd(text, headerEnd, beginInHunk);
      if (bodyEnd > headerEnd) {
        parts.push(PEM_BLOCK_REPLACEMENT);
        i = bodyEnd;
      } else {
        parts.push(text.slice(start, headerEnd));
        i = headerEnd;
      }
    }
  }
  return redactKeyHunkLines(parts.join(''), keyPaths, secretFilePaths);
}

interface PemTextLine {
  start: number;
  contentEnd: number;
  next: number;
}

function collectPemLines(text: string): PemTextLine[] {
  const lines: PemTextLine[] = [];
  let i = 0;
  while (i < text.length) {
    const br = readPemLine(text, i);
    lines.push({ start: i, contentEnd: br.contentEnd, next: br.next });
    if (!br.hasBreak) break;
    i = br.next;
  }
  return lines;
}

/** End index of a private-key BEGIN or END marker at `from`, or -1. */
function privateKeyMarkerEnd(line: string, from: number): number {
  if (from < 0 || from >= line.length) return -1;
  const begin = line.startsWith(PEM_BEGIN, from);
  if (!begin && !line.startsWith(PEM_END, from)) return -1;
  const kindAt = from + (begin ? PEM_BEGIN.length : PEM_END.length);
  return pemPrivateKeyEnd(line, kindAt);
}

function isDiffGitLine(line: string): boolean {
  return line.startsWith('diff --git ');
}

/** `--- a/path` or `+++ b/path`. A deleted line that starts with `--` is not this. */
function isGitDiffFileMarker(line: string): boolean {
  return (
    line.startsWith('--- a/') ||
    line.startsWith('--- b/') ||
    line.startsWith('+++ a/') ||
    line.startsWith('+++ b/') ||
    line.startsWith('--- /dev/null') ||
    line.startsWith('+++ /dev/null')
  );
}

function pathFromDiffGit(line: string): string | null {
  const prefix = 'diff --git ';
  if (!line.startsWith(prefix)) return null;
  const rest = line.slice(prefix.length);
  if (rest.startsWith('"')) {
    const endQuote = rest.indexOf('"', 1);
    if (endQuote < 0) return null;
    const after = rest.slice(endQuote + 1).trim();
    if (after.startsWith('"') && after.endsWith('"')) {
      const inner = after.slice(1, -1);
      return inner.startsWith('b/') ? inner.slice(2) : inner;
    }
    return null;
  }
  const at = rest.lastIndexOf(' b/');
  if (at < 0) return null;
  return rest.slice(at + 3);
}

function pathFromFileMarker(line: string): string | null {
  if (line.startsWith('+++ b/')) return line.slice(6);
  if (line.startsWith('+++ a/')) return line.slice(6);
  if (line.startsWith('--- a/')) return line.slice(6);
  if (line.startsWith('--- b/')) return line.slice(6);
  if (line.startsWith('+++ /dev/null') || line.startsWith('--- /dev/null')) return null;
  return null;
}

function noteDiffPath(path: string | null, line: string): string | null {
  const gitPath = pathFromDiffGit(line);
  if (gitPath) return gitPath;
  if (line.startsWith('+++ ')) return pathFromFileMarker(line) ?? path;
  if (!path && line.startsWith('--- ')) return pathFromFileMarker(line);
  return path;
}

/** A markdown fence or heading. A diff payload line is not a heading. */
function endsDiffRegion(line: string): boolean {
  if (line.trim() === '```') return true;
  return line.startsWith('#');
}

function isDiffRegionStart(line: string): boolean {
  return isDiffGitLine(line) || isUnifiedHunkHeader(line) || isGitDiffFileMarker(line);
}

function sameKeyPath(left: string, right: string): boolean {
  if (left === right) return true;
  if (left.endsWith(`/${right}`)) return true;
  if (right.endsWith(`/${left}`)) return true;
  return false;
}

function pathMatchesFinding(path: string, findings: Set<string>): boolean {
  for (const found of findings) {
    if (sameKeyPath(path, found)) return true;
  }
  return false;
}

/**
 * Same paths `risk.ts` flags as `secret-looking-path`. A `.pem` file is
 * one. `app.py` is not. The check is the path text only.
 */
function isSecretLookingPath(path: string): boolean {
  const n = path.replace(/\\/g, '/');
  if (/(^|\/)(secrets?|credentials?)\.(json|ya?ml|toml|env)$/i.test(n)) return true;
  if (/(^|\/).*\.(pem|p12|pfx)$/i.test(n)) return true;
  if (/(^|\/).*(?<!\.pub)\.key$/i.test(n)) return true;
  if (/(^|\/)id_rsa$/i.test(n)) return true;
  if (/(^|\/)\.npmrc$/i.test(n)) return true;
  if (/(^|\/)aws[_-]?credentials$/i.test(n)) return true;
  if (/(^|\/)\.netrc$/i.test(n)) return true;
  return false;
}

/** A risk-table row or a numbered review line. A diff payload is not one. */
function isRiskFindingLine(line: string): boolean {
  if (line.charCodeAt(0) === 124) return true;
  let i = 0;
  const n = line.length;
  while (i < n) {
    const code = line.charCodeAt(i);
    if (code < 48 || code > 57) break;
    i += 1;
  }
  return i > 0 && line.startsWith('. **', i);
}

function trimFindingPath(raw: string): string {
  let path = raw.trim();
  const bar = path.indexOf('|');
  if (bar >= 0) path = path.slice(0, bar).trim();
  if (path.endsWith('\\')) path = path.slice(0, -1).trim();
  return path;
}

interface KeyHunkFindings {
  all: Set<string>;
  secretFile: Set<string>;
}

/**
 * Paths named by a finding that makes a later key hunk sensitive.
 * `private-key-block` detail is `private key block appears in diff: <path>`.
 * `secret-looking-path` detail is `Secret-looking path (<label>): <path>`.
 * `high-entropy-secret` detail ends with ` in <path>`.
 * A private-key-block or secret-looking-path path is a secret file, and so
 * is a high-entropy path whose name already looks like key material.
 * A diff line that merely mentions the code is not a finding. One forward pass.
 */
function collectKeyHunkFindings(text: string): KeyHunkFindings {
  const all = new Set<string>();
  const secretFile = new Set<string>();
  const add = (path: string, secret: boolean): void => {
    if (!path) return;
    all.add(path);
    if (secret || isSecretLookingPath(path)) secretFile.add(path);
  };
  let i = 0;
  while (i < text.length) {
    const br = readPemLine(text, i);
    const line = text.slice(i, br.contentEnd);
    if (isRiskFindingLine(line)) {
      if (line.includes('private-key-block')) {
        const marker = 'appears in diff: ';
        const markAt = line.indexOf(marker);
        if (markAt >= 0) add(trimFindingPath(line.slice(markAt + marker.length)), true);
      }
      if (line.includes('secret-looking-path')) {
        const prefix = line.indexOf('Secret-looking path (');
        if (prefix >= 0) {
          const close = line.indexOf('): ', prefix);
          if (close >= 0) add(trimFindingPath(line.slice(close + 3)), true);
        }
      }
      if (line.includes('high-entropy-secret')) {
        const markAt = line.lastIndexOf(' in ');
        if (markAt >= 0) add(trimFindingPath(line.slice(markAt + 4)), false);
      }
    }
    if (!br.hasBreak) break;
    i = br.next;
  }
  return { all, secretFile };
}

/** True when the line is a BEGIN or END private-key marker, with one diff mark. */
function lineSignalsPrivateKey(line: string): boolean {
  if (privateKeyMarkerEnd(line, 0) >= 0) return true;
  if (line.length > 1 && !isGitDiffFileMarker(line)) {
    const code = line.charCodeAt(0);
    if ((code === 32 || code === 43 || code === 45) && privateKeyMarkerEnd(line, 1) >= 0) {
      return true;
    }
  }
  const headEnd = unifiedHunkHeadEnd(line);
  if (headEnd >= 0) {
    let ctx = headEnd;
    if (ctx < line.length && line.charCodeAt(ctx) === 32) ctx += 1;
    if (privateKeyMarkerEnd(line, ctx) >= 0) return true;
  }
  return false;
}

function hunkPayloadMarkLength(line: string): number {
  if (line.length < 1) return 0;
  const code = line.charCodeAt(0);
  if (code === 32 || code === 43 || code === 45) return 1;
  return 0;
}

function isHunkPayloadLine(line: string): boolean {
  return isUnifiedDiffPayload(line) && !isGitDiffFileMarker(line);
}

/**
 * Replace function-context text on a hunk of a key file when that text
 * is base64-like. Git copies the previous line into
 * `@@ -1,5 +1,5 @@ <that line>`. A mid-body hunk has no BEGIN line, so
 * a key line copied there is raw key material. Ordinary code such as
 * `def handler(event):` stays. An empty context stays empty. A short
 * ordinary token such as `Zm9v` stays on a file that is not a secret file.
 */
function redactHunkHeaderContext(line: string, secretFile: boolean): string {
  const headEnd = unifiedHunkHeadEnd(line);
  if (headEnd < 0 || headEnd >= line.length) return line;
  let ctxFrom = headEnd;
  if (line.charCodeAt(ctxFrom) === 32) ctxFrom += 1;
  let ctxEnd = line.length;
  while (ctxEnd > ctxFrom) {
    const code = line.charCodeAt(ctxEnd - 1);
    if (code !== 32 && code !== 9 && code !== 13) break;
    ctxEnd -= 1;
  }
  if (ctxEnd <= ctxFrom) return line;
  const context = line.slice(ctxFrom, ctxEnd);
  if (!isPemBodyLine(context, PEM_MARK_NONE)) return line;
  if (!secretFile && isShortOrdinaryBase64Span(context, 0, context.length)) return line;
  const lead = ctxFrom > headEnd ? ' ' : '';
  return `${line.slice(0, headEnd)}${lead}[REDACTED]`;
}

/**
 * Redact one hunk payload line. The diff marker stays. Prose after a
 * partial key stays. A short ordinary token such as `Zm9v` stays when
 * the file is not a secret file.
 */
function redactHunkPayloadLine(line: string, secretFile: boolean): string {
  if (line.charCodeAt(0) === 92) return line;
  if (!secretFile) {
    const span = hunkKeySpan(line);
    if (isShortOrdinaryBase64Span(line, span.start, span.end)) return line;
  }
  if (isPemBodyLine(line, PEM_MARK_HUNK)) {
    return `${line.slice(0, hunkPayloadMarkLength(line))}[REDACTED]`;
  }
  const partial = pemPartialCut(line, PEM_MARK_HUNK);
  if (partial >= 0) {
    return `${line.slice(0, hunkPayloadMarkLength(line))}[REDACTED]${line.slice(partial)}`;
  }
  return line;
}

/**
 * `@@` context on a secret-looking file with no finding. Redact it only
 * when the copied line is low-entropy key material. Ordinary code stays.
 * A high-entropy line stays until a finding names the file.
 */
function redactLowEntropyHeader(line: string): string {
  const headEnd = unifiedHunkHeadEnd(line);
  if (headEnd < 0 || headEnd >= line.length) return line;
  let ctxFrom = headEnd;
  if (line.charCodeAt(ctxFrom) === 32) ctxFrom += 1;
  let ctxEnd = line.length;
  while (ctxEnd > ctxFrom) {
    const code = line.charCodeAt(ctxEnd - 1);
    if (code !== 32 && code !== 9 && code !== 13) break;
    ctxEnd -= 1;
  }
  if (ctxEnd <= ctxFrom) return line;
  const context = line.slice(ctxFrom, ctxEnd);
  if (!isPemBodyLine(context, PEM_MARK_NONE)) return line;
  if (!isLowEntropyKeyMaterial(line, ctxFrom, ctxEnd)) return line;
  const lead = ctxFrom > headEnd ? ' ' : '';
  return `${line.slice(0, headEnd)}${lead}[REDACTED]`;
}

/** One payload line. The diff marker stays. High-entropy key text stays. */
function redactLowEntropyPayload(line: string): string {
  if (line.charCodeAt(0) === 92) return line;
  const span = hunkKeySpan(line);
  if (isPemBodyLine(line, PEM_MARK_HUNK) && isLowEntropyKeyMaterial(line, span.start, span.end)) {
    return `${line.slice(0, hunkPayloadMarkLength(line))}[REDACTED]`;
  }
  const partial = pemPartialCut(line, PEM_MARK_HUNK);
  if (partial >= 0 && isLowEntropyKeyMaterial(line, span.start, partial)) {
    return `${line.slice(0, hunkPayloadMarkLength(line))}[REDACTED]${line.slice(partial)}`;
  }
  return line;
}

function redactLowEntropyDiff(text: string, lines: PemTextLine[], region: KeyDiffRegion): string {
  const parts: string[] = [];
  let inHunk = false;
  for (let i = region.start; i < region.end; i += 1) {
    const rec = lines[i];
    const content = text.slice(rec.start, rec.contentEnd);
    const br = text.slice(rec.contentEnd, rec.next);
    if (isUnifiedHunkHeader(content)) {
      inHunk = true;
      parts.push(redactLowEntropyHeader(content), br);
      continue;
    }
    if (inHunk && isHunkPayloadLine(content)) {
      parts.push(redactLowEntropyPayload(content), br);
      continue;
    }
    inHunk = false;
    parts.push(content, br);
  }
  return parts.join('');
}

interface KeyDiffRegion {
  start: number;
  end: number;
  sensitive: boolean;
  secretFile: boolean;
  /** Secret-looking file, no BEGIN/END and no finding. Low-entropy body only. */
  lowEntropyOnly: boolean;
}

/** Same skip the risk scanner uses before it emits `high-entropy-secret`. */
const BARE_KEY_ENTROPY_MIN = 32;
const BARE_KEY_ENTROPY_UNIQ = 10;
const BARE_KEY_ENTROPY = 4.2;

/**
 * True when [start, end) would not produce a high-entropy finding.
 * Unique characters under 10, or Shannon entropy under 4.2. One or two
 * passes over that span. Shorter than 32 characters is not this case.
 */
function isLowEntropyKeyMaterial(line: string, start: number, end: number): boolean {
  const n = end - start;
  if (n < BARE_KEY_ENTROPY_MIN) return false;
  const seen = new Uint8Array(128);
  let uniq = 0;
  for (let i = start; i < end; i += 1) {
    const code = line.charCodeAt(i);
    if (code >= 128) return false;
    if (seen[code] === 0) {
      seen[code] = 1;
      uniq += 1;
    }
  }
  if (uniq < BARE_KEY_ENTROPY_UNIQ) return true;
  const freq = new Uint16Array(128);
  for (let i = start; i < end; i += 1) freq[line.charCodeAt(i)] += 1;
  let entropy = 0;
  for (let c = 0; c < 128; c += 1) {
    const count = freq[c];
    if (count === 0) continue;
    const p = count / n;
    entropy -= p * Math.log2(p);
  }
  return entropy < BARE_KEY_ENTROPY;
}

function textMayHoldBareKeyFile(text: string): boolean {
  return (
    text.includes('.pem') ||
    text.includes('.key') ||
    text.includes('.p12') ||
    text.includes('.pfx') ||
    text.includes('id_rsa') ||
    text.includes('.npmrc') ||
    text.includes('.netrc') ||
    text.includes('credentials')
  );
}

function findKeyDiffRegions(
  text: string,
  lines: PemTextLine[],
  findings: Set<string>,
  secretFiles: Set<string>,
): KeyDiffRegion[] {
  const regions: KeyDiffRegion[] = [];
  let i = 0;
  while (i < lines.length) {
    const content = text.slice(lines[i].start, lines[i].contentEnd);
    if (!isDiffRegionStart(content)) {
      i += 1;
      continue;
    }
    const start = i;
    let path = noteDiffPath(null, content);
    let signalsKey = lineSignalsPrivateKey(content);
    i += 1;
    while (i < lines.length) {
      const line = text.slice(lines[i].start, lines[i].contentEnd);
      if (isDiffGitLine(line) || endsDiffRegion(line)) break;
      path = noteDiffPath(path, line);
      if (lineSignalsPrivateKey(line)) signalsKey = true;
      i += 1;
    }
    const flagged = Boolean(path && pathMatchesFinding(path, findings));
    const sensitive = signalsKey || flagged;
    const secretFile = path
      ? isSecretLookingPath(path) || pathMatchesFinding(path, secretFiles)
      : signalsKey;
    const lowEntropyOnly = !sensitive && Boolean(path && isSecretLookingPath(path));
    regions.push({ start, end: i, sensitive, secretFile, lowEntropyOnly });
  }
  return regions;
}

function redactSensitiveDiff(text: string, lines: PemTextLine[], region: KeyDiffRegion): string {
  const parts: string[] = [];
  let inHunk = false;
  for (let i = region.start; i < region.end; i += 1) {
    const rec = lines[i];
    const content = text.slice(rec.start, rec.contentEnd);
    const br = text.slice(rec.contentEnd, rec.next);
    if (isUnifiedHunkHeader(content)) {
      inHunk = true;
      parts.push(redactHunkHeaderContext(content, region.secretFile), br);
      continue;
    }
    if (inHunk && isHunkPayloadLine(content)) {
      parts.push(redactHunkPayloadLine(content, region.secretFile), br);
      continue;
    }
    inHunk = false;
    parts.push(content, br);
  }
  return parts.join('');
}

/**
 * Redact base64-like key lines in every hunk of a file that has a
 * private-key block, or that a secret-looking-path or high-entropy-secret
 * finding already names. The block may sit in another hunk. A hunk with
 * only END, or with neither marker, is still covered. The `@@` function
 * context is redacted only when it is base64-like. A short ordinary token
 * such as `Zm9v` stays in a file that is not a secret file. A file with
 * no key block and no such finding is left alone, so an ordinary base64
 * diff stays visible. One forward pass over the lines.
 */
function redactKeyHunkLines(
  text: string,
  keyPaths?: readonly string[],
  secretFilePaths?: readonly string[],
): string {
  if (!text.includes('@@')) return text;
  const hinted =
    (keyPaths !== undefined && keyPaths.length > 0) ||
    (secretFilePaths !== undefined && secretFilePaths.length > 0);
  if (
    !hinted &&
    !text.includes('PRIVATE KEY-----') &&
    !text.includes('private-key-block') &&
    !text.includes('secret-looking-path') &&
    !text.includes('high-entropy-secret') &&
    !textMayHoldBareKeyFile(text)
  ) {
    return text;
  }
  const lines = collectPemLines(text);
  if (lines.length === 0) return text;
  const found = collectKeyHunkFindings(text);
  if (keyPaths) {
    for (const path of keyPaths) {
      if (!path) continue;
      found.all.add(path);
      if (isSecretLookingPath(path)) found.secretFile.add(path);
    }
  }
  if (secretFilePaths) {
    for (const path of secretFilePaths) {
      if (!path) continue;
      found.all.add(path);
      found.secretFile.add(path);
    }
  }
  const regions = findKeyDiffRegions(text, lines, found.all, found.secretFile);
  let actionable = false;
  for (const region of regions) {
    if (region.sensitive || region.lowEntropyOnly) {
      actionable = true;
      break;
    }
  }
  if (!actionable) return text;
  const parts: string[] = [];
  let cursor = 0;
  for (const region of regions) {
    if (!region.sensitive && !region.lowEntropyOnly) continue;
    const start = lines[region.start].start;
    const end = lines[region.end - 1].next;
    parts.push(text.slice(cursor, start));
    parts.push(region.sensitive
      ? redactSensitiveDiff(text, lines, region)
      : redactLowEntropyDiff(text, lines, region));
    cursor = end;
  }
  parts.push(text.slice(cursor));
  return parts.join('');
}

export function redactSecretsInText(
  text: string,
  opts?: { keyPaths?: readonly string[]; secretFilePaths?: readonly string[] },
): string {
  let out = redactSecretAssignments(text);
  out = maskJwtTokens(out);
  for (const { re, replacement } of SECRET_VALUE_PATTERNS) {
    if (re.source.startsWith('-----BEGIN ')) {
      out = redactPrivateKeyBlocks(out, opts?.keyPaths, opts?.secretFilePaths);
      continue;
    }
    out = typeof replacement === 'function'
      ? out.replace(re, replacement)
      : out.replace(re, replacement);
  }
  return out;
}

/**
 * Path fields printed to the user. Display only. The same strings passed
 * to the filesystem stay raw. Other strings (verdict, fingerprint, tldr)
 * are left as they are.
 */
const DISPLAYED_PATH_KEYS = new Set([
  'path',
  'jsonPath',
  'htmlPath',
  'markdownPath',
  'sigPath',
  'packagePath',
  'importPath',
  'importSigPath',
  'pagePath',
  'bundlePath',
  'relativePath',
]);

function maskDisplayedValue(value: unknown, key: string | undefined): unknown {
  if (typeof value === 'string') {
    return key !== undefined && DISPLAYED_PATH_KEYS.has(key) ? redactSecretsInText(value) : value;
  }
  if (Array.isArray(value)) return value.map((item) => maskDisplayedValue(item, undefined));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [childKey, child] of Object.entries(value)) {
      out[childKey] = maskDisplayedValue(child, childKey);
    }
    return out;
  }
  return value;
}

/** Copy of a JSON value with displayed path fields run through secret redaction. */
export function maskDisplayedJson<T>(value: T): T {
  return maskDisplayedValue(value, undefined) as T;
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
  // Risk findings sit above the diff fence. A later hunk of that file
  // may not contain BEGIN. The fence redaction still needs the path.
  // secret-looking-path and high-entropy-secret name the file too.
  const keyFindings = collectKeyHunkFindings(normalized);
  const keyFindingPaths = [...keyFindings.all];
  const secretFilePaths = [...keyFindings.secretFile];
  const all = normalized.split('\n');
  const lines = all.slice(0, integrityCutIndex(all));
  const out: string[] = [];
  let inDiffFence = false;
  let inNestedArtifactDiff = false;
  let nestedOmitted = false;
  const diffBuf: string[] = [];
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
        diffBuf.length = 0;
        out.push(line);
        continue;
      }
      if (inDiffFence && line.trim() === '```') {
        if (inNestedArtifactDiff && !nestedOmitted) {
          out.push('+[REDACTED — nested receipt/index body omitted]');
        } else if (!inNestedArtifactDiff && diffBuf.length > 0) {
          // One pass over the fence. A private-key block spans lines, so
          // redacting each diff line alone would leave the body in place.
          // keyPaths covers a hunk that has no BEGIN line when a
          // private-key-block, secret-looking-path, or high-entropy-secret
          // finding names this file.
          const redacted = redactSecretsInText(diffBuf.join('\n'), {
            keyPaths: keyFindingPaths,
            secretFilePaths,
          });
          if (redacted.length > 0) out.push(...redacted.split('\n'));
        }
        diffBuf.length = 0;
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
      diffBuf.push(line);
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
