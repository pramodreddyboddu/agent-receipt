import type { FileStat } from './git.js';
import { pathMatchesGlob } from './ignore.js';

export type Severity = 'high' | 'medium' | 'low';

export interface RiskHint {
  severity: Severity;
  code: string;
  message: string;
  path?: string;
}

export interface RiskSummary {
  high: number;
  medium: number;
  low: number;
  total: number;
  /** Highest severity present, or null if none. */
  maxSeverity: Severity | null;
}

export type FailOnThreshold = Severity;

const SECRET_PATTERNS: Array<{ re: RegExp; label: string; code: string }> = [
  { re: /(^|\/)(secrets?|credentials?)\.(json|ya?ml|toml|env)$/i, label: 'credentials file', code: 'secret-looking-path' },
  { re: /(^|\/).*\.(pem|p12|pfx)$/i, label: 'key / cert material', code: 'secret-looking-path' },
  { re: /(^|\/).*(?<!\.pub)\.key$/i, label: 'key material', code: 'secret-looking-path' },
  { re: /(^|\/)id_rsa$/i, label: 'SSH private key', code: 'secret-looking-path' },
  { re: /(^|\/)\.npmrc$/i, label: 'npmrc (may contain tokens)', code: 'secret-looking-path' },
  { re: /(^|\/)aws[_-]?credentials$/i, label: 'AWS credentials', code: 'secret-looking-path' },
  { re: /(^|\/)\.netrc$/i, label: 'netrc (may contain tokens)', code: 'secret-looking-path' },
];

/** Real env files (committed .env / .env.local / .env.production, …). */
const ENV_FILE_RE = /(^|\/)\.env(?:$|\.(?:local|development|dev|production|prod|staging|ci|sandbox))/i;
const ENV_TEMPLATE_RE =
  /(^|\/)\.env\.(example|sample|template|test|default)(?:\.|$)/i;

/** Secret-store filenames — not source like src/auth/login.ts. */
const AUTH_SECRET_FILE_RE =
  /(^|\/)(\.htpasswd|htpasswd|passwd|shadow)$|(^|\/).*(password|secret|token)s?\.(json|ya?ml|toml|env|txt|csv)$/i;

const LOCKFILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'Cargo.lock',
  'poetry.lock',
  'Gemfile.lock',
  'composer.lock',
  'go.sum',
]);

const DEPENDENCY_MANIFESTS = new Set([
  'package.json',
  'Cargo.toml',
  'pyproject.toml',
  'requirements.txt',
  'Gemfile',
  'go.mod',
  'composer.json',
]);

const CI_PATTERNS = [
  /^\.github\/workflows\//i,
  /^\.gitlab-ci\.ya?ml$/i,
  /^\.circleci\//i,
  /^Jenkinsfile$/i,
  /^\.travis\.ya?ml$/i,
];

/** Common media / font assets — low signal as binaries. */
const MEDIA_EXT_RE =
  /\.(png|jpe?g|gif|svg|ico|webp|avif|bmp|mp3|mp4|wav|ogg|woff2?|ttf|eot|otf)$/i;

/** High-signal content in diffs (not path heuristics). */
const CONTENT_PATTERNS: Array<{
  re: RegExp;
  code: string;
  label: string;
}> = [
  {
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    code: 'aws-access-key',
    label: 'AWS access key id',
  },
  {
    re: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/,
    code: 'private-key-block',
    label: 'private key block',
  },
  {
    re: /\baws[_-]?secret[_-]?access[_-]?key\s*[:=]/i,
    code: 'aws-secret-key',
    label: 'AWS secret access key assignment',
  },
  {
    re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/,
    code: 'github-token',
    label: 'GitHub token',
  },
  {
    re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
    code: 'github-token',
    label: 'GitHub fine-grained PAT',
  },
  {
    re: /\bglpat-[A-Za-z0-9\-_]{20,}\b/,
    code: 'gitlab-token',
    label: 'GitLab personal access token',
  },
  {
    re: /\bnpm_[A-Za-z0-9]{36}\b/,
    code: 'npm-token',
    label: 'npm access token',
  },
  {
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    code: 'google-api-key',
    label: 'Google API key',
  },
  {
    re: /\bya29\.[0-9A-Za-z\-_]{20,}/,
    code: 'google-oauth-token',
    label: 'Google OAuth access token',
  },
  {
    re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b/,
    code: 'stripe-secret',
    label: 'Stripe secret key',
  },
  {
    re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
    code: 'sendgrid-token',
    label: 'SendGrid API key',
  },
  {
    re: /\bAccountKey\s*=\s*[^\s;"']+/i,
    code: 'azure-account-key',
    label: 'Azure storage account key',
  },
  {
    re: /\b(?:xox[a-z]-|xapp-)[A-Za-z0-9-]{10,}/,
    code: 'slack-token',
    label: 'Slack API token',
  },
  {
    re: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{24,}\b/,
    code: 'llm-api-key',
    label: 'LLM API key',
  },
  {
    re: /\bhf_[A-Za-z0-9]{20,}\b/,
    code: 'huggingface-token',
    label: 'Hugging Face token',
  },
  {
    re: /\bgsk_[A-Za-z0-9]{20,}\b/,
    code: 'groq-api-key',
    label: 'Groq API key',
  },
  {
    re: /\bxai-[A-Za-z0-9]{20,}\b/,
    code: 'xai-api-key',
    label: 'xAI API key',
  },
  {
    re: /Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/=]{20,}/i,
    code: 'bearer-token',
    label: 'Authorization bearer token',
  },
];


/** Allowlist entry: ignore a risk code (optionally only on matching paths). */
export interface RiskAllowlistEntry {
  /** Risk code to ignore, or "*" for any code. */
  code: string;
  /** Optional path glob; when omitted, code is ignored on all paths. */
  path?: string;
}

/**
 * Parse allowlist strings from config:
 * - `package-json-change`           → ignore that code everywhere
 * - `lockfile-change:*.lock`        → code on matching paths
 * - `*:docs/**`                     → any code under docs/
 * - `env-file:.env.local`           → specific
 */
export function parseRiskAllowlist(entries: string[]): RiskAllowlistEntry[] {
  const out: RiskAllowlistEntry[] = [];
  for (const raw of entries) {
    const s = String(raw).trim();
    if (!s) continue;
    const colon = s.indexOf(':');
    if (colon <= 0) {
      out.push({ code: s });
      continue;
    }
    const code = s.slice(0, colon).trim();
    const path = s.slice(colon + 1).trim();
    if (!code) continue;
    out.push(path ? { code, path } : { code });
  }
  return out;
}

export function isRiskAllowlisted(
  hint: RiskHint,
  allowlist: RiskAllowlistEntry[],
): boolean {
  if (!allowlist.length) return false;
  for (const e of allowlist) {
    const codeOk = e.code === '*' || e.code === hint.code;
    if (!codeOk) continue;
    if (!e.path) return true;
    if (hint.path && pathMatchesGlob(hint.path, e.path)) return true;
  }
  return false;
}

export function applyRiskAllowlist(
  hints: RiskHint[],
  allowlist: RiskAllowlistEntry[] | string[],
): RiskHint[] {
  const entries = allowlist.length && typeof allowlist[0] === 'string'
    ? parseRiskAllowlist(allowlist as string[])
    : (allowlist as RiskAllowlistEntry[]);
  if (!entries.length) return hints;
  return hints.filter((h) => !isRiskAllowlisted(h, entries));
}

/** Shannon entropy in bits/char. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let e = 0;
  const n = s.length;
  for (const count of freq.values()) {
    const p = count / n;
    e -= p * Math.log2(p);
  }
  return e;
}

const HIGH_ENTROPY_TOKEN_RE =
  /(?<![A-Za-z0-9+/=_\-.])[A-Za-z0-9+/=_\-.]{32,}(?![A-Za-z0-9+/=_\-.])/g;
const ENTROPY_THRESHOLD = 4.2;
const ENTROPY_MIN_LEN = 32;
/** Skip obvious non-secrets: long hex-ish hashes alone are still flagged; skip pure paths / urls-ish. */
const ENTROPY_SKIP_RE =
  /^(?:https?:|node_modules|sha256|sha512|checksum)/i;

/** Receipt / index artifacts often embed SHA-256 footers — skip entropy noise. */
function isReceiptArtifactPath(path: string): boolean {
  const n = path.replace(/\\/g, '/');
  return /(^|\/)\.agent-receipt\//i.test(n);
}

/** Pure hex digests (git / sha256 footers) — not live secrets. */
const HEX_DIGEST_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

function scanHighEntropy(path: string, diff: string, hints: RiskHint[]): void {
  if (!diff) return;
  // Nested receipt/index bodies re-list integrity hashes — not actionable secrets
  if (isReceiptArtifactPath(path)) return;
  // Only scan added lines to cut noise from context
  const added = diff
    .split('\n')
    .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
    .map((l) => l.slice(1))
    .join('\n');
  if (!added) return;
  const seen = new Set<string>();
  for (const m of added.matchAll(HIGH_ENTROPY_TOKEN_RE)) {
    const token = m[0];
    if (token.length < ENTROPY_MIN_LEN) continue;
    if (ENTROPY_SKIP_RE.test(token)) continue;
    if (HEX_DIGEST_RE.test(token)) continue;
    // Require mixed alphabet (not all same char / trivial)
    const uniq = new Set(token).size;
    if (uniq < 10) continue;
    const ent = shannonEntropy(token);
    if (ent < ENTROPY_THRESHOLD) continue;
    const key = token.slice(0, 12);
    if (seen.has(key)) continue;
    seen.add(key);
    const preview = token.length > 20 ? `${token.slice(0, 12)}…` : token;
    hints.push({
      severity: 'high',
      code: 'high-entropy-secret',
      message: `High-entropy token (${ent.toFixed(2)} bits/char, len ${token.length}): ${preview} in ${path}`,
      path,
    });
  }
}

/** Lines changed threshold for "large diff" signal. */
const LARGE_DIFF_LINES = 400;
/** File count threshold for "broad change" signal. */
const BROAD_CHANGE_FILES = 25;

const SEVERITY_RANK: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s];
}

/** Sort by severity (high → low), then code/path. */
export function sortRisks(hints: RiskHint[]): RiskHint[] {
  return [...hints].sort((a, b) => {
    const sr = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sr !== 0) return sr;
    return a.code.localeCompare(b.code) || (a.path || '').localeCompare(b.path || '');
  });
}

/** Top-N risks already sorted by severity. */
export function topRisks(hints: RiskHint[], n = 10): RiskHint[] {
  return sortRisks(hints).slice(0, Math.max(0, n));
}

export function summarizeRisks(hints: RiskHint[]): RiskSummary {
  let high = 0;
  let medium = 0;
  let low = 0;
  for (const h of hints) {
    if (h.severity === 'high') high++;
    else if (h.severity === 'medium') medium++;
    else low++;
  }
  const total = high + medium + low;
  const maxSeverity: RiskSummary['maxSeverity'] =
    high > 0 ? 'high' : medium > 0 ? 'medium' : low > 0 ? 'low' : null;
  return { high, medium, low, total, maxSeverity };
}

export function parseFailOn(value: string | boolean | undefined): FailOnThreshold | undefined {
  if (value === undefined || value === false) return undefined;
  if (value === true) return 'high';
  const v = String(value).toLowerCase().trim();
  if (v === 'high' || v === 'medium' || v === 'low') return v;
  throw new Error('--fail-on must be high, medium, or low (bare --fail-on means high)');
}

/** True when the session's max severity is at least the --fail-on threshold. */
export function meetsFailOn(
  maxSeverity: RiskSummary['maxSeverity'],
  threshold: FailOnThreshold,
): boolean {
  if (!maxSeverity) return false;
  return SEVERITY_RANK[maxSeverity] >= SEVERITY_RANK[threshold];
}

/**
 * Read the Summary table written by formatMarkdown.
 * Redaction masks secret detail but does not change these counts.
 * Missing / unparseable tables yield an empty summary (fail-on will not trip).
 */
export function parseRiskSummaryMarkdown(markdown: string): RiskSummary {
  const empty: RiskSummary = {
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    maxSeverity: null,
  };
  const riskLine = markdown.match(/^\|\s*Risk\s*\|\s*([^|\n]+)\|/m);
  const value = riskLine?.[1]?.trim() ?? '';
  if (!value || /^none$/i.test(value)) return empty;

  const high = Number(value.match(/high\s+(\d+)/i)?.[1] ?? 0);
  const medium = Number(value.match(/medium\s+(\d+)/i)?.[1] ?? 0);
  const low = Number(value.match(/low\s+(\d+)/i)?.[1] ?? 0);
  const leading = value.match(/^(\d+)/);
  const total = leading ? Number(leading[1]) : high + medium + low;

  const maxLine = markdown.match(/^\|\s*Max severity\s*\|\s*\*\*(\w+)\*\*\s*\|/im);
  const labeled = maxLine?.[1]?.toLowerCase();
  let maxSeverity: RiskSummary['maxSeverity'] = null;
  if (labeled === 'high' || labeled === 'medium' || labeled === 'low') {
    maxSeverity = labeled;
  } else if (high > 0) maxSeverity = 'high';
  else if (medium > 0) maxSeverity = 'medium';
  else if (low > 0) maxSeverity = 'low';

  return { high, medium, low, total, maxSeverity };
}

function scanDiffContent(path: string, diff: string, hints: RiskHint[]): void {
  if (!diff) return;
  for (const pat of CONTENT_PATTERNS) {
    if (pat.re.test(diff)) {
      hints.push({
        severity: 'high',
        code: pat.code,
        message: `${pat.label} appears in diff: ${path}`,
        path,
      });
    }
  }
  scanHighEntropy(path, diff, hints);
}

export function analyzeRisks(
  files: FileStat[],
  diffs: Record<string, string> = {},
  allowlist: RiskAllowlistEntry[] | string[] = [],
): RiskHint[] {
  const hints: RiskHint[] = [];

  let totalLines = 0;
  for (const f of files) {
    totalLines += f.insertions + f.deletions;

    if (ENV_TEMPLATE_RE.test(f.path)) {
      hints.push({
        severity: 'low',
        code: 'env-template',
        message: `Env template changed (usually safe): ${f.path}`,
        path: f.path,
      });
    } else if (ENV_FILE_RE.test(f.path) || /(^|\/)\.env$/i.test(f.path)) {
      hints.push({
        severity: 'high',
        code: 'env-file',
        message: `.env file committed or changed: ${f.path}`,
        path: f.path,
      });
    }

    for (const sp of SECRET_PATTERNS) {
      if (sp.re.test(f.path)) {
        hints.push({
          severity: 'high',
          code: sp.code,
          message: `Secret-looking path (${sp.label}): ${f.path}`,
          path: f.path,
        });
      }
    }

    if (f.binary) {
      const media = MEDIA_EXT_RE.test(f.path);
      hints.push({
        severity: media ? 'low' : f.status === 'A' || f.status === 'M' ? 'medium' : 'low',
        code: 'binary-change',
        message: media
          ? `Media/font binary changed: ${f.path}`
          : `Binary file changed: ${f.path}`,
        path: f.path,
      });
    }

    const baseName = f.path.split('/').pop() || f.path;
    if (LOCKFILES.has(baseName) && (f.status === 'D' || f.deletions > f.insertions * 2)) {
      hints.push({
        severity: 'high',
        code: 'lockfile-deletion',
        message: `Lockfile deleted or heavily reduced: ${f.path}`,
        path: f.path,
      });
    } else if (LOCKFILES.has(baseName) && (f.status === 'A' || f.status === 'M')) {
      hints.push({
        severity: 'low',
        code: 'lockfile-change',
        message: `Lockfile changed: ${f.path} (+${f.insertions}/−${f.deletions})`,
        path: f.path,
      });
    }

    if (baseName === 'package.json' && (f.status === 'A' || f.status === 'M' || f.status === 'D')) {
      hints.push({
        severity: 'medium',
        code: 'package-json-change',
        message: `package.json changed: ${f.path} (+${f.insertions}/-${f.deletions})`,
        path: f.path,
      });
    } else if (DEPENDENCY_MANIFESTS.has(baseName) && (f.status === 'A' || f.status === 'M')) {
      hints.push({
        severity: 'medium',
        code: 'dependency-manifest',
        message: `Dependency manifest changed: ${f.path}`,
        path: f.path,
      });
    }

    if (AUTH_SECRET_FILE_RE.test(f.path) && !SECRET_PATTERNS.some((sp) => sp.re.test(f.path))) {
      hints.push({
        severity: 'medium',
        code: 'auth-secret-file',
        message: `Auth / secret-store file changed: ${f.path}`,
        path: f.path,
      });
    }

    if (CI_PATTERNS.some((re) => re.test(f.path))) {
      if (f.status === 'D') {
        hints.push({
          severity: 'high',
          code: 'ci-deletion',
          message: `CI / workflow file deleted: ${f.path}`,
          path: f.path,
        });
      } else if (f.status === 'A') {
        hints.push({
          severity: 'medium',
          code: 'ci-addition',
          message: `CI / workflow file added: ${f.path}`,
          path: f.path,
        });
      } else if (f.status === 'M') {
        hints.push({
          severity: 'medium',
          code: 'ci-modification',
          message: `CI / workflow file modified: ${f.path}`,
          path: f.path,
        });
      }
    }

    if (!f.binary && f.insertions + f.deletions >= LARGE_DIFF_LINES) {
      hints.push({
        severity: 'medium',
        code: 'large-file-diff',
        message: `Large diff in single file (+${f.insertions}/−${f.deletions}): ${f.path}`,
        path: f.path,
      });
    }

    const diff = diffs[f.path];
    if (diff && !f.binary) {
      scanDiffContent(f.path, diff, hints);
    }
  }

  if (files.length >= BROAD_CHANGE_FILES) {
    hints.push({
      severity: 'medium',
      code: 'broad-change',
      message: `Broad change set: ${files.length} files touched`,
    });
  }

  if (totalLines >= LARGE_DIFF_LINES * 2) {
    hints.push({
      severity: 'low',
      code: 'large-total-diff',
      message: `Large total diff volume: +/− ${totalLines} lines across ${files.length} file(s)`,
    });
  }

  const seen = new Set<string>();
  const deduped = hints.filter((h) => {
    const k = `${h.code}:${h.path || ''}:${h.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return applyRiskAllowlist(sortRisks(deduped), allowlist);
}
