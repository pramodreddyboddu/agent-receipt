import type { FileStat } from './git.js';

export interface RiskHint {
  severity: 'high' | 'medium' | 'low';
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
  maxSeverity: 'high' | 'medium' | 'low' | null;
}

const SECRET_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /(^|\/)\.env(\.|$)/i, label: 'dotenv / env file' },
  { re: /(^|\/)(secrets?|credentials?)\.(json|ya?ml|toml|env)$/i, label: 'credentials file' },
  { re: /(^|\/).*\.(pem|p12|pfx|key)$/i, label: 'key / cert material' },
  { re: /(^|\/)id_rsa(\.pub)?$/i, label: 'SSH key' },
  { re: /(^|\/)\.npmrc$/i, label: 'npmrc (may contain tokens)' },
  { re: /(^|\/)aws[_-]?credentials$/i, label: 'AWS credentials' },
  { re: /(^|\/)\.netrc$/i, label: 'netrc (may contain tokens)' },
];

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

const AUTH_PATH_RE =
  /(^|\/)(auth|oauth|jwt|session|passwd|password|token)s?([./_-]|$)/i;

const CI_PATTERNS = [
  /^\.github\/workflows\//i,
  /^\.gitlab-ci\.ya?ml$/i,
  /^\.circleci\//i,
  /^Jenkinsfile$/i,
  /^\.travis\.ya?ml$/i,
];

/** Lines changed threshold for "large diff" signal. */
const LARGE_DIFF_LINES = 400;
/** File count threshold for "broad change" signal. */
const BROAD_CHANGE_FILES = 25;


const SEVERITY_RANK: Record<RiskHint['severity'], number> = {
  high: 0,
  medium: 1,
  low: 2,
};

/** Sort by severity (high → low), then code/path. */
export function sortRisks(hints: RiskHint[]): RiskHint[] {
  return [...hints].sort((a, b) => {
    const sr = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
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

export function analyzeRisks(files: FileStat[]): RiskHint[] {
  const hints: RiskHint[] = [];

  let totalLines = 0;
  for (const f of files) {
    totalLines += f.insertions + f.deletions;

    for (const sp of SECRET_PATTERNS) {
      if (sp.re.test(f.path)) {
        hints.push({
          severity: 'high',
          code: 'secret-looking-path',
          message: `Secret-looking path (${sp.label}): ${f.path}`,
          path: f.path,
        });
      }
    }

    if (f.binary) {
      hints.push({
        severity: f.status === 'A' || f.status === 'M' ? 'medium' : 'low',
        code: 'binary-change',
        message: `Binary file changed: ${f.path}`,
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

    if (AUTH_PATH_RE.test(f.path) && !SECRET_PATTERNS.some((sp) => sp.re.test(f.path))) {
      hints.push({
        severity: 'medium',
        code: 'auth-path',
        message: `Auth / session related path changed: ${f.path}`,
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

  // Deduplicate by code+path, then severity-sort
  const seen = new Set<string>();
  const deduped = hints.filter((h) => {
    const k = `${h.code}:${h.path || ''}:${h.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return sortRisks(deduped);
}
