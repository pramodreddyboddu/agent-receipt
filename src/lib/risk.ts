import type { FileStat } from './git.js';

export interface RiskHint {
  severity: 'high' | 'medium' | 'low';
  code: string;
  message: string;
  path?: string;
}

const SECRET_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /(^|\/)\.env(\.|$)/i, label: 'dotenv / env file' },
  { re: /(^|\/)(secrets?|credentials?)\.(json|ya?ml|toml|env)$/i, label: 'credentials file' },
  { re: /(^|\/).*\.(pem|p12|pfx|key)$/i, label: 'key / cert material' },
  { re: /(^|\/)id_rsa(\.pub)?$/i, label: 'SSH key' },
  { re: /(^|\/)\.npmrc$/i, label: 'npmrc (may contain tokens)' },
  { re: /(^|\/)aws[_-]?credentials$/i, label: 'AWS credentials' },
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

const CI_PATTERNS = [
  /^\.github\/workflows\//i,
  /^\.gitlab-ci\.ya?ml$/i,
  /^\.circleci\//i,
  /^Jenkinsfile$/i,
  /^\.travis\.ya?ml$/i,
];

const LARGE_BINARY_HINT_BYTES = 512 * 1024; // we only know binary flag from git; treat binary as elevated

export function analyzeRisks(files: FileStat[]): RiskHint[] {
  const hints: RiskHint[] = [];

  for (const f of files) {
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
      // oversized binary heuristic via insert/delete volume when available
      if (f.insertions + f.deletions > 0) {
        // numstat for binary is -, - so this rarely fires; keep for completeness
      }
      void LARGE_BINARY_HINT_BYTES;
    }

    const baseName = f.path.split('/').pop() || f.path;
    if (LOCKFILES.has(baseName) && (f.status === 'D' || f.deletions > f.insertions * 2)) {
      hints.push({
        severity: 'high',
        code: 'lockfile-deletion',
        message: `Lockfile deleted or heavily reduced: ${f.path}`,
        path: f.path,
      });
    }

    if (
      (f.status === 'D' || f.status === 'M') &&
      CI_PATTERNS.some((re) => re.test(f.path))
    ) {
      if (f.status === 'D') {
        hints.push({
          severity: 'high',
          code: 'ci-deletion',
          message: `CI / workflow file deleted: ${f.path}`,
          path: f.path,
        });
      } else {
        hints.push({
          severity: 'medium',
          code: 'ci-modification',
          message: `CI / workflow file modified: ${f.path}`,
          path: f.path,
        });
      }
    }
  }

  // Deduplicate by code+path
  const seen = new Set<string>();
  return hints.filter((h) => {
    const k = `${h.code}:${h.path || ''}:${h.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
