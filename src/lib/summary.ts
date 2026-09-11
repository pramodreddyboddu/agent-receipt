import type { FileStat } from './git.js';

export interface ChangeSummary {
  kind: 'package' | 'lockfile' | 'workflow' | 'dependency-manifest';
  path: string;
  status: string;
  note: string;
}

const LOCKFILE_NAMES = new Set([
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

const MANIFEST_NAMES = new Set([
  'package.json',
  'Cargo.toml',
  'pyproject.toml',
  'Gemfile',
  'composer.json',
  'go.mod',
  'requirements.txt',
]);

const WORKFLOW_RE = [
  /^\.github\/workflows\//i,
  /^\.gitlab-ci\.ya?ml$/i,
  /^\.circleci\//i,
  /^Jenkinsfile$/i,
  /^\.travis\.ya?ml$/i,
];

function statusVerb(status: string): string {
  switch (status[0]) {
    case 'A':
      return 'added';
    case 'D':
      return 'deleted';
    case 'R':
      return 'renamed';
    case 'M':
    default:
      return 'modified';
  }
}

/** Highlight package / lockfile / CI workflow changes for the receipt overview. */
export function summarizeNotableChanges(files: FileStat[]): ChangeSummary[] {
  const out: ChangeSummary[] = [];
  for (const f of files) {
    const base = f.path.split('/').pop() || f.path;
    if (base === 'package.json' || MANIFEST_NAMES.has(base)) {
      out.push({
        kind: base === 'package.json' ? 'package' : 'dependency-manifest',
        path: f.path,
        status: f.status,
        note: `${statusVerb(f.status)} ${base} (+${f.insertions}/−${f.deletions})`,
      });
    } else if (LOCKFILE_NAMES.has(base)) {
      out.push({
        kind: 'lockfile',
        path: f.path,
        status: f.status,
        note: `${statusVerb(f.status)} lockfile ${base} (+${f.insertions}/−${f.deletions})`,
      });
    } else if (WORKFLOW_RE.some((re) => re.test(f.path))) {
      out.push({
        kind: 'workflow',
        path: f.path,
        status: f.status,
        note: `${statusVerb(f.status)} CI/workflow ${f.path} (+${f.insertions}/−${f.deletions})`,
      });
    }
  }
  return out;
}

export function formatDiffStatTable(files: FileStat[]): string[] {
  const lines: string[] = [];
  if (!files.length) {
    lines.push('_No file changes._');
    return lines;
  }
  const maxPath = Math.min(
    60,
    Math.max(12, ...files.map((f) => f.path.length)),
  );
  lines.push('```');
  for (const f of files) {
    const path = f.path.length > maxPath ? '…' + f.path.slice(-(maxPath - 1)) : f.path;
    const pad = ' '.repeat(Math.max(1, maxPath - path.length + 1));
    const barPlus = '+'.repeat(Math.min(20, f.insertions));
    const barMinus = '-'.repeat(Math.min(20, f.deletions));
    const bin = f.binary ? ' Bin' : '';
    lines.push(
      `${path}${pad}| ${f.status} ${String(f.insertions).padStart(4)} ${String(f.deletions).padStart(4)} ${barPlus}${barMinus}${bin}`,
    );
  }
  const totalIns = files.reduce((a, f) => a + f.insertions, 0);
  const totalDel = files.reduce((a, f) => a + f.deletions, 0);
  lines.push(
    `${files.length} file${files.length === 1 ? '' : 's'} changed, ${totalIns} insertion${totalIns === 1 ? '' : 's'}(+), ${totalDel} deletion${totalDel === 1 ? '' : 's'}(-)`,
  );
  lines.push('```');
  return lines;
}
