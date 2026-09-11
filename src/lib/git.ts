import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export function runGit(args: string[], cwd: string): string {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    }).trim();
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    const detail = (e.stderr || e.message || String(err)).toString().trim();
    throw new Error(`git ${args.join(' ')} failed: ${detail}`);
  }
}

export function isGitRepo(cwd: string): boolean {
  return existsSync(join(cwd, '.git')) || (() => {
    try {
      runGit(['rev-parse', '--is-inside-work-tree'], cwd);
      return true;
    } catch {
      return false;
    }
  })();
}

export function getBranch(cwd: string): string {
  try {
    return runGit(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
  } catch {
    return 'DETACHED';
  }
}

export function getHead(cwd: string): string {
  try {
    return runGit(['rev-parse', 'HEAD'], cwd);
  } catch {
    return '(no commits)';
  }
}

export function getRemoteUrl(cwd: string): string | null {
  try {
    return runGit(['remote', 'get-url', 'origin'], cwd);
  } catch {
    return null;
  }
}

export interface FileStat {
  path: string;
  status: string;
  insertions: number;
  deletions: number;
  binary: boolean;
}

export function resolveRange(
  cwd: string,
  opts: { since?: string; commits?: number },
): { base: string; head: string; label: string } {
  const head = 'HEAD';
  if (opts.since) {
    return { base: opts.since, head, label: `${opts.since}..HEAD` };
  }
  const n = opts.commits && opts.commits > 0 ? opts.commits : 1;
  // Prefer N commits back; fall back to empty tree if shallow/history short
  try {
    const base = runGit([`rev-parse`, `HEAD~${n}`], cwd);
    return { base, head, label: `HEAD~${n}..HEAD` };
  } catch {
    try {
      // First commit / empty-ish: compare against empty tree
      const empty = runGit(['hash-object', '-t', 'tree', '/dev/null'], cwd);
      return { base: empty, head, label: `(root)..HEAD` };
    } catch {
      return { base: 'HEAD', head, label: 'HEAD' };
    }
  }
}

export function getChangedFiles(
  cwd: string,
  base: string,
  head: string,
): FileStat[] {
  let nameStatus = '';
  try {
    nameStatus = runGit(
      ['diff', '--name-status', '--find-renames', `${base}...${head}`],
      cwd,
    );
  } catch {
    nameStatus = runGit(
      ['diff', '--name-status', '--find-renames', base, head],
      cwd,
    );
  }

  const numstatRaw = (() => {
    try {
      return runGit(
        ['diff', '--numstat', '--find-renames', `${base}...${head}`],
        cwd,
      );
    } catch {
      return runGit(['diff', '--numstat', '--find-renames', base, head], cwd);
    }
  })();

  const numMap = new Map<string, { ins: number; del: number; binary: boolean }>();
  for (const line of numstatRaw.split('\n').filter(Boolean)) {
    const parts = line.split('\t');
    if (parts.length < 3) continue;
    const [insS, delS, ...pathParts] = parts;
    const path = pathParts.join('\t');
    // rename shows as old => new
    const finalPath = path.includes('=>')
      ? path.replace(/\{(.+?)\s*=>\s*(.+?)\}/, '$2').replace(/(.+)\s*=>\s*(.+)/, '$2').trim()
      : path;
    const binary = insS === '-' && delS === '-';
    numMap.set(finalPath, {
      ins: binary ? 0 : parseInt(insS, 10) || 0,
      del: binary ? 0 : parseInt(delS, 10) || 0,
      binary,
    });
  }

  const files: FileStat[] = [];
  for (const line of nameStatus.split('\n').filter(Boolean)) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const status = line.slice(0, tab).trim();
    const rest = line.slice(tab + 1);
    let path: string;
    if (status.startsWith('R') || status.startsWith('C')) {
      const bits = rest.split('\t');
      path = bits[bits.length - 1];
    } else {
      path = rest.split('\t')[0];
    }
    const stats = numMap.get(path) || { ins: 0, del: 0, binary: false };
    files.push({
      path,
      status: status[0],
      insertions: stats.ins,
      deletions: stats.del,
      binary: stats.binary,
    });
  }
  return files;
}

export function getFileDiffSummary(
  cwd: string,
  base: string,
  head: string,
  filePath: string,
  full: boolean,
  maxLines = 40,
): string {
  let diff = '';
  try {
    diff = runGit(
      ['diff', '--find-renames', `${base}...${head}`, '--', filePath],
      cwd,
    );
  } catch {
    try {
      diff = runGit(['diff', '--find-renames', base, head, '--', filePath], cwd);
    } catch {
      return '(diff unavailable)';
    }
  }
  if (!diff) return '(no textual diff)';
  const lines = diff.split('\n');
  if (full || lines.length <= maxLines) return diff;
  const headLines = lines.slice(0, maxLines);
  return `${headLines.join('\n')}\n… (${lines.length - maxLines} more lines truncated; use --full)`;
}

export function getCommitLog(
  cwd: string,
  base: string,
  head: string,
  limit = 20,
): string[] {
  try {
    const out = runGit(
      ['log', `--max-count=${limit}`, '--pretty=format:%h %s', `${base}..${head}`],
      cwd,
    );
    return out ? out.split('\n').filter(Boolean) : [];
  } catch {
    return [];
  }
}
