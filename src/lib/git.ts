import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
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

export interface ResolvedRange {
  base: string;
  head: string;
  label: string;
  /** When set via --base / --since against a named ref. */
  baseRef?: string;
  /** Commits reachable from HEAD but not the base ref (ahead count). */
  commitsAhead?: number;
}

/** Count commits on head not in base (`base..head`). */
export function countCommitsAhead(cwd: string, base: string, head = 'HEAD'): number {
  try {
    const out = runGit(['rev-list', '--count', `${base}..${head}`], cwd);
    const n = parseInt(out, 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

/**
 * Resolve a capture range.
 * - `--base <ref>`: changes vs a branch/ref (e.g. main); label includes commits ahead
 * - `--since <ref>`: same diff range, classic `ref..HEAD` label
 * - `--commits N`: last N commits
 */
export function resolveRange(
  cwd: string,
  opts: { since?: string; commits?: number; base?: string },
): ResolvedRange {
  const head = 'HEAD';
  const baseRef = opts.base || opts.since;
  if (baseRef) {
    // Validate ref exists
    try {
      runGit(['rev-parse', '--verify', baseRef], cwd);
    } catch {
      throw new Error(
        `Unknown git ref for ${opts.base ? '--base' : '--since'}: ${baseRef}
` +
          `Pass a branch, tag, or commit (e.g. main, origin/main, HEAD~3).`,
      );
    }
    const ahead = countCommitsAhead(cwd, baseRef, head);
    if (opts.base) {
      return {
        base: baseRef,
        head,
        label: `${ahead} commit${ahead === 1 ? '' : 's'} ahead of ${baseRef}`,
        baseRef,
        commitsAhead: ahead,
      };
    }
    return {
      base: baseRef,
      head,
      label: `${baseRef}..HEAD`,
      baseRef,
      commitsAhead: ahead,
    };
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

/** Porcelain status of the working tree (tracked + untracked, exclude-standard). */
export function getPorcelainStatus(cwd: string): string {
  try {
    return runGit(['status', '--porcelain=v1', '-uall'], cwd);
  } catch {
    return '';
  }
}

/** True when there are staged, unstaged, or untracked changes. */
export function isDirty(cwd: string): boolean {
  return getPorcelainStatus(cwd).trim().length > 0;
}

/**
 * Stable fingerprint of the dirty tree for watch polling.
 * Empty string when clean.
 */
export function dirtyFingerprint(cwd: string): string {
  const p = getPorcelainStatus(cwd);
  if (!p.trim()) return '';
  let num = '';
  try {
    num = runGit(['diff', '--numstat', 'HEAD'], cwd);
  } catch {
    num = '';
  }
  let untracked = '';
  try {
    untracked = runGit(['ls-files', '--others', '--exclude-standard'], cwd);
  } catch {
    untracked = '';
  }
  return `${p}\n--\n${num}\n--\n${untracked}`;
}

function truncateDiff(diff: string, full: boolean, maxLines: number): string {
  if (!diff) return '(no textual diff)';
  const lines = diff.split('\n');
  if (full || lines.length <= maxLines) return diff;
  return `${lines.slice(0, maxLines).join('\n')}\n… (${lines.length - maxLines} more lines truncated; use --full)`;
}

function countLinesAndBinary(cwd: string, filePath: string): { ins: number; binary: boolean } {
  try {
    const buf = readFileSync(join(cwd, filePath));
    if (buf.includes(0)) return { ins: 0, binary: true };
    const text = buf.toString('utf8');
    const n = text.length ? text.split(/\r?\n/).length : 0;
    return { ins: n, binary: false };
  } catch {
    return { ins: 0, binary: false };
  }
}

/**
 * Working-tree changes vs HEAD (staged + unstaged tracked) plus untracked files.
 * Used for uncommitted captures / dirty watch.
 */
export function getWorkingTreeFiles(cwd: string): FileStat[] {
  const head = getHead(cwd);
  const files: FileStat[] = [];
  const seen = new Set<string>();

  if (head !== '(no commits)') {
    let nameStatus = '';
    try {
      nameStatus = runGit(['diff', '--name-status', '--find-renames', 'HEAD'], cwd);
    } catch {
      nameStatus = '';
    }
    let numstatRaw = '';
    try {
      numstatRaw = runGit(['diff', '--numstat', '--find-renames', 'HEAD'], cwd);
    } catch {
      numstatRaw = '';
    }

    const numMap = new Map<string, { ins: number; del: number; binary: boolean }>();
    for (const line of numstatRaw.split('\n').filter(Boolean)) {
      const parts = line.split('\t');
      if (parts.length < 3) continue;
      const [insS, delS, ...pathParts] = parts;
      const path = pathParts.join('\t');
      const finalPath = path.includes('=>')
        ? path
            .replace(/\{(.+?)\s*=>\s*(.+?)\}/, '$2')
            .replace(/(.+)\s*=>\s*(.+)/, '$2')
            .trim()
        : path;
      const binary = insS === '-' && delS === '-';
      numMap.set(finalPath, {
        ins: binary ? 0 : parseInt(insS, 10) || 0,
        del: binary ? 0 : parseInt(delS, 10) || 0,
        binary,
      });
    }

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
      seen.add(path);
    }
  }

  let untracked = '';
  try {
    untracked = runGit(['ls-files', '--others', '--exclude-standard'], cwd);
  } catch {
    untracked = '';
  }
  for (const path of untracked.split('\n').filter(Boolean)) {
    if (seen.has(path)) continue;
    const { ins, binary } = countLinesAndBinary(cwd, path);
    files.push({
      path,
      status: 'A',
      insertions: ins,
      deletions: 0,
      binary,
    });
    seen.add(path);
  }

  return files;
}

/**
 * Diff text for a path in the working tree vs HEAD (or full file for untracked).
 */
export function getWorkingTreeDiff(
  cwd: string,
  filePath: string,
  full: boolean,
  maxLines = 40,
): string {
  const head = getHead(cwd);
  if (head !== '(no commits)') {
    try {
      const diff = runGit(['diff', '--find-renames', 'HEAD', '--', filePath], cwd);
      if (diff) return truncateDiff(diff, full, maxLines);
    } catch {
      /* fall through */
    }
  }
  try {
    execFileSync('git', ['diff', '--no-index', '--', '/dev/null', filePath], {
      cwd,
      encoding: 'utf8',
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    const e = err as { stdout?: string };
    if (typeof e.stdout === 'string' && e.stdout.length) {
      return truncateDiff(e.stdout.trimEnd(), full, maxLines);
    }
  }
  return '(no textual diff)';
}
