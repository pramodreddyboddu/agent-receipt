import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Decode a path git printed with C-style quoting (`core.quotePath`).
 * Non-ASCII, quotes, backslashes, and control bytes show up as
 * `"caf\303\251.txt"`. Octal escapes `\000`–`\377` are bytes, then UTF-8.
 * A path that is not wrapped in double quotes is returned unchanged.
 *
 * With `quotePath=false`, git still quotes a path that contains a
 * backslash, quote, or control byte, and leaves bytes above 0x7f raw.
 * Node has already decoded those raw bytes to code points. Masking each
 * one with `0xff` collapses it to a single byte and turns U+0100 into
 * NUL, so the name no longer matches the file. Those code points are
 * kept. An octal value above 255 (`\400`) is the Unicode scalar, not a
 * byte masked down to NUL, and the rest of the path stays.
 */
export function unquoteGitPath(path: string): string {
  if (path.length < 2 || path.charCodeAt(0) !== 34 || path.charCodeAt(path.length - 1) !== 34) {
    return path;
  }
  const body = path.slice(1, -1);
  const parts: string[] = [];
  const bytes: number[] = [];
  const flush = (): void => {
    if (!bytes.length) return;
    parts.push(Buffer.from(bytes).toString('utf8'));
    bytes.length = 0;
  };
  const pushByte = (value: number): void => {
    bytes.push(value);
  };
  const pushPoint = (code: number): void => {
    flush();
    if (code >= 0 && code <= 0x10ffff && (code < 0xd800 || code > 0xdfff)) {
      parts.push(String.fromCodePoint(code));
      return;
    }
    parts.push('\uFFFD');
  };

  for (let i = 0; i < body.length; i += 1) {
    const code = body.charCodeAt(i);
    if (code !== 92) {
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < body.length) {
        const pair = body.charCodeAt(i + 1);
        if (pair >= 0xdc00 && pair <= 0xdfff) {
          const point = ((code - 0xd800) << 10) + (pair - 0xdc00) + 0x10000;
          pushPoint(point);
          i += 1;
          continue;
        }
      }
      if (code < 128) pushByte(code);
      else pushPoint(code);
      continue;
    }
    const next = body.charCodeAt(i + 1);
    if (Number.isNaN(next)) {
      pushByte(92);
      break;
    }
    if (next === 97) pushByte(7);
    else if (next === 98) pushByte(8);
    else if (next === 116) pushByte(9);
    else if (next === 110) pushByte(10);
    else if (next === 118) pushByte(11);
    else if (next === 102) pushByte(12);
    else if (next === 114) pushByte(13);
    else if (next === 92) pushByte(92);
    else if (next === 34) pushByte(34);
    else if (next >= 48 && next <= 55) {
      let oct = String.fromCharCode(next);
      let j = i + 2;
      while (oct.length < 3 && j < body.length) {
        const digit = body.charCodeAt(j);
        if (digit < 48 || digit > 55) break;
        oct += String.fromCharCode(digit);
        j += 1;
      }
      const value = parseInt(oct, 8);
      if (value <= 255) pushByte(value);
      else pushPoint(value);
      i = j - 1;
      continue;
    } else if (next < 128) {
      pushByte(next);
    } else {
      pushPoint(next);
    }
    i += 1;
  }
  flush();
  return parts.join('');
}

/**
 * True when a receipt table cell must be one physical line. A newline in
 * the cell splits the row, so the file drops out of every parser. A
 * backtick ends the markdown span (`` `name` ``) and the row no longer
 * matches, so that name drops out of the table and out of attest. A name
 * that already looks quoted is quoted again so a later decode does not
 * strip characters that belong to the name.
 * `escapeBacktick` is false for the diff-stat fence. That block already
 * shields a leading ``` with a space, and octal-escaping it would hide
 * the name.
 */
function needsReceiptQuoting(path: string, escapeBacktick = true): boolean {
  if (/[\u0000-\u001f\u007f\u2028\u2029]/.test(path)) return true;
  if (escapeBacktick && path.includes('`')) return true;
  return path.length >= 2 && path.startsWith('"') && path.endsWith('"');
}

/**
 * One-line form of a path for a markdown table cell. Names that fit on
 * one line, including a backslash, are unchanged. A newline, other
 * control, or backtick is git-quoted (`"has\nnewline.txt"`,
 * `"has\140tick.txt"`) and round-trips through `decodeReceiptTablePath`.
 * The backtick is octal so the markdown span stays one span.
 * Pass `{ escapeBacktick: false }` inside a ``` fence, where a raw
 * backtick must stay visible and a leading fence is shielded separately.
 */
export function quoteReceiptTablePath(
  path: string,
  opts?: { escapeBacktick?: boolean },
): string {
  const escapeBacktick = opts?.escapeBacktick !== false;
  if (!needsReceiptQuoting(path, escapeBacktick)) return path;
  let out = '"';
  for (const ch of path) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '`' && escapeBacktick) out += '\\140';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\v') out += '\\v';
    else if (code < 32 || code === 127 || code === 0x2028 || code === 0x2029) {
      // Named escapes cover the usual controls. Anything else that would
      // split a row (DEL, U+2028, U+2029) is UTF-8 octal, which unquote
      // turns back into the same character. A raw U+2028 inside quotes
      // would still break the line.
      for (const byte of Buffer.from(ch, 'utf8')) {
        out += `\\${byte.toString(8).padStart(3, '0')}`;
      }
    } else out += ch;
  }
  out += '"';
  return out;
}

/**
 * Inverse of `quoteReceiptTablePath`. A cell we quoted contains a
 * backslash escape. Older receipts store the path raw, including a
 * backslash, and do not get a second decode.
 */
export function decodeReceiptTablePath(cell: string): string {
  if (cell.length >= 2 && cell.startsWith('"') && cell.endsWith('"') && cell.includes('\\')) {
    return unquoteGitPath(cell);
  }
  return cell;
}

/**
 * A diff path, after git quoting is removed. Rename lines use `=>`.
 * Unquote first so the braces and arrow are real characters, not escapes.
 */
function normalizeDiffPath(raw: string): string {
  const path = unquoteGitPath(raw);
  if (!path.includes('=>')) return path;
  return path
    .replace(/\{(.+?)\s*=>\s*(.+?)\}/, '$2')
    .replace(/(.+)\s*=>\s*(.+)/, '$2')
    .trim();
}

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
    const finalPath = normalizeDiffPath(pathParts.join('\t'));
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
      path = unquoteGitPath(bits[bits.length - 1]);
    } else {
      path = unquoteGitPath(rest.split('\t')[0]);
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
      const finalPath = normalizeDiffPath(pathParts.join('\t'));
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
        path = unquoteGitPath(bits[bits.length - 1]);
      } else {
        path = unquoteGitPath(rest.split('\t')[0]);
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
  for (const rawPath of untracked.split('\n').filter(Boolean)) {
    const path = unquoteGitPath(rawPath);
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
