/**
 * Identity check for a user-given `--out`.
 *
 * Path strings are not enough. A symlinked parent (`link -> receipts/`)
 * makes `link/receipt.md` and `receipts/receipt.md` different strings and
 * the same file. macOS `/tmp` and `/private/tmp` are the same directory.
 * A case-insensitive volume treats `Foo.md` and `foo.md` as one file.
 *
 * Compare `realpath(dirname(out)) + basename(out)` with the source.
 * When the destination already exists, also compare `stat` dev+ino.
 * When it does not, and the parent volume folds case, compare the parent
 * dev+ino plus a case-folded basename. Darwin and win32 always fold.
 * Other platforms probe one existing name in the parent directory.
 */
import { lstatSync, readdirSync, realpathSync, statSync, type Stats } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

export class OutGuardError extends Error {
  readonly exitCode = 1 as const;
  constructor(message: string) {
    super(message);
    this.name = 'OutGuardError';
  }
}

const caseFoldByDir = new Map<string, boolean>();

export function outHasTrailingSeparator(out: string): boolean {
  return /[/\\]$/.test(out);
}

/** A trailing separator is a directory, not a file name. */
export function assertNotDirectoryPath(out: string): void {
  if (outHasTrailingSeparator(out)) {
    throw new OutGuardError(`--out must be a file path, not a directory (${out}).`);
  }
}

function isDangling(abs: string): boolean {
  try {
    statSync(abs);
    return false;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return true;
    const detail = err instanceof Error ? err.message : String(err);
    throw new OutGuardError(`could not use --out ${abs} (${detail})`);
  }
}

/**
 * Refuse a symlink at `abs`, including a dangling one. Do not follow it.
 * A directory is refused unless the caller is about to place a file inside it.
 * A missing path is allowed: the caller creates the file.
 */
export function assertWritableOutFile(abs: string): void {
  let st: Stats;
  try {
    st = lstatSync(abs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return;
    const detail = err instanceof Error ? err.message : String(err);
    throw new OutGuardError(`could not use --out ${abs} (${detail})`);
  }
  if (st.isSymbolicLink()) {
    const dangling = isDangling(abs);
    throw new OutGuardError(
      dangling
        ? `refusing to write through a dangling symlink: ${abs}`
        : `refusing to write through a symlink: ${abs}`,
    );
  }
  if (st.isDirectory()) {
    throw new OutGuardError(`--out is a directory (${abs}). Pass a file path.`);
  }
}

function safeRealpath(target: string): string | null {
  try {
    return realpathSync(target);
  } catch {
    return null;
  }
}

function flipAlpha(name: string): string {
  let out = '';
  for (const ch of name) {
    const lower = ch.toLowerCase();
    const upper = ch.toUpperCase();
    if (lower === upper) out += ch;
    else if (ch === lower) out += upper;
    else out += lower;
  }
  return out;
}

/** True when names in `dir` are compared without case. Cached per directory inode. */
export function directoryFoldsCase(dir: string): boolean {
  if (process.platform === 'darwin' || process.platform === 'win32') return true;
  let st: Stats;
  try {
    st = statSync(dir);
  } catch {
    return false;
  }
  const key = `${st.dev}:${st.ino}`;
  const cached = caseFoldByDir.get(key);
  if (cached !== undefined) return cached;
  let folds = false;
  try {
    for (const name of readdirSync(dir)) {
      const flipped = flipAlpha(name);
      if (flipped === name) continue;
      try {
        const a = statSync(join(dir, name));
        const b = statSync(join(dir, flipped));
        folds = a.dev === b.dev && a.ino === b.ino;
      } catch {
        folds = false;
      }
      break;
    }
  } catch {
    folds = false;
  }
  caseFoldByDir.set(key, folds);
  return folds;
}

/** `realpath(dirname) + basename`, or null when the parent does not exist. */
function resolvedFile(abs: string): string | null {
  const dirReal = safeRealpath(dirname(abs));
  if (!dirReal) return null;
  return join(dirReal, basename(abs));
}

function sameInode(a: string, b: string): boolean {
  try {
    const left = statSync(a);
    const right = statSync(b);
    return left.dev === right.dev && left.ino === right.ino;
  } catch {
    return false;
  }
}

/**
 * True when writing `outAbs` would replace `sourceAbs`.
 * `sourceAbs` may be missing (a companion path that is not on disk yet).
 * The check still matches that path once both parents resolve.
 */
export function sameFileTarget(outAbs: string, sourceAbs: string): boolean {
  const outResolved = resolvedFile(outAbs);
  const sourceResolved = resolvedFile(sourceAbs);
  const sourceReal = safeRealpath(sourceAbs);
  if (outResolved && sourceReal && outResolved === sourceReal) return true;
  if (outResolved && sourceResolved && outResolved === sourceResolved) return true;

  if (outResolved && sourceReal && sameInode(outResolved, sourceReal)) return true;
  if (sourceReal && sameInode(outAbs, sourceReal)) return true;

  const parentReal = outResolved ? dirname(outResolved) : safeRealpath(dirname(outAbs));
  const sourceParent = sourceReal
    ? dirname(sourceReal)
    : sourceResolved
      ? dirname(sourceResolved)
      : null;
  if (!parentReal || !sourceParent) return false;
  if (!directoryFoldsCase(parentReal)) return false;
  try {
    const parentOut = statSync(parentReal);
    const parentSrc = statSync(sourceParent);
    if (parentOut.dev !== parentSrc.dev || parentOut.ino !== parentSrc.ino) return false;
  } catch {
    return false;
  }
  const outBase = basename(outResolved ?? outAbs);
  const sourceBase = basename(sourceReal ?? sourceResolved ?? sourceAbs);
  return outBase.toLowerCase() === sourceBase.toLowerCase();
}

export function conflictingProtectedPath(outAbs: string, protectedPaths: string[]): string | null {
  for (const source of protectedPaths) {
    if (sameFileTarget(outAbs, source)) return source;
  }
  return null;
}

/** Message for an export-style overwrite. Keeps the historical receipt wording. */
export function protectedOverwriteMessage(hit: string, noun: string): string {
  const base = basename(hit);
  if (
    base === 'session-manifest.json' ||
    base === 'session-manifest.sig.json' ||
    base.endsWith('.sig.json')
  ) {
    return `refusing to write the ${noun} over a session package file: ${base}`;
  }
  if (base.endsWith('.json')) {
    return `refusing to write the ${noun} over the receipt companion .json`;
  }
  return `refusing to write the ${noun} over the receipt`;
}

export function assertProtectedOut(outAbs: string, protectedPaths: string[], noun: string): void {
  const hit = conflictingProtectedPath(outAbs, protectedPaths);
  if (hit) throw new OutGuardError(protectedOverwriteMessage(hit, noun));
}

/**
 * Resolve a `--out` that must be a file. A trailing separator or an
 * existing directory is an error. A symlink, dangling or not, is an error.
 */
export function resolveFileOut(cwd: string, out: string): string {
  assertNotDirectoryPath(out);
  const abs = resolve(cwd, out);
  assertWritableOutFile(abs);
  return abs;
}

/**
 * `--out` for a command that writes one file, and also accepts a directory.
 * A trailing separator or an existing directory (including a symlink to a
 * directory) receives `fileName` inside it. A dangling symlink, or a symlink
 * to a file, is refused and is not followed. The returned path is the file.
 * Omitted `--out` is `join(fallbackDir, fileName)` with no symlink check;
 * the caller still checks that path before writing.
 */
export function resolveDirOrFileOut(
  cwd: string,
  out: string | undefined,
  fileName: string,
  fallbackDir: string,
): string {
  if (!out) return join(fallbackDir, fileName);
  const wantsDir = outHasTrailingSeparator(out);
  const resolved = resolve(cwd, out);
  let isDir = false;
  try {
    const st = lstatSync(resolved);
    if (st.isSymbolicLink()) {
      let followed: Stats;
      try {
        followed = statSync(resolved);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === 'ENOENT') {
          throw new OutGuardError(`refusing to write through a dangling symlink: ${resolved}`);
        }
        const detail = err instanceof Error ? err.message : String(err);
        throw new OutGuardError(`could not use --out ${resolved} (${detail})`);
      }
      if (!followed.isDirectory()) {
        throw new OutGuardError(`refusing to write through a symlink: ${resolved}`);
      }
      isDir = true;
    } else if (st.isDirectory()) {
      isDir = true;
    }
  } catch (err) {
    if (err instanceof OutGuardError) throw err;
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT') {
      const detail = err instanceof Error ? err.message : String(err);
      throw new OutGuardError(`could not use --out ${resolved} (${detail})`);
    }
  }
  const dest = wantsDir || isDir ? join(resolved, fileName) : resolved;
  assertWritableOutFile(dest);
  return dest;
}
