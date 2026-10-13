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
 * When both parents are the same directory (parent `dev`+`ino`), an exact
 * basename matches even if `realpath` did not collapse a bind mount and the
 * file is not on disk yet. A case-folded basename matches only when that
 * volume folds case. Darwin and win32 always fold. Other platforms probe
 * one existing name in the parent directory. The fold also maps long s
 * (U+017F) and dotless i (U+0131) onto `s` and `i`.
 *
 * Share package files discovered beside an input are compared the same way,
 * so a hardlink of `manifest.json` outside the `.share` directory is refused.
 * That discovery lives with the protected-path set. This module still refuses
 * the share names when `--out` itself is inside a `.share` directory.
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
 * Optional test hook. Production callers omit it and probe the volume.
 * `foldsCase: true` treats the parent as case-insensitive without a probe.
 * `foldsCase: false` treats it as case-sensitive even on darwin and win32.
 */
export interface OutGuardOptions {
  foldsCase?: boolean;
  /**
   * `share --package` creates and refreshes `receipt.md` and
   * `receipt.sig.json`. Other commands still refuse those names.
   * Manifest files stay refused.
   */
  allowShareReceipt?: boolean;
}

/**
 * Share package files `--out` must not replace. Compared case-folded.
 * `receipt.html` is not in this list: the HTML body is unsigned.
 * Manifest names are refused even when the file is not on disk yet.
 * `receipt.md` and `receipt.sig.json` are refused once that file exists
 * (`share --package` creates them). A case variant is refused either way
 * on a volume that folds case, because that name is the same file.
 */
const SHARE_MANIFEST_FILES = ['manifest.json', 'manifest.sig.json'];
const SHARE_RECEIPT_FILES = ['receipt.md', 'receipt.sig.json'];
/** Share package files `--out` must not replace. Canonical, case-sensitive names. */
export const SHARE_PACKAGE_FILE_NAMES = [...SHARE_MANIFEST_FILES, ...SHARE_RECEIPT_FILES];

/**
 * Case fold for a basename. ASCII `toLowerCase` leaves U+017F (long s) and
 * U+0131 (dotless i) unchanged, but a case-insensitive volume maps them to
 * `s` and `i`. `ß` and ligatures are left alone.
 */
export function foldCaseName(name: string): string {
  return name.toLowerCase().replaceAll('\u017f', 's').replaceAll('\u0131', 'i');
}

/**
 * Refuse a symlink at `abs`, including a dangling one. Do not follow it.
 * A directory is refused unless the caller is about to place a file inside it.
 * A missing path is allowed: the caller creates the file.
 * A share package manifest, its signature, `receipt.md`, and `receipt.sig.json`
 * are refused, including a basename that differs only by case on a volume
 * that folds case.
 */
export function assertWritableOutFile(abs: string, opts?: OutGuardOptions): void {
  let st: Stats;
  try {
    st = lstatSync(abs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      refuseSharePackageFile(abs, opts);
      return;
    }
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
  refuseSharePackageFile(abs, opts);
}

function pathExists(abs: string): boolean {
  try {
    lstatSync(abs);
    return true;
  } catch {
    return false;
  }
}

/**
 * `foo.share/manifest.json`, `manifest.sig.json`, `receipt.md`, and
 * `receipt.sig.json`. The path string counts, and so does a resolved parent.
 * An exact manifest name is refused even when the parent directory does not
 * exist yet. An exact `receipt.md` or `receipt.sig.json` that is not on disk
 * yet is allowed so `share --package` can create it. A later `share --package`
 * may refresh that file. Every other command refuses it. A case variant is
 * refused when the identity check matches (same inode, or a case-folding parent).
 */
function refuseSharePackageFile(abs: string, opts?: OutGuardOptions): void {
  const foldsCase = opts?.foldsCase;
  const base = basename(abs);
  const parent = dirname(abs);
  const parentLooksShare = /\.share$/i.test(basename(parent));
  const realParent = safeRealpath(parent);
  const realLooksShare = Boolean(realParent && /\.share$/i.test(basename(realParent)));
  if (!parentLooksShare && !realLooksShare) return;
  const canonical = SHARE_PACKAGE_FILE_NAMES.find((name) => name === foldCaseName(base));
  if (!canonical) return;
  if (opts?.allowShareReceipt && SHARE_RECEIPT_FILES.includes(canonical)) return;
  if (SHARE_MANIFEST_FILES.includes(canonical) && base === canonical) {
    throw new OutGuardError(`refusing to write over a share package file: ${base}`);
  }
  const dirs = new Set<string>();
  if (realParent && realLooksShare) dirs.add(realParent);
  if (parentLooksShare) dirs.add(parent);
  for (const dir of dirs) {
    const canonicalPath = join(dir, canonical);
    if (!sameFileTarget(abs, canonicalPath, foldsCase)) continue;
    const creatingReceipt =
      SHARE_RECEIPT_FILES.includes(canonical) &&
      base === canonical &&
      !pathExists(canonicalPath) &&
      !pathExists(abs);
    if (creatingReceipt) continue;
    throw new OutGuardError(`refusing to write over a share package file: ${base}`);
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
 * `foldsCase`, when passed, skips the volume probe.
 */
export function sameFileTarget(outAbs: string, sourceAbs: string, foldsCase?: boolean): boolean {
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
  try {
    const parentOut = statSync(parentReal);
    const parentSrc = statSync(sourceParent);
    if (parentOut.dev !== parentSrc.dev || parentOut.ino !== parentSrc.ino) return false;
  } catch {
    return false;
  }
  const outBase = basename(outResolved ?? outAbs);
  const sourceBase = basename(sourceReal ?? sourceResolved ?? sourceAbs);
  if (outBase === sourceBase) return true;
  const folds = foldsCase !== undefined ? foldsCase : directoryFoldsCase(parentReal);
  if (!folds) return false;
  return foldCaseName(outBase) === foldCaseName(sourceBase);
}

/**
 * Message when `hit` is a share package file inside a `*.share` directory.
 * Null for every other path. Callers check this before the `.sig.json` and
 * `.json` messages, because `receipt.sig.json` and `manifest.json` match those.
 */
export function sharePackageOverwriteMessage(hit: string): string | null {
  const base = basename(hit);
  if (!/\.share$/i.test(basename(dirname(hit)))) return null;
  if (!SHARE_PACKAGE_FILE_NAMES.includes(base)) return null;
  return `refusing to write over a share package file: ${base}`;
}

/**
 * `share --package` may refresh the canonical `receipt.md` or
 * `receipt.sig.json` at that same path. A different path that is the same
 * inode, or any manifest file, is not a refresh.
 */
function allowedShareReceiptRefresh(outAbs: string, hit: string): boolean {
  const base = basename(hit);
  if (base !== 'receipt.md' && base !== 'receipt.sig.json') return false;
  if (!/\.share$/i.test(basename(dirname(hit)))) return false;
  const outResolved = resolvedFile(outAbs);
  const hitResolved = resolvedFile(hit);
  return Boolean(outResolved && hitResolved && outResolved === hitResolved);
}

export function conflictingProtectedPath(outAbs: string, protectedPaths: string[]): string | null {
  for (const source of protectedPaths) {
    if (sameFileTarget(outAbs, source)) return source;
  }
  return null;
}

/** Message for an export-style overwrite. Keeps the historical receipt wording. */
export function protectedOverwriteMessage(hit: string, noun: string): string {
  const shareMessage = sharePackageOverwriteMessage(hit);
  if (shareMessage) return shareMessage;
  const base = basename(hit);
  if (base === 'session-manifest.json' || base === 'session-manifest.sig.json') {
    return `refusing to write the ${noun} over a session package file: ${base}`;
  }
  if (base.endsWith('.sig.json')) {
    return `refusing to write the ${noun} over the receipt signature sidecar`;
  }
  if (base.endsWith('.json')) {
    return `refusing to write the ${noun} over the receipt companion .json`;
  }
  return `refusing to write the ${noun} over the receipt`;
}

export function assertProtectedOut(
  outAbs: string,
  protectedPaths: string[],
  noun: string,
  opts?: OutGuardOptions,
): void {
  const hits: string[] = [];
  for (const source of protectedPaths) {
    if (sameFileTarget(outAbs, source, opts?.foldsCase)) hits.push(source);
  }
  if (hits.length === 0) return;
  if (opts?.allowShareReceipt && hits.every((hit) => allowedShareReceiptRefresh(outAbs, hit))) return;
  const blocking = hits.find((hit) => !allowedShareReceiptRefresh(outAbs, hit)) ?? hits[0];
  throw new OutGuardError(protectedOverwriteMessage(blocking, noun));
}

/**
 * Resolve a `--out` that must be a file. A trailing separator or an
 * existing directory is an error. A symlink, dangling or not, is an error.
 */
export function resolveFileOut(cwd: string, out: string, opts?: OutGuardOptions): string {
  assertNotDirectoryPath(out);
  const abs = resolve(cwd, out);
  assertWritableOutFile(abs, opts);
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
