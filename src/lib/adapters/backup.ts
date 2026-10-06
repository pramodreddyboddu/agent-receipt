/**
 * Pre-install snapshots for native adapters.
 *
 * The first install copies each file it is about to change. The copy lives
 * under the repo git dir (`git rev-parse --git-path`), keyed by a path
 * relative to the project root (`git rev-parse --show-toplevel`), not the
 * process cwd. A repo without git falls back to
 * `.agent-receipt/adapter-backups/` and adds that directory to `.gitignore`.
 *
 * Each entry records the sha256 of the bytes written by the last install
 * (`postSha256`). Uninstall restores the snapshot when the file still matches
 * that hash. When the file changed, uninstall strips only this adapter's
 * hooks unless `--force` is set. A reinstall that sees a user edit refreshes
 * the snapshot to those pre-write bytes and marks `userModified`.
 *
 * Dry-run writes nothing, including no snapshot and no gitignore line.
 */
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { InstallResult } from './types.js';

export interface BackupEntry {
  rel: string;
  existed: boolean;
  /** Present when `existed` is true. Base64url file name of the blob. */
  file?: string;
  sha256: string | null;
  /** Sha256 of the bytes this adapter wrote on the last successful install. */
  postSha256?: string | null;
  /** True once a later install saw bytes that were not `postSha256`. Omitted when false. */
  userModified?: boolean;
}

interface BackupManifest {
  adapter: string;
  entries: BackupEntry[];
}

export interface ApplyResult {
  path: string;
  rel: string;
  changed: boolean;
}

export interface UninstallEntryPlan {
  rel: string;
  path: string;
  mode: 'restore' | 'strip';
  userChanged: boolean;
  existed: boolean;
  bytes: Buffer | null;
}

export interface UninstallPlan {
  hadBackup: boolean;
  entries: UninstallEntryPlan[];
}

const GITIGNORE_LINE = '.agent-receipt/adapter-backups/';

function sha256Buffer(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function safeAdapter(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
  if (!cleaned || cleaned === '.' || cleaned === '..') {
    throw new Error(`refusing adapter backup name: ${name}`);
  }
  return cleaned;
}

function encodeRel(rel: string): string {
  return Buffer.from(rel, 'utf8').toString('base64url');
}

function errno(err: unknown): string {
  return err && typeof err === 'object' && 'code' in err ? String((err as { code?: string }).code ?? '') : '';
}

export function projectRoot(cwd: string): string {
  const probe = spawnSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8' });
  if (probe.status === 0 && probe.stdout.trim()) return probe.stdout.trim();
  return resolve(cwd);
}

function gitBackupDir(root: string, name: string): string | null {
  const probe = spawnSync('git', ['rev-parse', '--git-path', `agent-receipt-adapter-backups/${name}`], {
    cwd: root,
    encoding: 'utf8',
  });
  if (probe.status === 0 && probe.stdout.trim()) {
    const printed = probe.stdout.trim();
    return isAbsolute(printed) ? printed : resolve(root, printed);
  }
  return null;
}

/** Directory that holds this adapter's manifest and blobs. */
export function adapterBackupDir(cwd: string, adapter: string): string {
  const root = projectRoot(cwd);
  const name = safeAdapter(adapter);
  return gitBackupDir(root, name) ?? join(root, '.agent-receipt', 'adapter-backups', name);
}

function backupIsFallback(cwd: string, adapter: string): boolean {
  return gitBackupDir(projectRoot(cwd), safeAdapter(adapter)) === null;
}

export function adapterBackupManifest(cwd: string, adapter: string): string {
  return join(adapterBackupDir(cwd, adapter), 'manifest.json');
}

/** Walk every existing component. A symlink anywhere in the backup path is refused. */
export function assertBackupPathNotSymlinked(dir: string): void {
  const abs = resolve(dir);
  const parts = abs.split(sep).filter(Boolean);
  let current = abs.startsWith(sep) ? sep : '';
  for (const part of parts) {
    current = current === sep ? join(sep, part) : join(current, part);
    let st;
    try {
      st = lstatSync(current);
    } catch (err) {
      if (errno(err) === 'ENOENT') return;
      throw err;
    }
    if (st.isSymbolicLink()) {
      throw new Error('refusing to follow a symlink in the adapter backup path');
    }
  }
}

function ensureAdapterBackupGitignore(root: string): void {
  const ignorePath = join(root, '.gitignore');
  try {
    if (lstatSync(ignorePath).isSymbolicLink()) {
      throw new Error('refusing to follow a symlink: .gitignore');
    }
  } catch (err) {
    if (errno(err) !== 'ENOENT') {
      if (err instanceof Error && err.message.startsWith('refusing')) throw err;
      throw err;
    }
  }
  const text = existsSync(ignorePath) ? readFileSync(ignorePath, 'utf8') : '';
  if (text.split('\n').some((line) => line.trim() === GITIGNORE_LINE)) return;
  const next = text.length === 0 ? `${GITIGNORE_LINE}\n` : text.endsWith('\n') ? `${text}${GITIGNORE_LINE}\n` : `${text}\n${GITIGNORE_LINE}\n`;
  writeFileSync(ignorePath, next, 'utf8');
}

export function ioError(err: unknown, rel: string): Error {
  const code = errno(err);
  if (code === 'EACCES' || code === 'EPERM' || code === 'EROFS') {
    return new Error(`cannot write ${rel}: permission denied`);
  }
  return err instanceof Error ? err : new Error(String(err));
}

/**
 * Refuse a write that leaves the project or follows a symlink.
 * A missing file is allowed when its existing parent stays inside `cwd`.
 */
export function assertSafeProjectPath(cwd: string, filePath: string): void {
  let root: string;
  try {
    root = realpathSync(cwd);
  } catch {
    throw new Error(`refusing to write outside the project: ${filePath}`);
  }
  const abs = resolve(filePath);
  try {
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) {
      throw new Error(`refusing to follow a symlink: ${filePath}`);
    }
  } catch (err) {
    if (errno(err) !== 'ENOENT') {
      if (err instanceof Error && err.message.startsWith('refusing to follow')) throw err;
      throw new Error(`refusing to write ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  let existing = abs;
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (parent === existing) throw new Error(`refusing to write outside the project: ${filePath}`);
    existing = parent;
  }
  let realExisting: string;
  try {
    const st = lstatSync(existing);
    if (st.isSymbolicLink()) {
      realExisting = realpathSync(existing);
      const relLink = relative(root, realExisting);
      if (realExisting !== root && (relLink.startsWith('..') || isAbsolute(relLink))) {
        throw new Error(`refusing to follow a symlink outside the project: ${filePath}`);
      }
      if (realExisting !== root) {
        throw new Error(`refusing to follow a symlink: ${filePath}`);
      }
      return;
    }
    realExisting = realpathSync(existing);
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('refusing')) throw err;
    throw new Error(`refusing to write outside the project: ${filePath}`);
  }
  const rel = relative(root, realExisting);
  if (rel !== '' && (rel.startsWith('..') || isAbsolute(rel))) {
    throw new Error(`refusing to write outside the project: ${filePath}`);
  }
}

function corrupt(): Error {
  return new Error('adapter backup manifest is corrupt');
}

function storageRel(root: string, cwd: string, rel: string): string {
  if (rel.includes('\0')) throw new Error(`refusing to write outside the project: ${rel}`);
  const abs = resolve(cwd, rel);
  const stored = relative(root, abs).split(sep).join('/');
  if (!stored || stored === '.' || stored.startsWith('..') || isAbsolute(stored)) {
    throw new Error(`refusing to write outside the project: ${rel}`);
  }
  return stored;
}

function assertStoredRel(rel: unknown): string {
  if (typeof rel !== 'string' || !rel || rel.includes('\0')) throw corrupt();
  if (isAbsolute(rel) || rel.startsWith('/') || /^[A-Za-z]:[\\/]/.test(rel)) throw corrupt();
  const parts = rel.split(/[/\\]/);
  if (parts.some((part) => part === '..' || part === '.' || part === '')) throw corrupt();
  return parts.join('/');
}

function readManifestStrict(cwd: string, adapter: string): BackupManifest {
  const filePath = adapterBackupManifest(cwd, adapter);
  if (!existsSync(filePath)) return { adapter, entries: [] };
  try {
    if (lstatSync(filePath).isSymbolicLink()) {
      throw new Error('refusing to follow a symlink in the adapter backup path');
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('refusing')) throw err;
  }
  let doc: BackupManifest;
  try {
    doc = JSON.parse(readFileSync(filePath, 'utf8')) as BackupManifest;
  } catch {
    throw corrupt();
  }
  if (!doc || !Array.isArray(doc.entries)) throw corrupt();
  return doc;
}

function writeManifestIfChanged(cwd: string, adapter: string, manifest: BackupManifest): void {
  const dir = adapterBackupDir(cwd, adapter);
  assertBackupPathNotSymlinked(dir);
  mkdirSync(dir, { recursive: true });
  const filePath = adapterBackupManifest(cwd, adapter);
  try {
    if (existsSync(filePath) && lstatSync(filePath).isSymbolicLink()) {
      throw new Error('refusing to follow a symlink in the adapter backup path');
    }
  } catch (err) {
    if (errno(err) !== 'ENOENT') {
      if (err instanceof Error && err.message.startsWith('refusing')) throw err;
      throw err;
    }
  }
  const next = `${JSON.stringify(manifest, null, 2)}\n`;
  if (existsSync(filePath) && readFileSync(filePath, 'utf8') === next) return;
  writeFileSync(filePath, next, 'utf8');
}

function writeBlob(backupDir: string, name: string, bytes: Buffer): void {
  if (name.includes('/') || name.includes('\\') || name.includes('..') || name.includes('\0')) throw corrupt();
  const filesDir = join(backupDir, 'files');
  assertBackupPathNotSymlinked(filesDir);
  mkdirSync(filesDir, { recursive: true });
  const blob = join(filesDir, name);
  try {
    if (lstatSync(blob).isSymbolicLink()) {
      throw new Error('refusing to follow a symlink in the adapter backup path');
    }
  } catch (err) {
    if (errno(err) !== 'ENOENT') {
      if (err instanceof Error && err.message.startsWith('refusing')) throw err;
      throw err;
    }
  }
  writeFileSync(blob, bytes);
}

function locate(cwd: string, rel: string, stored: boolean): { root: string; storedRel: string; filePath: string } {
  const root = projectRoot(cwd);
  const storedRel = stored ? assertStoredRel(rel) : storageRel(root, cwd, rel);
  const filePath = join(root, ...storedRel.split('/'));
  return { root, storedRel, filePath };
}

function recordSnapshot(
  cwd: string,
  adapter: string,
  storedRel: string,
  before: Buffer | null,
  next: string | null,
): void {
  const root = projectRoot(cwd);
  if (backupIsFallback(cwd, adapter)) ensureAdapterBackupGitignore(root);
  const manifest = readManifestStrict(cwd, adapter);
  const beforeHash = before ? sha256Buffer(before) : null;
  const afterHash = next === null ? null : sha256Buffer(Buffer.from(next, 'utf8'));
  let entry = manifest.entries.find((item) => item.rel === storedRel);
  if (entry && beforeHash === entry.postSha256 && afterHash === entry.postSha256) return;
  const backupDir = adapterBackupDir(cwd, adapter);
  if (!entry) {
    const created: BackupEntry = {
      rel: storedRel,
      existed: before !== null,
      sha256: beforeHash,
      postSha256: afterHash,
    };
    if (before) {
      const file = encodeRel(storedRel);
      writeBlob(backupDir, file, before);
      created.file = file;
    }
    manifest.entries.push(created);
    writeManifestIfChanged(cwd, adapter, manifest);
    return;
  }
  if (entry.postSha256 !== undefined && beforeHash !== entry.postSha256) {
    if (before) {
      const file = encodeRel(storedRel);
      writeBlob(backupDir, file, before);
      entry.existed = true;
      entry.file = file;
      entry.sha256 = beforeHash;
    } else {
      entry.existed = false;
      delete entry.file;
      entry.sha256 = null;
    }
    entry.userModified = true;
  }
  entry.postSha256 = afterHash;
  writeManifestIfChanged(cwd, adapter, manifest);
}

function removeEmptyParents(root: string, filePath: string): void {
  const base = resolve(root);
  let dir = dirname(resolve(filePath));
  while (dir.startsWith(base + sep) && dir !== base) {
    try {
      const st = lstatSync(dir);
      if (st.isSymbolicLink() || !st.isDirectory()) return;
      rmdirSync(dir);
    } catch {
      return;
    }
    dir = dirname(dir);
  }
}

export interface ApplyFileOptions {
  dryRun?: boolean;
  /** False for a surgical uninstall that has no snapshot to keep. */
  backup?: boolean;
  /** `rel` is already relative to the project root. */
  stored?: boolean;
}

/**
 * Write `next`, or delete when `next` is null. No-op when the bytes already
 * match. The snapshot is written only after the project file write succeeds,
 * so a permission error leaves no backup behind.
 */
export function applyProjectFile(
  cwd: string,
  adapter: string,
  rel: string,
  next: string | null,
  opts: ApplyFileOptions = {},
): ApplyResult {
  const { root, storedRel, filePath } = locate(cwd, rel, Boolean(opts.stored));
  assertSafeProjectPath(root, filePath);
  if (opts.backup !== false) assertBackupPathNotSymlinked(adapterBackupDir(cwd, adapter));
  let before: Buffer | null = null;
  if (existsSync(filePath)) {
    if (lstatSync(filePath).isSymbolicLink()) throw new Error(`refusing to follow a symlink: ${rel}`);
    before = readFileSync(filePath);
  }
  const beforeText = before ? before.toString('utf8') : null;
  const changed = next === null ? beforeText !== null : beforeText !== next;
  if (opts.dryRun) return { path: filePath, rel: storedRel, changed };
  if (changed) {
    try {
      if (next === null) {
        rmSync(filePath, { force: true });
        removeEmptyParents(root, filePath);
      } else {
        mkdirSync(dirname(filePath), { recursive: true });
        writeFileSync(filePath, next, 'utf8');
      }
    } catch (err) {
      throw ioError(err, storedRel);
    }
  }
  if (opts.backup !== false) recordSnapshot(cwd, adapter, storedRel, before, next);
  return { path: filePath, rel: storedRel, changed };
}

function blobBytes(cwd: string, adapter: string, entry: BackupEntry, rel: string): Buffer | null {
  if (!entry.existed) {
    if (entry.file) throw corrupt();
    return null;
  }
  if (typeof entry.file !== 'string' || entry.file !== encodeRel(rel)) throw corrupt();
  if (typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw corrupt();
  const filesDir = join(adapterBackupDir(cwd, adapter), 'files');
  const blob = join(filesDir, entry.file);
  const relBlob = relative(filesDir, blob);
  if (!relBlob || relBlob.startsWith('..') || isAbsolute(relBlob) || relBlob.includes(sep)) throw corrupt();
  let st;
  try {
    st = lstatSync(blob);
  } catch (err) {
    if (errno(err) === 'ENOENT') throw new Error(`adapter backup blob is missing: ${rel}`);
    throw err;
  }
  if (st.isSymbolicLink()) throw corrupt();
  const bytes = readFileSync(blob);
  if (sha256Buffer(bytes) !== entry.sha256) throw corrupt();
  return bytes;
}

function fileHash(filePath: string): string | null {
  if (!existsSync(filePath)) return null;
  if (lstatSync(filePath).isSymbolicLink()) throw new Error(`refusing to follow a symlink: ${filePath}`);
  return sha256Buffer(readFileSync(filePath));
}

/**
 * Validate every manifest entry before any uninstall write. A corrupt
 * manifest or a missing blob throws and leaves the backup in place.
 */
export function planAdapterUninstall(cwd: string, adapter: string, force = false): UninstallPlan {
  const manifestPath = adapterBackupManifest(cwd, adapter);
  const backupDir = adapterBackupDir(cwd, adapter);
  assertBackupPathNotSymlinked(backupDir);
  if (!existsSync(manifestPath)) return { hadBackup: false, entries: [] };
  const manifest = readManifestStrict(cwd, adapter);
  const root = projectRoot(cwd);
  const entries: UninstallEntryPlan[] = [];
  for (const entry of manifest.entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw corrupt();
    const rel = assertStoredRel(entry.rel);
    const filePath = join(root, ...rel.split('/'));
    assertSafeProjectPath(root, filePath);
    const bytes = blobBytes(cwd, adapter, entry, rel);
    const current = fileHash(filePath);
    const recorded = entry.postSha256;
    const userChanged = entry.userModified === true || recorded === undefined || current !== recorded;
    entries.push({
      rel,
      path: filePath,
      mode: !userChanged || force ? 'restore' : 'strip',
      userChanged,
      existed: entry.existed,
      bytes,
    });
  }
  return { hadBackup: true, entries };
}

function restorePlannedFile(root: string, entry: UninstallEntryPlan, dryRun: boolean): boolean {
  assertSafeProjectPath(root, entry.path);
  if (dryRun) return true;
  if (!entry.existed) {
    if (!existsSync(entry.path)) return false;
    if (lstatSync(entry.path).isSymbolicLink()) throw new Error(`refusing to follow a symlink: ${entry.rel}`);
    rmSync(entry.path, { force: true });
    removeEmptyParents(root, entry.path);
    return true;
  }
  if (!entry.bytes) throw new Error(`adapter backup blob is missing: ${entry.rel}`);
  if (existsSync(entry.path) && lstatSync(entry.path).isSymbolicLink()) {
    throw new Error(`refusing to follow a symlink: ${entry.rel}`);
  }
  const current = existsSync(entry.path) ? readFileSync(entry.path) : null;
  const changed = !current || !current.equals(entry.bytes);
  if (!changed) return false;
  try {
    mkdirSync(dirname(entry.path), { recursive: true });
    writeFileSync(entry.path, entry.bytes);
  } catch (err) {
    throw ioError(err, entry.rel);
  }
  return true;
}

export function removeAdapterBackup(cwd: string, adapter: string): void {
  const dir = adapterBackupDir(cwd, adapter);
  assertBackupPathNotSymlinked(dir);
  rmSync(dir, { recursive: true, force: true });
}

/**
 * Apply a validated plan. `strip` removes only this adapter's hooks from a
 * file the user changed. The backup directory is removed only after every
 * entry succeeds.
 */
export function applyUninstallPlan(
  cwd: string,
  adapter: string,
  plan: UninstallPlan,
  dryRun: boolean,
  strip: (entry: UninstallEntryPlan) => { path: string; changed: boolean } | null,
): InstallResult {
  const root = projectRoot(cwd);
  const files: string[] = [];
  const changed: string[] = [];
  const verbs: NonNullable<InstallResult['verbs']> = [];
  const userChanged = plan.entries.filter((entry) => entry.userChanged).map((entry) => entry.path);
  for (const entry of plan.entries) {
    files.push(entry.path);
    if (entry.mode === 'restore') {
      const did = restorePlannedFile(root, entry, dryRun);
      if (did) changed.push(entry.path);
      verbs.push({ path: entry.path, verb: 'restored' });
      continue;
    }
    const result = dryRun ? strip(entry) : strip(entry);
    const did = Boolean(result?.changed);
    if (did) changed.push(entry.path);
    verbs.push({ path: entry.path, verb: did ? 'stripped' : 'unchanged' });
  }
  if (!dryRun) removeAdapterBackup(cwd, adapter);
  return { files, changed, verbs, userChanged };
}

export function strippedResult(applies: Array<{ path: string; changed: boolean }>): InstallResult {
  return {
    files: applies.map((item) => item.path),
    changed: applies.filter((item) => item.changed).map((item) => item.path),
    verbs: applies.map((item) => ({ path: item.path, verb: item.changed ? 'stripped' : 'unchanged' })),
  };
}
