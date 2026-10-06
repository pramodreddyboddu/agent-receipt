/**
 * Pre-install snapshots for native adapters.
 *
 * The first install of an adapter copies each file it is about to change.
 * The copy lives under the repo git dir (`git rev-parse --git-path`), so it
 * is not an untracked work-tree file and a later hook does not see it as
 * dirty. A repo without git falls back to `.agent-receipt/adapter-backups/`.
 * That fallback is still inside the project.
 *
 * Uninstall writes those bytes back, or deletes a file that did not exist.
 * A second install does not replace the original snapshot. Edits made to
 * those same files after install are not kept: uninstall returns the
 * pre-install bytes. Dry-run writes nothing, including no snapshot.
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
import { projectPath } from './json-config.js';

export interface BackupEntry {
  rel: string;
  existed: boolean;
  /** Present when `existed` is true. Base64url file name of the blob. */
  file?: string;
  sha256: string | null;
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

/** Directory that holds this adapter's manifest and blobs. */
export function adapterBackupDir(cwd: string, adapter: string): string {
  const name = safeAdapter(adapter);
  const probe = spawnSync('git', ['rev-parse', '--git-path', `agent-receipt-adapter-backups/${name}`], {
    cwd,
    encoding: 'utf8',
  });
  if (probe.status === 0 && probe.stdout.trim()) {
    const printed = probe.stdout.trim();
    return isAbsolute(printed) ? printed : resolve(cwd, printed);
  }
  return join(cwd, '.agent-receipt', 'adapter-backups', name);
}

export function adapterBackupManifest(cwd: string, adapter: string): string {
  return join(adapterBackupDir(cwd, adapter), 'manifest.json');
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
    const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : '';
    if (code !== 'ENOENT') {
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

function readManifest(cwd: string, adapter: string): BackupManifest {
  const filePath = adapterBackupManifest(cwd, adapter);
  if (!existsSync(filePath)) return { adapter, entries: [] };
  try {
    const doc = JSON.parse(readFileSync(filePath, 'utf8')) as BackupManifest;
    if (!doc || !Array.isArray(doc.entries)) return { adapter, entries: [] };
    return doc;
  } catch {
    return { adapter, entries: [] };
  }
}

function writeManifest(cwd: string, adapter: string, manifest: BackupManifest): void {
  const dir = adapterBackupDir(cwd, adapter);
  mkdirSync(dir, { recursive: true });
  writeFileSync(adapterBackupManifest(cwd, adapter), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

/** Remember the pre-install bytes once. Later installs keep that snapshot. */
export function snapshotOriginal(cwd: string, adapter: string, rel: string, filePath: string): void {
  assertSafeProjectPath(cwd, filePath);
  const manifest = readManifest(cwd, adapter);
  if (manifest.entries.some((entry) => entry.rel === rel)) return;
  const entry: BackupEntry = { rel, existed: false, sha256: null };
  if (existsSync(filePath)) {
    const st = lstatSync(filePath);
    if (st.isSymbolicLink()) throw new Error(`refusing to follow a symlink: ${rel}`);
    const bytes = readFileSync(filePath);
    const file = encodeRel(rel);
    const blobDir = join(adapterBackupDir(cwd, adapter), 'files');
    mkdirSync(blobDir, { recursive: true });
    writeFileSync(join(blobDir, file), bytes);
    entry.existed = true;
    entry.file = file;
    entry.sha256 = sha256Buffer(bytes);
  }
  manifest.entries.push(entry);
  writeManifest(cwd, adapter, manifest);
}

function removeEmptyParents(cwd: string, filePath: string): void {
  const root = resolve(cwd);
  let dir = dirname(resolve(filePath));
  // `rmSync` rejects directories. `rmdirSync` removes an empty one and
  // throws when something is still inside, which stops the walk.
  while (dir.startsWith(root + sep) && dir !== root) {
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
}

/**
 * Write `next`, or delete when `next` is null. No-op when the bytes already
 * match. `backup` snapshots the previous bytes on the first real change.
 */
export function applyProjectFile(
  cwd: string,
  adapter: string,
  rel: string,
  next: string | null,
  opts: ApplyFileOptions = {},
): ApplyResult {
  const filePath = projectPath(cwd, rel);
  assertSafeProjectPath(cwd, filePath);
  const exists = existsSync(filePath);
  if (exists && lstatSync(filePath).isSymbolicLink()) {
    throw new Error(`refusing to follow a symlink: ${rel}`);
  }
  const current = exists ? readFileSync(filePath, 'utf8') : null;
  const changed = next === null ? current !== null : current !== next;
  // Snapshot even when the bytes already match, so uninstall can put the
  // pre-install file back instead of treating an identical file as one we created.
  if (!opts.dryRun && opts.backup !== false) snapshotOriginal(cwd, adapter, rel, filePath);
  if (!changed || opts.dryRun) return { path: filePath, rel, changed };
  if (next === null) {
    rmSync(filePath, { force: true });
    removeEmptyParents(cwd, filePath);
  } else {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, next, 'utf8');
  }
  return { path: filePath, rel, changed: true };
}

export interface RestoreResult {
  hadBackup: boolean;
  files: string[];
  changed: string[];
}

/** Put back the pre-install bytes. Dry-run reports the paths and writes nothing. */
export function restoreAdapter(cwd: string, adapter: string, dryRun = false): RestoreResult {
  const manifestPath = adapterBackupManifest(cwd, adapter);
  if (!existsSync(manifestPath)) return { hadBackup: false, files: [], changed: [] };
  const manifest = readManifest(cwd, adapter);
  const files: string[] = [];
  const changed: string[] = [];
  for (const entry of manifest.entries) {
    const filePath = projectPath(cwd, entry.rel);
    assertSafeProjectPath(cwd, filePath);
    files.push(filePath);
    if (dryRun) {
      changed.push(filePath);
      continue;
    }
    if (!entry.existed) {
      if (existsSync(filePath)) {
        if (lstatSync(filePath).isSymbolicLink()) {
          throw new Error(`refusing to follow a symlink: ${entry.rel}`);
        }
        rmSync(filePath, { force: true });
        removeEmptyParents(cwd, filePath);
      }
      changed.push(filePath);
      continue;
    }
    if (!entry.file) throw new Error(`adapter backup for ${entry.rel} is missing its blob`);
    const blob = join(adapterBackupDir(cwd, adapter), 'files', entry.file);
    if (!existsSync(blob)) throw new Error(`adapter backup blob is missing: ${entry.rel}`);
    const bytes = readFileSync(blob);
    mkdirSync(dirname(filePath), { recursive: true });
    const current = existsSync(filePath) ? readFileSync(filePath) : null;
    if (!current || !current.equals(bytes)) changed.push(filePath);
    writeFileSync(filePath, bytes);
  }
  if (!dryRun) rmSync(adapterBackupDir(cwd, adapter), { recursive: true, force: true });
  return { hadBackup: true, files, changed };
}
