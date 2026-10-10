/**
 * Replace a file by creating a sibling temp file with flag `wx`
 * (O_EXCL|O_CREAT) and a random suffix, then renaming it into place.
 * An existing path, including a symlink, is not opened or followed.
 * The temp file is removed if the write fails after this call created it.
 */
import { randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

function isErrno(err: unknown, code: string): boolean {
  return Boolean(err) && typeof err === 'object' && (err as NodeJS.ErrnoException).code === code;
}

/**
 * Create `tmp` with flag `wx` and rename it to `dest`.
 * A path that already exists is left unchanged. A temp file this call
 * created is removed when the rename fails.
 */
export function writeExclusiveTemp(tmp: string, dest: string, body: string): void {
  let created = false;
  try {
    writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o644, flag: 'wx' });
    created = true;
    renameSync(tmp, dest);
    created = false;
  } catch (err) {
    if (created) {
      try {
        unlinkSync(tmp);
      } catch {
        // The original error is the one to report.
      }
    } else if (!isErrno(err, 'EEXIST')) {
      // A failed exclusive create can leave a partial regular file.
      // Never unlink a symlink or a file this call did not create.
      try {
        const st = lstatSync(tmp);
        if (st.isFile() && !st.isSymbolicLink()) unlinkSync(tmp);
      } catch {
        // Nothing of ours to remove.
      }
    }
    throw err;
  }
}

function exclusiveTempPath(dir: string, filename: string): string {
  return join(dir, `.${filename}.${randomBytes(8).toString('hex')}.tmp`);
}

/** Write `body` to `abs`. A colliding random temp name is tried again. */
export function writeExclusiveFile(abs: string, body: string): void {
  const parent = dirname(abs);
  mkdirSync(parent, { recursive: true });
  const filename = basename(abs);
  let last: unknown;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const tmp = exclusiveTempPath(parent, filename);
    try {
      writeExclusiveTemp(tmp, abs, body);
      return;
    } catch (err) {
      last = err;
      if (isErrno(err, 'EEXIST')) continue;
      throw err;
    }
  }
  throw last instanceof Error ? last : new Error(`could not create a temp file for ${abs}`);
}
