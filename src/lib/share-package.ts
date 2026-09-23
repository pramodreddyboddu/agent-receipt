import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { VERSION } from './version.js';
import {
  createSignatureDocument,
  loadKeys,
  writeSignatureDocument,
} from './sign.js';

/** Manifest `kind`. Peers can reject anything else. */
export const SHARE_PACKAGE_KIND = 'agent-receipt-share';
/** Manifest schema version. Not the CLI version. */
export const SHARE_PACKAGE_VERSION = 1;

export const RECEIPT_MD_NAME = 'receipt.md';
export const RECEIPT_HTML_NAME = 'receipt.html';
export const RECEIPT_SIG_NAME = 'receipt.sig.json';
export const MANIFEST_NAME = 'manifest.json';
export const MANIFEST_SIG_NAME = 'manifest.sig.json';

const HEX64 = /^[0-9a-f]{64}$/;

export interface ShareManifestFiles {
  'receipt.md': string;
  'receipt.html': string;
  'receipt.sig.json'?: string;
}

/**
 * Small index for a portable share directory.
 * `sha256` is the verify hash of `receipt.md` (canonical body).
 * `files` hashes are SHA-256 of the raw file bytes.
 * HTML is not signed. `signed` is true when `receipt.sig.json` is present.
 */
export interface ShareManifest {
  kind: typeof SHARE_PACKAGE_KIND;
  version: typeof SHARE_PACKAGE_VERSION;
  cliVersion: string;
  sha256: string;
  redacted: boolean;
  files: ShareManifestFiles;
  fingerprint: string | null;
  signed: boolean;
}

/** `foo.md` → sibling `foo.share` directory. */
export function defaultSharePackageDir(sourcePath: string): string {
  const stem = basename(sourcePath).replace(/\.md$/i, '');
  return join(dirname(sourcePath), `${stem}.share`);
}

/**
 * `--out` that names an existing directory, or ends with a slash, is the
 * package directory. Any other `--out` keeps the sibling `<stem>.share`.
 */
export function resolveSharePackageDir(
  cwd: string,
  sourcePath: string,
  out?: string,
): string {
  if (!out) return defaultSharePackageDir(sourcePath);
  const wantsDir = /[/\\]$/.test(out);
  const resolved = resolve(cwd, out);
  if (wantsDir) return resolved;
  try {
    if (statSync(resolved).isDirectory()) return resolved;
  } catch {
    // A missing path is not a directory override.
  }
  return defaultSharePackageDir(sourcePath);
}

/** SHA-256 of raw file bytes (not the receipt canonical body). */
export function sha256FileBytes(filePath: string): string {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

export function fingerprintFromSidecar(sigPath: string | null): string | null {
  if (!sigPath || !existsSync(sigPath)) return null;
  try {
    const parsed = JSON.parse(readFileSync(sigPath, 'utf8')) as { fingerprint?: unknown };
    if (typeof parsed.fingerprint === 'string' && HEX64.test(parsed.fingerprint)) {
      return parsed.fingerprint;
    }
  } catch {
    return null;
  }
  return null;
}

/** Build the manifest from files already written in `packageDir`. */
export function buildShareManifest(input: {
  packageDir: string;
  sha256: string;
  redacted: boolean;
  fingerprint: string | null;
}): ShareManifest {
  const files: ShareManifestFiles = {
    'receipt.md': sha256FileBytes(join(input.packageDir, RECEIPT_MD_NAME)),
    'receipt.html': sha256FileBytes(join(input.packageDir, RECEIPT_HTML_NAME)),
  };
  const sigAbs = join(input.packageDir, RECEIPT_SIG_NAME);
  const signed = existsSync(sigAbs);
  if (signed) {
    files['receipt.sig.json'] = sha256FileBytes(sigAbs);
  }
  return {
    kind: SHARE_PACKAGE_KIND,
    version: SHARE_PACKAGE_VERSION,
    cliVersion: VERSION,
    sha256: input.sha256,
    redacted: input.redacted,
    files,
    fingerprint: signed ? input.fingerprint : null,
    signed,
  };
}

export function writeShareManifest(packageDir: string, manifest: ShareManifest): string {
  const manifestPath = join(packageDir, MANIFEST_NAME);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return manifestPath;
}

/**
 * Sign the UTF-8 hex SHA-256 of the canonical `manifest.json` bytes.
 * Same SignatureDocument shape as a receipt sidecar. Missing keys remove
 * any stale `manifest.sig.json` and return null. That is not an error.
 */
export function signShareManifest(
  cwd: string,
  manifestPath: string,
): { sigPath: string | null } {
  const sigPath = join(dirname(manifestPath), MANIFEST_SIG_NAME);
  let keys;
  try {
    keys = loadKeys(cwd);
  } catch {
    if (existsSync(sigPath)) unlinkSync(sigPath);
    return { sigPath: null };
  }
  const hex = sha256FileBytes(manifestPath);
  const doc = createSignatureDocument(hex, keys);
  writeSignatureDocument(sigPath, doc);
  return { sigPath };
}
