import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { VERSION } from './version.js';
import {
  createSignatureDocument,
  loadKeys,
  verifySignature,
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

/** Usage / malformed package. Callers map this to exit 1. */
export class SharePackageUsageError extends Error {
  readonly exitCode = 1 as const;
  constructor(message: string) {
    super(message);
    this.name = 'SharePackageUsageError';
  }
}

export interface ManifestSigReport {
  present: boolean;
  ok: boolean | null;
  fingerprint: string | null;
  reason: string | null;
}

export interface SharePackageLocation {
  inputPath: string;
  packageDir: string;
  manifestPath: string;
  /** `other` is a file that is not manifest.json. */
  inputKind: 'directory' | 'manifest' | 'other' | 'missing';
  manifestExists: boolean;
}

const PACKAGE_FILE_NAMES = new Set<string>([
  RECEIPT_MD_NAME,
  RECEIPT_HTML_NAME,
  RECEIPT_SIG_NAME,
]);

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function hex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

/**
 * A directory, or a path that is `manifest.json`, resolved to the package
 * directory. Does not require the manifest to be valid.
 */
export function locateSharePackage(cwd: string, pathArg: string): SharePackageLocation {
  const inputPath = resolve(cwd, pathArg);
  if (!existsSync(inputPath)) {
    const namedManifest = basename(inputPath) === MANIFEST_NAME;
    return {
      inputPath,
      packageDir: namedManifest ? dirname(inputPath) : inputPath,
      manifestPath: namedManifest ? inputPath : join(inputPath, MANIFEST_NAME),
      inputKind: namedManifest ? 'manifest' : 'missing',
      manifestExists: false,
    };
  }
  let st;
  try {
    st = statSync(inputPath);
  } catch {
    return {
      inputPath,
      packageDir: inputPath,
      manifestPath: join(inputPath, MANIFEST_NAME),
      inputKind: 'missing',
      manifestExists: false,
    };
  }
  if (st.isDirectory()) {
    const manifestPath = join(inputPath, MANIFEST_NAME);
    return {
      inputPath,
      packageDir: inputPath,
      manifestPath,
      inputKind: 'directory',
      manifestExists: existsSync(manifestPath),
    };
  }
  if (st.isFile() && basename(inputPath) === MANIFEST_NAME) {
    return {
      inputPath,
      packageDir: dirname(inputPath),
      manifestPath: inputPath,
      inputKind: 'manifest',
      manifestExists: true,
    };
  }
  return {
    inputPath,
    packageDir: dirname(inputPath),
    manifestPath: join(dirname(inputPath), MANIFEST_NAME),
    inputKind: 'other',
    manifestExists: false,
  };
}

/**
 * True when the path is a package directory or `manifest.json` whose
 * `kind` is `agent-receipt-share`. Malformed JSON and other kinds are false
 * so plain verify stays on normal receipt paths.
 */
export function sharePackageAutoDetected(cwd: string, pathArg: string): boolean {
  const loc = locateSharePackage(cwd, pathArg);
  if ((loc.inputKind !== 'directory' && loc.inputKind !== 'manifest') || !loc.manifestExists) {
    return false;
  }
  try {
    const parsed = JSON.parse(readFileSync(loc.manifestPath, 'utf8')) as { kind?: unknown };
    return parsed?.kind === SHARE_PACKAGE_KIND;
  } catch {
    return false;
  }
}

/** Shape check. Throws SharePackageUsageError (exit 1) when the document is malformed. */
export function parseShareManifest(value: unknown): ShareManifest {
  const doc = asRecord(value);
  if (!doc) throw new SharePackageUsageError('manifest.json is not an object');
  const allowed = new Set([
    'kind',
    'version',
    'cliVersion',
    'sha256',
    'redacted',
    'files',
    'fingerprint',
    'signed',
  ]);
  for (const key of Object.keys(doc)) {
    if (!allowed.has(key)) {
      throw new SharePackageUsageError(`manifest.json has unknown field: ${key}`);
    }
  }
  if (doc.kind !== SHARE_PACKAGE_KIND) {
    throw new SharePackageUsageError(
      `manifest.json kind must be "${SHARE_PACKAGE_KIND}"`,
    );
  }
  if (doc.version !== SHARE_PACKAGE_VERSION) {
    throw new SharePackageUsageError(
      `manifest.json version must be ${SHARE_PACKAGE_VERSION}`,
    );
  }
  if (typeof doc.cliVersion !== 'string' || doc.cliVersion.trim() === '') {
    throw new SharePackageUsageError('manifest.json cliVersion must be a non-empty string');
  }
  if (!hex64(doc.sha256)) {
    throw new SharePackageUsageError('manifest.json sha256 must be 64 lowercase hex chars');
  }
  if (typeof doc.redacted !== 'boolean') {
    throw new SharePackageUsageError('manifest.json redacted must be a boolean');
  }
  if (typeof doc.signed !== 'boolean') {
    throw new SharePackageUsageError('manifest.json signed must be a boolean');
  }
  if (doc.fingerprint !== null && !hex64(doc.fingerprint)) {
    throw new SharePackageUsageError(
      'manifest.json fingerprint must be 64 lowercase hex chars or null',
    );
  }
  const files = parseShareManifestFiles(doc.files);
  return {
    kind: SHARE_PACKAGE_KIND,
    version: SHARE_PACKAGE_VERSION,
    cliVersion: doc.cliVersion,
    sha256: doc.sha256,
    redacted: doc.redacted,
    files,
    fingerprint: doc.fingerprint,
    signed: doc.signed,
  };
}

function parseShareManifestFiles(value: unknown): ShareManifestFiles {
  const files = asRecord(value);
  if (!files) throw new SharePackageUsageError('manifest.json files must be an object');
  for (const key of Object.keys(files)) {
    if (!PACKAGE_FILE_NAMES.has(key)) {
      throw new SharePackageUsageError(`manifest.json files has unknown entry: ${key}`);
    }
  }
  if (!hex64(files[RECEIPT_MD_NAME])) {
    throw new SharePackageUsageError(
      'manifest.json files["receipt.md"] must be 64 lowercase hex chars',
    );
  }
  if (!hex64(files[RECEIPT_HTML_NAME])) {
    throw new SharePackageUsageError(
      'manifest.json files["receipt.html"] must be 64 lowercase hex chars',
    );
  }
  const out: ShareManifestFiles = {
    'receipt.md': files[RECEIPT_MD_NAME],
    'receipt.html': files[RECEIPT_HTML_NAME],
  };
  if (Object.prototype.hasOwnProperty.call(files, RECEIPT_SIG_NAME)) {
    if (!hex64(files[RECEIPT_SIG_NAME])) {
      throw new SharePackageUsageError(
        'manifest.json files["receipt.sig.json"] must be 64 lowercase hex chars',
      );
    }
    out['receipt.sig.json'] = files[RECEIPT_SIG_NAME];
  }
  return out;
}

/** Read and shape-check manifest.json. Missing or malformed is exit 1. */
export function loadShareManifest(manifestPath: string): ShareManifest {
  let text: string;
  try {
    text = readFileSync(manifestPath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new SharePackageUsageError(`unreadable manifest.json (${detail})`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SharePackageUsageError('manifest.json is malformed JSON');
  }
  return parseShareManifest(parsed);
}

export interface SharePackageFileCheck {
  ok: boolean;
  reasons: string[];
}

/**
 * Byte hashes for every `manifest.files` entry, plus the signed bit.
 * `signed: true` requires `receipt.sig.json` listed. `signed: false` rejects
 * a listed or present sidecar. HTML is hashed as bytes only.
 */
export function checkSharePackageFiles(
  packageDir: string,
  manifest: ShareManifest,
): SharePackageFileCheck {
  const reasons: string[] = [];
  const listedSig = Object.prototype.hasOwnProperty.call(manifest.files, RECEIPT_SIG_NAME);
  const sigAbs = join(packageDir, RECEIPT_SIG_NAME);
  const sigPresent = existsSync(sigAbs);
  if (manifest.signed && !listedSig) {
    reasons.push('manifest signed is true but receipt.sig.json is not listed');
  }
  if (!manifest.signed && listedSig) {
    reasons.push('manifest signed is false but receipt.sig.json is listed');
  }
  if (!manifest.signed && sigPresent) {
    reasons.push('manifest signed is false but receipt.sig.json is present');
  }
  for (const [name, expected] of Object.entries(manifest.files)) {
    if (!PACKAGE_FILE_NAMES.has(name) || name.includes('..') || name.includes('/') || name.includes('\\')) {
      reasons.push(`unsafe package file name: ${name}`);
      continue;
    }
    const abs = join(packageDir, name);
    let st;
    try {
      st = lstatSync(abs);
    } catch {
      reasons.push(`missing package file: ${name}`);
      continue;
    }
    if (!st.isFile()) {
      reasons.push(`missing package file: ${name}`);
      continue;
    }
    const actual = sha256FileBytes(abs);
    if (actual !== expected) {
      reasons.push(`file hash mismatch: ${name}`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Optional `manifest.sig.json`. Absent is fine. A present sidecar is a
 * SignatureDocument over the UTF-8 hex SHA-256 of the current manifest bytes.
 */
export function inspectManifestSignature(packageDir: string): ManifestSigReport {
  const sigPath = join(packageDir, MANIFEST_SIG_NAME);
  if (!existsSync(sigPath)) {
    return { present: false, ok: null, fingerprint: null, reason: null };
  }
  const manifestPath = join(packageDir, MANIFEST_NAME);
  let hex: string;
  try {
    hex = sha256FileBytes(manifestPath);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      present: true,
      ok: false,
      fingerprint: null,
      reason: `unreadable manifest.json (${detail})`,
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(sigPath, 'utf8'));
  } catch {
    return {
      present: true,
      ok: false,
      fingerprint: null,
      reason: 'malformed manifest signature JSON',
    };
  }
  const rec = asRecord(parsed);
  const fingerprint = rec && typeof rec.fingerprint === 'string' ? rec.fingerprint : null;
  const result = verifySignature(parsed, hex);
  let reason = result.reason;
  if (reason === 'signature sha256 does not match receipt hash') {
    reason = 'manifest signature does not match manifest.json bytes';
  } else if (reason === 'Ed25519 signature does not match receipt sha256') {
    reason = 'Ed25519 signature does not match manifest sha256';
  }
  return {
    present: true,
    ok: result.ok,
    fingerprint,
    reason,
  };
}
