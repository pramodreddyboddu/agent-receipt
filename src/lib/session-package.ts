import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { appendHashFooter, canonicalBody } from './hash.js';
import { receiptsDir } from './receipt-index.js';
import {
  createSignatureDocument,
  loadKeys,
  verifySignature,
  writeSignatureDocument,
} from './sign.js';
import { sha256FileBytes } from './share-package.js';
import { VERSION } from './version.js';

/** Manifest `kind`. Peers reject anything else. */
export const SESSION_PACKAGE_KIND = 'agent-receipt-session';
/** Manifest schema version. Not the CLI version. */
export const SESSION_PACKAGE_VERSION = 1;

export const SESSION_MANIFEST_NAME = 'session-manifest.json';
export const SESSION_MANIFEST_SIG_NAME = 'session-manifest.sig.json';
export const SESSION_RECEIPTS_DIR = 'receipts';

/** Same token `share` writes when it masks Host. Legal on a 1.0.28+ receipt. */
export const SESSION_REDACTED_HOST = '[REDACTED]';

export const SESSION_WARNING_ORPHAN = 'orphan';
export const SESSION_WARNING_CYCLE = 'cycle';
export const SESSION_WARNING_CROSS_SESSION = 'cross-session-parent';
export const SESSION_WARNING_PARENT_UNVERIFIED = 'parent-unverified';
export const SESSION_WARNING_MISSING_SESSION = 'missing-session';

const SESSION_WARNING_CODES = new Set<string>([
  SESSION_WARNING_ORPHAN,
  SESSION_WARNING_CYCLE,
  SESSION_WARNING_CROSS_SESSION,
  SESSION_WARNING_PARENT_UNVERIFIED,
  SESSION_WARNING_MISSING_SESSION,
]);

const HEX64 = /^[0-9a-f]{64}$/;
const LINK_ID_RE = /^r-[0-9a-f]{16}$/;
const SAFE_BASENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.md$/;
const SAFE_DIR_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,200}$/;

/** Usage / malformed session package. Callers map this to exit 1. */
export class SessionPackageUsageError extends Error {
  readonly exitCode = 1 as const;
  constructor(message: string) {
    super(message);
    this.name = 'SessionPackageUsageError';
  }
}

export interface SessionManifestReceipt {
  id: string;
  parent: string | null;
  agent: string | null;
  /** Packaged host: `[REDACTED]`, the original label, or null when unset. */
  host: string | null;
  /** Path relative to the package root, always `receipts/<basename>.md`. */
  path: string;
  /** Canonical verify hash of the packaged receipt (the hex `verify` prints). */
  sha256: string;
  /** SHA-256 of the raw receipt file bytes. */
  bytes: string;
  signed: boolean;
  fingerprint: string | null;
  /** SHA-256 of the raw sidecar bytes. Present only when `signed` is true. */
  sigBytes?: string;
  orphan: boolean;
  cycle: boolean;
  warnings: string[];
}

/**
 * Index for a portable session directory.
 * Receipts live under `receipts/`. Optional `session-manifest.sig.json`
 * is a SignatureDocument over the UTF-8 hex SHA-256 of this file's bytes.
 * It is not a receipt and is not listed inside `receipts`.
 */
export interface SessionManifest {
  kind: typeof SESSION_PACKAGE_KIND;
  version: typeof SESSION_PACKAGE_VERSION;
  cliVersion: string;
  session: string;
  receiptCount: number;
  /**
   * False when export masked Host (the default). True when `--include-host`
   * kept the label. Session, parent, and agent are always kept.
   */
  includeHost: boolean;
  warnings: string[];
  receipts: SessionManifestReceipt[];
}

export interface ManifestSigReport {
  present: boolean;
  ok: boolean | null;
  fingerprint: string | null;
  reason: string | null;
}

export interface SessionPackageLocation {
  inputPath: string;
  packageDir: string;
  manifestPath: string;
  inputKind: 'directory' | 'manifest' | 'other' | 'missing';
  manifestExists: boolean;
}

/**
 * Directory basename for a session id.
 * A single safe path segment is `<id>.session`. Anything else (spaces,
 * slashes) becomes `session-<12 hex of sha256(id)>.session` so the name
 * cannot escape the parent directory. The manifest stores the real id.
 */
export function sessionPackageBaseName(sessionId: string): string {
  if (SAFE_DIR_ID.test(sessionId) && !sessionId.includes('..')) {
    return `${sessionId}.session`;
  }
  const digest = createHash('sha256').update(sessionId, 'utf8').digest('hex').slice(0, 12);
  return `session-${digest}.session`;
}

/**
 * Default package directory: the sibling of outDir.
 * `.agent-receipt/receipts` → `.agent-receipt/<id>.session`.
 */
export function defaultSessionPackageDir(cwd: string, sessionId: string): string {
  return join(dirname(receiptsDir(cwd)), sessionPackageBaseName(sessionId));
}

/** `--out` always names the package directory. Omitted keeps the sibling of outDir. */
export function resolveSessionPackageDir(
  cwd: string,
  sessionId: string,
  out?: string,
): string {
  if (!out) return defaultSessionPackageDir(cwd, sessionId);
  return resolve(cwd, out);
}

/** True when `name` is a `*.session` package directory basename. */
export function isSafeReceiptBasename(name: string): boolean {
  if (!SAFE_BASENAME.test(name)) return false;
  if (name.toLowerCase().endsWith('.prove.md')) return false;
  return true;
}

/**
 * Replace an explicit Host line with `[REDACTED]` and re-hash.
 * No host line, an already masked host, or `includeHost` leaves the
 * original bytes alone so an existing sidecar still matches.
 * A rewrite drops bytes after the integrity footer (same as share).
 */
export function publishSessionReceipt(
  markdown: string,
  includeHost: boolean,
): { markdown: string; masked: boolean } {
  if (includeHost) return { markdown, masked: false };
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  let changed = false;
  let pastIntegrity = false;
  const out: string[] = [];
  for (const line of lines) {
    if (
      !pastIntegrity &&
      (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256'))
    ) {
      pastIntegrity = true;
    }
    if (
      !pastIntegrity &&
      /^- \*\*Host\*\*:/.test(line) &&
      line !== `- **Host**: ${SESSION_REDACTED_HOST}`
    ) {
      out.push(`- **Host**: ${SESSION_REDACTED_HOST}`);
      changed = true;
      continue;
    }
    out.push(line);
  }
  if (!changed) return { markdown, masked: false };
  return { markdown: appendHashFooter(canonicalBody(out.join('\n'))), masked: true };
}

export function writeSessionManifest(packageDir: string, manifest: SessionManifest): string {
  const manifestPath = join(packageDir, SESSION_MANIFEST_NAME);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return manifestPath;
}

/**
 * Sign the UTF-8 hex SHA-256 of `session-manifest.json`.
 * Missing keys remove a stale sidecar and return null. That is not an error.
 */
export function signSessionManifest(
  cwd: string,
  manifestPath: string,
): { sigPath: string | null } {
  const sigPath = join(dirname(manifestPath), SESSION_MANIFEST_SIG_NAME);
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

/**
 * A directory, or a path that is `session-manifest.json`, resolved to the
 * package directory. Does not require the manifest to be valid.
 */
export function locateSessionPackage(cwd: string, pathArg: string): SessionPackageLocation {
  const inputPath = resolve(cwd, pathArg);
  if (!existsSync(inputPath)) {
    const namedManifest = basename(inputPath) === SESSION_MANIFEST_NAME;
    return {
      inputPath,
      packageDir: namedManifest ? dirname(inputPath) : inputPath,
      manifestPath: namedManifest ? inputPath : join(inputPath, SESSION_MANIFEST_NAME),
      inputKind: namedManifest ? 'manifest' : 'missing',
      manifestExists: false,
    };
  }
  let st;
  try {
    st = lstatSync(inputPath);
  } catch {
    return {
      inputPath,
      packageDir: inputPath,
      manifestPath: join(inputPath, SESSION_MANIFEST_NAME),
      inputKind: 'missing',
      manifestExists: false,
    };
  }
  if (st.isSymbolicLink()) {
    return {
      inputPath,
      packageDir: inputPath,
      manifestPath: join(inputPath, SESSION_MANIFEST_NAME),
      inputKind: 'other',
      manifestExists: false,
    };
  }
  if (st.isDirectory()) {
    const manifestPath = join(inputPath, SESSION_MANIFEST_NAME);
    return {
      inputPath,
      packageDir: inputPath,
      manifestPath,
      inputKind: 'directory',
      manifestExists: existsSync(manifestPath) && isRegularFile(manifestPath),
    };
  }
  if (st.isFile() && basename(inputPath) === SESSION_MANIFEST_NAME) {
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
    manifestPath: join(dirname(inputPath), SESSION_MANIFEST_NAME),
    inputKind: 'other',
    manifestExists: false,
  };
}

export function isRegularFile(filePath: string): boolean {
  try {
    const st = lstatSync(filePath);
    return st.isFile() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function hex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

function isRef(value: unknown): value is string {
  return typeof value === 'string' && (LINK_ID_RE.test(value) || HEX64.test(value));
}

function parseWarnings(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new SessionPackageUsageError(`${label} must be an array`);
  }
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || !SESSION_WARNING_CODES.has(item)) {
      throw new SessionPackageUsageError(
        `${label} has an unknown code: ${JSON.stringify(item)}`,
      );
    }
    if (!out.includes(item)) out.push(item);
  }
  return out;
}

function parseNullableString(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value !== 'string') {
    throw new SessionPackageUsageError(`${label} must be a string or null`);
  }
  return value;
}

/** Shape check. Throws SessionPackageUsageError (exit 1) when the document is malformed. */
export function parseSessionManifest(value: unknown): SessionManifest {
  const doc = asRecord(value);
  if (!doc) throw new SessionPackageUsageError('session-manifest.json is not an object');
  const allowed = new Set([
    'kind',
    'version',
    'cliVersion',
    'session',
    'receiptCount',
    'includeHost',
    'warnings',
    'receipts',
  ]);
  for (const key of Object.keys(doc)) {
    if (!allowed.has(key)) {
      throw new SessionPackageUsageError(`session-manifest.json has unknown field: ${key}`);
    }
  }
  if (doc.kind !== SESSION_PACKAGE_KIND) {
    throw new SessionPackageUsageError(
      `session-manifest.json kind must be "${SESSION_PACKAGE_KIND}"`,
    );
  }
  if (doc.version !== SESSION_PACKAGE_VERSION) {
    throw new SessionPackageUsageError(
      `session-manifest.json version must be ${SESSION_PACKAGE_VERSION}`,
    );
  }
  if (typeof doc.cliVersion !== 'string' || doc.cliVersion.trim() === '') {
    throw new SessionPackageUsageError('session-manifest.json cliVersion must be a non-empty string');
  }
  if (typeof doc.session !== 'string' || doc.session.trim() === '') {
    throw new SessionPackageUsageError('session-manifest.json session must be a non-empty string');
  }
  if (typeof doc.receiptCount !== 'number' || !Number.isInteger(doc.receiptCount) || doc.receiptCount < 1) {
    throw new SessionPackageUsageError('session-manifest.json receiptCount must be an integer >= 1');
  }
  if (typeof doc.includeHost !== 'boolean') {
    throw new SessionPackageUsageError('session-manifest.json includeHost must be a boolean');
  }
  const warnings = parseWarnings(doc.warnings, 'session-manifest.json warnings');
  if (!Array.isArray(doc.receipts)) {
    throw new SessionPackageUsageError('session-manifest.json receipts must be an array');
  }
  if (doc.receipts.length !== doc.receiptCount) {
    throw new SessionPackageUsageError(
      'session-manifest.json receiptCount must equal receipts.length',
    );
  }
  const receipts = doc.receipts.map((entry, index) =>
    parseReceiptEntry(entry, index, doc.includeHost as boolean),
  );
  const paths = new Set<string>();
  const ids = new Set<string>();
  const bases = new Set<string>();
  for (const entry of receipts) {
    if (paths.has(entry.path)) {
      throw new SessionPackageUsageError(`duplicate receipt path: ${entry.path}`);
    }
    paths.add(entry.path);
    if (ids.has(entry.id)) {
      throw new SessionPackageUsageError(`duplicate receipt id: ${entry.id}`);
    }
    ids.add(entry.id);
    const base = basename(entry.path);
    if (bases.has(base)) {
      throw new SessionPackageUsageError(`duplicate receipt basename: ${base}`);
    }
    bases.add(base);
  }
  return {
    kind: SESSION_PACKAGE_KIND,
    version: SESSION_PACKAGE_VERSION,
    cliVersion: doc.cliVersion,
    session: doc.session,
    receiptCount: doc.receiptCount,
    includeHost: doc.includeHost,
    warnings,
    receipts,
  };
}

function parseReceiptEntry(
  value: unknown,
  index: number,
  includeHost: boolean,
): SessionManifestReceipt {
  const label = `session-manifest.json receipts[${index}]`;
  const doc = asRecord(value);
  if (!doc) throw new SessionPackageUsageError(`${label} must be an object`);
  const allowed = new Set([
    'id',
    'parent',
    'agent',
    'host',
    'path',
    'sha256',
    'bytes',
    'signed',
    'fingerprint',
    'sigBytes',
    'orphan',
    'cycle',
    'warnings',
  ]);
  for (const key of Object.keys(doc)) {
    if (!allowed.has(key)) {
      throw new SessionPackageUsageError(`${label} has unknown field: ${key}`);
    }
  }
  if (!isRef(doc.id)) {
    throw new SessionPackageUsageError(
      `${label}.id must be an r- id or 64 lowercase hex chars`,
    );
  }
  if (doc.parent !== null && !isRef(doc.parent)) {
    throw new SessionPackageUsageError(
      `${label}.parent must be an r- id, 64 lowercase hex chars, or null`,
    );
  }
  const agent = parseNullableString(doc.agent, `${label}.agent`);
  if (agent !== null && agent.trim() === '') {
    throw new SessionPackageUsageError(`${label}.agent must be a non-empty string or null`);
  }
  const host = parseNullableString(doc.host, `${label}.host`);
  if (!includeHost && host !== null && host !== SESSION_REDACTED_HOST) {
    throw new SessionPackageUsageError(
      `${label}.host must be null or "${SESSION_REDACTED_HOST}" when includeHost is false`,
    );
  }
  if (typeof doc.path !== 'string' || !isSafeReceiptRel(doc.path)) {
    throw new SessionPackageUsageError(
      `${label}.path must be receipts/<basename>.md with a safe basename`,
    );
  }
  if (!hex64(doc.sha256)) {
    throw new SessionPackageUsageError(`${label}.sha256 must be 64 lowercase hex chars`);
  }
  if (!hex64(doc.bytes)) {
    throw new SessionPackageUsageError(`${label}.bytes must be 64 lowercase hex chars`);
  }
  if (typeof doc.signed !== 'boolean') {
    throw new SessionPackageUsageError(`${label}.signed must be a boolean`);
  }
  if (doc.fingerprint !== null && !hex64(doc.fingerprint)) {
    throw new SessionPackageUsageError(
      `${label}.fingerprint must be 64 lowercase hex chars or null`,
    );
  }
  if (doc.signed && !hex64(doc.fingerprint)) {
    throw new SessionPackageUsageError(`${label}.fingerprint is required when signed is true`);
  }
  if (!doc.signed && doc.fingerprint !== null) {
    throw new SessionPackageUsageError(`${label}.fingerprint must be null when signed is false`);
  }
  if (doc.signed && !hex64(doc.sigBytes)) {
    throw new SessionPackageUsageError(`${label}.sigBytes is required when signed is true`);
  }
  if (!doc.signed && doc.sigBytes !== undefined) {
    throw new SessionPackageUsageError(`${label}.sigBytes must be omitted when signed is false`);
  }
  if (typeof doc.orphan !== 'boolean' || typeof doc.cycle !== 'boolean') {
    throw new SessionPackageUsageError(`${label}.orphan and cycle must be booleans`);
  }
  const warnings = parseWarnings(doc.warnings, `${label}.warnings`);
  if (doc.orphan !== warnings.includes(SESSION_WARNING_ORPHAN)) {
    throw new SessionPackageUsageError(`${label}.orphan must match warnings`);
  }
  if (doc.cycle !== warnings.includes(SESSION_WARNING_CYCLE)) {
    throw new SessionPackageUsageError(`${label}.cycle must match warnings`);
  }
  const entry: SessionManifestReceipt = {
    id: doc.id,
    parent: doc.parent,
    agent,
    host,
    path: doc.path,
    sha256: doc.sha256,
    bytes: doc.bytes,
    signed: doc.signed,
    fingerprint: doc.fingerprint,
    orphan: doc.orphan,
    cycle: doc.cycle,
    warnings,
  };
  if (doc.signed) entry.sigBytes = doc.sigBytes as string;
  return entry;
}

/** `receipts/<safe>.md` only. No absolute paths, no `..`, no extra segments. */
export function isSafeReceiptRel(rel: string): boolean {
  if (typeof rel !== 'string' || !rel) return false;
  if (rel.includes('\\') || rel.startsWith('/') || rel.includes('..')) return false;
  const prefix = `${SESSION_RECEIPTS_DIR}/`;
  if (!rel.startsWith(prefix)) return false;
  const base = rel.slice(prefix.length);
  if (!base || base.includes('/')) return false;
  return isSafeReceiptBasename(base);
}

export function loadSessionManifest(manifestPath: string): SessionManifest {
  let text: string;
  try {
    text = readFileSync(manifestPath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new SessionPackageUsageError(`unreadable session-manifest.json (${detail})`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SessionPackageUsageError('session-manifest.json is malformed JSON');
  }
  return parseSessionManifest(parsed);
}

/**
 * Optional `session-manifest.sig.json`. Absent is fine. A present sidecar
 * is a SignatureDocument over the UTF-8 hex SHA-256 of the manifest bytes.
 */
export function inspectSessionManifestSignature(packageDir: string): ManifestSigReport {
  const sigPath = join(packageDir, SESSION_MANIFEST_SIG_NAME);
  if (!existsSync(sigPath)) {
    return { present: false, ok: null, fingerprint: null, reason: null };
  }
  if (!isRegularFile(sigPath)) {
    return {
      present: true,
      ok: false,
      fingerprint: null,
      reason: 'session-manifest.sig.json is not a regular file',
    };
  }
  const manifestPath = join(packageDir, SESSION_MANIFEST_NAME);
  let hex: string;
  try {
    hex = sha256FileBytes(manifestPath);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      present: true,
      ok: false,
      fingerprint: null,
      reason: `unreadable session-manifest.json (${detail})`,
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
      reason: 'malformed session manifest signature JSON',
    };
  }
  const rec = asRecord(parsed);
  const fingerprint = rec && typeof rec.fingerprint === 'string' ? rec.fingerprint : null;
  const result = verifySignature(parsed, hex);
  let reason = result.reason;
  if (reason === 'signature sha256 does not match receipt hash') {
    reason = 'session manifest signature does not match session-manifest.json bytes';
  } else if (reason === 'Ed25519 signature does not match receipt sha256') {
    reason = 'Ed25519 signature does not match session manifest sha256';
  }
  return {
    present: true,
    ok: result.ok,
    fingerprint,
    reason,
  };
}

/** Remove a directory this command created. Ignores a missing path. */
export function removeTree(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

export function partialPackageDir(dest: string): string {
  return join(
    dirname(dest),
    `.${basename(dest)}.partial-${randomBytes(4).toString('hex')}`,
  );
}

export function ensurePackageParent(dest: string): void {
  mkdirSync(dirname(dest), { recursive: true });
}

/** Current CLI version, re-exported for manifest writers. */
export { VERSION };
