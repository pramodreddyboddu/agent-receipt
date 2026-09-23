import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

/** Local key directory. Already under gitignored `.agent-receipt/`. */
export const KEY_DIR_REL = '.agent-receipt/keys';
export const PRIVATE_KEY_NAME = 'ed25519.private';
export const PUBLIC_KEY_NAME = 'ed25519.public';

export const SIG_ALG = 'ed25519' as const;
export const SIG_VERSION = 1;

const HEX64 = /^[0-9a-f]{64}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Sidecar written next to a Markdown receipt (`foo.md` → `foo.sig.json`).
 * `signature` is the base64 raw 64-byte Ed25519 signature over the UTF-8
 * bytes of `sha256` (the same hex `verify` uses), not over the Markdown.
 * `publicKey` is SPKI PEM so a peer can verify without this keys directory.
 * The private key is never stored here.
 */
export interface SignatureDocument {
  alg: typeof SIG_ALG;
  version: typeof SIG_VERSION;
  sha256: string;
  /** Key fingerprint: lowercase hex SHA-256 of the DER SPKI bytes. */
  fingerprint: string;
  signature: string;
  publicKey: string;
}

export interface VerifySignatureResult {
  ok: boolean;
  reason: string | null;
}

export interface LoadedKeys {
  privateKeyPem: string;
  publicKeyPem: string;
  privateKeyPath: string;
  publicKeyPath: string;
  /** Key fingerprint of the public key. */
  fingerprint: string;
}

export interface SignatureStatus {
  present: boolean;
  /** Null when no sidecar is present. */
  ok: boolean | null;
  alg: string | null;
  fingerprint: string | null;
  reason: string | null;
}

export const ABSENT_SIGNATURE: SignatureStatus = {
  present: false,
  ok: null,
  alg: null,
  fingerprint: null,
  reason: null,
};

export function keyDir(cwd: string): string {
  return join(cwd, KEY_DIR_REL);
}

export function privateKeyPath(cwd: string): string {
  return join(keyDir(cwd), PRIVATE_KEY_NAME);
}

export function publicKeyPath(cwd: string): string {
  return join(keyDir(cwd), PUBLIC_KEY_NAME);
}

/** True for the local key directory or an `ed25519.private` / `ed25519.public` path. */
export function isLocalKeyMaterialPath(filePath: string): boolean {
  const p = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  if (p === '.agent-receipt/keys' || p.startsWith('.agent-receipt/keys/')) return true;
  const base = p.split('/').pop() || p;
  return base === PRIVATE_KEY_NAME || base === PUBLIC_KEY_NAME;
}

export function ensureKeyDir(cwd: string): string {
  const dir = keyDir(cwd);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* directory mode is best-effort; the private key is still mode 0o600 */
  }
  return dir;
}

/**
 * Key fingerprint: lowercase hex SHA-256 of the DER-encoded SPKI public key.
 * Not a cert fingerprint and not a hash of the PEM text.
 */
export function fingerprint(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

function pemExport(key: KeyObject, type: 'pkcs8' | 'spki'): string {
  const exported = key.export({ type, format: 'pem' });
  if (typeof exported !== 'string') {
    throw new Error('expected PEM text from key export');
  }
  return exported;
}

export function loadKeys(cwd: string): LoadedKeys {
  const privPath = privateKeyPath(cwd);
  const pubPath = publicKeyPath(cwd);
  const missing: string[] = [];
  if (!existsSync(privPath)) missing.push(privPath);
  if (!existsSync(pubPath)) missing.push(pubPath);
  if (missing.length) {
    throw new Error(
      `Ed25519 keys not found (${missing.join(', ')}). Run \`agent-receipt keygen\` to create a local keypair.`,
    );
  }
  let privateKeyPem: string;
  let publicKeyPem: string;
  try {
    privateKeyPem = readFileSync(privPath, 'utf8');
    publicKeyPem = readFileSync(pubPath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Could not read Ed25519 keys under ${keyDir(cwd)}. Run \`agent-receipt keygen\`. (${detail})`,
    );
  }
  if (privateKeyPem.includes('PUBLIC KEY') && !privateKeyPem.includes('PRIVATE KEY')) {
    throw new Error(
      `Ed25519 private key file is not a PKCS8 private key (${privPath}). Run \`agent-receipt keygen --force\` to rotate.`,
    );
  }
  try {
    createPrivateKey(privateKeyPem);
    createPublicKey(publicKeyPem);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Ed25519 keys are unreadable. Run \`agent-receipt keygen --force\` to rotate. (${detail})`,
    );
  }
  return {
    privateKeyPem,
    publicKeyPem,
    privateKeyPath: privPath,
    publicKeyPath: pubPath,
    fingerprint: fingerprint(publicKeyPem),
  };
}

export interface GeneratedKeys {
  created: boolean;
  rotated: boolean;
  fingerprint: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

/**
 * Write a new Ed25519 keypair. Caller decides create vs rotate.
 * Private key is PKCS8 PEM mode 0o600. Public key is SPKI PEM.
 */
export function writeKeyPair(cwd: string): { fingerprint: string } {
  ensureKeyDir(cwd);
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privatePem = pemExport(privateKey, 'pkcs8');
  const publicPem = pemExport(publicKey, 'spki');
  const privPath = privateKeyPath(cwd);
  const pubPath = publicKeyPath(cwd);
  writeFileSync(privPath, privatePem, { mode: 0o600 });
  chmodSync(privPath, 0o600);
  writeFileSync(pubPath, publicPem, { mode: 0o644 });
  return { fingerprint: fingerprint(publicPem) };
}

/** `foo.md` → `foo.sig.json` in the same directory. */
export function signaturePathFor(receiptPath: string): string {
  if (/\.md$/i.test(receiptPath)) return receiptPath.replace(/\.md$/i, '.sig.json');
  return `${receiptPath}.sig.json`;
}

/** Sign the receipt sha256 hex string as UTF-8 bytes. */
export function signSha256Hex(sha256Hex: string, privateKeyPem: string): Buffer {
  return cryptoSign(null, Buffer.from(sha256Hex, 'utf8'), createPrivateKey(privateKeyPem));
}

export function createSignatureDocument(
  sha256Hex: string,
  keys: LoadedKeys,
): SignatureDocument {
  const raw = signSha256Hex(sha256Hex, keys.privateKeyPem);
  return {
    alg: SIG_ALG,
    version: SIG_VERSION,
    sha256: sha256Hex,
    fingerprint: keys.fingerprint,
    signature: raw.toString('base64'),
    publicKey: keys.publicKeyPem,
  };
}

export function writeSignatureSidecar(receiptPath: string, doc: SignatureDocument): string {
  const sigPath = signaturePathFor(receiptPath);
  const body = JSON.stringify(doc, null, 2) + '\n';
  if (body.includes('PRIVATE KEY')) {
    throw new Error('refusing to write a signature sidecar that contains a private key');
  }
  writeFileSync(sigPath, body, { mode: 0o644 });
  return sigPath;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

/**
 * Fail closed. Checks alg, version, sha256 match, fingerprint vs the
 * embedded SPKI public key, and `crypto.verify` over the UTF-8 sha256 hex.
 */
export function verifySignature(
  sigDoc: unknown,
  expectedSha256: string,
): VerifySignatureResult {
  const doc = asRecord(sigDoc);
  if (!doc) return { ok: false, reason: 'malformed signature document' };
  if (doc.alg !== SIG_ALG) {
    return { ok: false, reason: `unsupported signature alg: ${String(doc.alg)}` };
  }
  if (doc.version !== SIG_VERSION) {
    return { ok: false, reason: `unsupported signature version: ${String(doc.version)}` };
  }
  if (typeof doc.sha256 !== 'string' || !HEX64.test(doc.sha256)) {
    return { ok: false, reason: 'signature sha256 is missing or not 64 lowercase hex chars' };
  }
  if (!HEX64.test(expectedSha256) || doc.sha256 !== expectedSha256) {
    return { ok: false, reason: 'signature sha256 does not match receipt hash' };
  }
  if (typeof doc.fingerprint !== 'string' || !HEX64.test(doc.fingerprint)) {
    return { ok: false, reason: 'signature fingerprint is missing or not 64 lowercase hex chars' };
  }
  if (typeof doc.publicKey !== 'string' || doc.publicKey.length === 0) {
    return { ok: false, reason: 'signature publicKey is missing' };
  }
  if (doc.publicKey.includes('PRIVATE KEY')) {
    return { ok: false, reason: 'signature document must not contain a private key' };
  }
  if (typeof doc.signature !== 'string' || !B64.test(doc.signature)) {
    return { ok: false, reason: 'signature is missing or not base64' };
  }
  let derived: string;
  try {
    derived = fingerprint(doc.publicKey);
  } catch {
    return { ok: false, reason: 'signature publicKey is not a valid SPKI key' };
  }
  if (derived !== doc.fingerprint) {
    return { ok: false, reason: 'fingerprint does not match embedded publicKey' };
  }
  const sigBuf = Buffer.from(doc.signature, 'base64');
  if (sigBuf.length !== 64) {
    return { ok: false, reason: 'signature is not 64 bytes' };
  }
  try {
    const ok = cryptoVerify(
      null,
      Buffer.from(expectedSha256, 'utf8'),
      createPublicKey(doc.publicKey),
      sigBuf,
    );
    if (!ok) {
      return { ok: false, reason: 'Ed25519 signature does not match receipt sha256' };
    }
  } catch {
    return { ok: false, reason: 'Ed25519 verify failed' };
  }
  return { ok: true, reason: null };
}

/** Read `*.sig.json` beside a receipt. Malformed JSON fails closed. */
export function inspectReceiptSignature(
  receiptPath: string,
  expectedSha256: string,
): SignatureStatus {
  const sigPath = signaturePathFor(receiptPath);
  if (!existsSync(sigPath)) return { ...ABSENT_SIGNATURE };
  let text: string;
  try {
    text = readFileSync(sigPath, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      present: true,
      ok: false,
      alg: null,
      fingerprint: null,
      reason: `unreadable signature sidecar (${detail})`,
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      present: true,
      ok: false,
      alg: null,
      fingerprint: null,
      reason: 'malformed signature JSON',
    };
  }
  const rec = asRecord(parsed);
  const result = verifySignature(parsed, expectedSha256);
  return {
    present: true,
    ok: result.ok,
    alg: rec && typeof rec.alg === 'string' ? rec.alg : null,
    fingerprint: rec && typeof rec.fingerprint === 'string' ? rec.fingerprint : null,
    reason: result.reason,
  };
}
