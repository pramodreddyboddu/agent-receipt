/**
 * Sigstore keyless signing for one DSSE envelope.
 *
 * An ephemeral P-256 key stays in memory. Fulcio binds it to an OIDC
 * identity. The DSSE PAE is signed with that key. Rekor returns a signed
 * entry timestamp and an inclusion proof. The bundle is
 * application/vnd.dev.sigstore.bundle.v0.3+json.
 *
 * The private key and the OIDC token are never written and never placed in
 * an error string. Certificate transparency (embedded SCTs) is not checked:
 * the time source is the Rekor integrated time. This is not a CA.
 */
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import {
  DSSE_PAYLOAD_TYPE,
  decodeBase64,
  dssePae,
  encodeBase64,
  type DsseEnvelope,
} from '../dsse.js';
import { fingerprint } from '../sign.js';
import {
  chainToTrustedRoot,
  certificateDer,
  fulcioIssuer,
  identitySans,
  validAt,
} from './x509.js';
import {
  buildCheckpoint,
  logIdForKey,
  rootFromInclusion,
  signEntryTimestamp,
  verifyCheckpoint,
  verifyEntryTimestamp,
} from './tlog.js';
import { loadTrustedRoot, TrustedRootError, type TrustedLog, type TrustedRoot } from './trust-root.js';

export const BUNDLE_MEDIA_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json';
export const DEFAULT_FULCIO_URL = 'https://fulcio.sigstore.dev';
export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';
const DEFAULT_TIMEOUT_MS = 10_000;

export class KeylessError extends Error {
  readonly exitCode: 1 | 2;
  constructor(message: string, exitCode: 1 | 2 = 1) {
    super(message);
    this.name = 'KeylessError';
    this.exitCode = exitCode;
  }
}

export interface KeylessSignOptions {
  identityTokenPath?: string;
  fulcioUrl?: string;
  rekorUrl?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

export interface KeylessBundleResult {
  bundle: Record<string, unknown>;
  bundleJson: string;
  envelope: DsseEnvelope;
  identity: string;
  issuer: string;
  integratedTime: number;
  logIndex: number;
}

function scrub(message: string, secrets: string[]): string {
  let out = message;
  for (const secret of secrets) {
    if (secret && secret.length >= 8) out = out.split(secret).join('[REDACTED]');
  }
  return out.replace(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g, '[REDACTED]');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || !Number.isFinite(value)) {
      throw new KeylessError('canonical JSON number must be an integer');
    }
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`;
  }
  throw new KeylessError('canonical JSON value is unsupported');
}

/** Canonical Rekor intoto v0.0.2 body. `publicKey` is the leaf certificate DER, base64. */
export function canonicalIntotoBody(
  payloadB64: string,
  payloadType: string,
  sigB64: string,
  certB64: string,
): Buffer {
  const payloadHash = createHash('sha256').update(decodeBase64(payloadB64)).digest('hex');
  const doc = {
    apiVersion: '0.0.2',
    kind: 'intoto',
    spec: {
      content: {
        envelope: {
          payload: payloadB64,
          payloadType,
          signatures: [{ publicKey: certB64, sig: sigB64 }],
        },
        payloadHash: { algorithm: 'sha256', value: payloadHash },
      },
    },
  };
  return Buffer.from(canonicalize(doc), 'utf8');
}

function httpUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new KeylessError(`${label} is not a URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new KeylessError(`${label} must be http or https`);
  }
  return url;
}

function originOf(url: URL): string {
  return url.origin;
}

function timeoutMs(explicit: number | undefined, env: NodeJS.ProcessEnv): number {
  if (explicit !== undefined) {
    if (!Number.isInteger(explicit) || explicit < 1) throw new KeylessError('Sigstore timeout must be a positive integer');
    return explicit;
  }
  const raw = env.AGENT_RECEIPT_SIGSTORE_TIMEOUT_MS;
  if (raw === undefined || raw === '') return DEFAULT_TIMEOUT_MS;
  if (!/^\d+$/.test(raw)) throw new KeylessError('AGENT_RECEIPT_SIGSTORE_TIMEOUT_MS must be a positive integer');
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new KeylessError('AGENT_RECEIPT_SIGSTORE_TIMEOUT_MS must be a positive integer');
  return n;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length < 2 || !parts[1]) throw new KeylessError('OIDC token is not a JWT');
  let json: string;
  try {
    json = decodeBase64(parts[1]).toString('utf8');
  } catch {
    throw new KeylessError('OIDC token payload is not base64');
  }
  let payload: unknown;
  try {
    payload = JSON.parse(json);
  } catch {
    throw new KeylessError('OIDC token payload is not JSON');
  }
  const doc = asRecord(payload);
  if (!doc) throw new KeylessError('OIDC token payload is not an object');
  return doc;
}

function assertFresh(payload: Record<string, unknown>): void {
  if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
    if (payload.exp * 1000 < Date.now() - 60_000) throw new KeylessError('OIDC token is expired');
  }
}

/**
 * `--identity-token` wins, then SIGSTORE_ID_TOKEN, then the GitHub Actions
 * ambient token. The token string is returned to the caller and must not
 * be logged.
 */
export async function resolveOidcToken(
  identityTokenPath: string | undefined,
  env: NodeJS.ProcessEnv,
  timeout: number,
): Promise<string> {
  if (identityTokenPath !== undefined) {
    const token = readTokenFile(identityTokenPath).trim();
    if (!token) throw new KeylessError('OIDC identity token is empty');
    return token;
  }
  const fromEnv = env.SIGSTORE_ID_TOKEN;
  if (typeof fromEnv === 'string' && fromEnv.trim()) return fromEnv.trim();
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (typeof requestUrl === 'string' && requestUrl && typeof requestToken === 'string' && requestToken) {
    return requestActionsToken(requestUrl, requestToken, timeout);
  }
  throw new KeylessError(
    'no OIDC token. Pass --identity-token, set SIGSTORE_ID_TOKEN, or run in GitHub Actions with id-token: write',
  );
}

function readTokenFile(filePath: string): string {
  if (filePath === '-') {
    try {
      return readFileSync(0, 'utf8');
    } catch {
      throw new KeylessError('could not read the OIDC token from stdin');
    }
  }
  try {
    return readFileSync(filePath, 'utf8');
  } catch {
    throw new KeylessError('OIDC identity token file is not readable');
  }
}

async function requestActionsToken(requestUrl: string, requestToken: string, timeout: number): Promise<string> {
  let url: URL;
  try {
    url = new URL(requestUrl);
  } catch {
    throw new KeylessError('ACTIONS_ID_TOKEN_REQUEST_URL is not a URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new KeylessError('ACTIONS_ID_TOKEN_REQUEST_URL must be http or https');
  }
  url.searchParams.set('audience', 'sigstore');
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'GET',
      redirect: 'error',
      headers: { Authorization: `Bearer ${requestToken}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(timeout),
    });
  } catch (err) {
    throw networkError(err, 'GitHub Actions OIDC');
  }
  if (!res.ok) throw new KeylessError(`GitHub Actions OIDC returned HTTP ${res.status}`);
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new KeylessError('GitHub Actions OIDC returned invalid JSON');
  }
  const doc = asRecord(body);
  const value = doc && typeof doc.value === 'string' ? doc.value.trim() : '';
  if (!value) throw new KeylessError('GitHub Actions OIDC response did not include a token');
  return value;
}

function networkError(err: unknown, label: string): KeylessError {
  const name = err instanceof Error ? err.name : '';
  if (name === 'TimeoutError' || name === 'AbortError') return new KeylessError(`timed out contacting ${label}`);
  return new KeylessError(`network error contacting ${label}`);
}

async function postJson(url: URL, body: unknown, timeout: number, label: string): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeout),
    });
  } catch (err) {
    throw networkError(err, label);
  }
  const text = await res.text();
  if (!res.ok) throw new KeylessError(`${label} returned HTTP ${res.status}`);
  try {
    return JSON.parse(text);
  } catch {
    throw new KeylessError(`${label} returned invalid JSON`);
  }
}

function pemPublic(key: KeyObject): string {
  const exported = key.export({ type: 'spki', format: 'pem' });
  if (typeof exported !== 'string') throw new KeylessError('ephemeral public key export failed');
  return exported.trim();
}

function leafFromFulcio(value: unknown): Buffer {
  const doc = asRecord(value);
  const embedded = doc ? asRecord(doc.signedCertificateEmbeddedSct) : null;
  const detached = doc ? asRecord(doc.signedCertificateDetachedSct) : null;
  const chain = asRecord(embedded?.chain) || asRecord(detached?.chain);
  const certs = chain && Array.isArray(chain.certificates) ? chain.certificates : null;
  const first = certs && typeof certs[0] === 'string' ? certs[0] : '';
  if (!first) throw new KeylessError('Fulcio response did not include a certificate');
  try {
    return certificateDer(first.trim());
  } catch {
    throw new KeylessError('Fulcio certificate is not a valid X.509 certificate');
  }
}

interface RekorEntry {
  canonicalBody: Buffer;
  integratedTime: number;
  logIndex: number;
  logIdHex: string;
  setSignature: Buffer;
  inclusion: {
    logIndex: number;
    treeSize: number;
    rootHash: Buffer;
    hashes: Buffer[];
    checkpoint: string;
  };
}

function integerField(value: unknown, label: string): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' && /^-?\d+$/.test(value) ? Number(value) : NaN;
  if (!Number.isInteger(n)) throw new KeylessError(`${label} is not an integer`);
  return n;
}

function parseRekor(value: unknown): RekorEntry {
  const top = asRecord(value);
  if (!top) throw new KeylessError('Rekor response is not JSON');
  let entry = top;
  if (typeof top.body !== 'string') {
    const keys = Object.keys(top);
    if (keys.length !== 1) throw new KeylessError('Rekor response did not include one log entry');
    const nested = asRecord(top[keys[0]]);
    if (!nested) throw new KeylessError('Rekor response did not include one log entry');
    entry = nested;
  }
  if (typeof entry.body !== 'string' || !entry.body) throw new KeylessError('Rekor entry is missing body');
  const verification = asRecord(entry.verification);
  const setB64 = verification && typeof verification.signedEntryTimestamp === 'string'
    ? verification.signedEntryTimestamp
    : '';
  if (!setB64) throw new KeylessError('Rekor entry is missing a signed entry timestamp');
  const proof = verification ? asRecord(verification.inclusionProof) : null;
  if (!proof) throw new KeylessError('Rekor entry is missing an inclusion proof');
  const checkpoint = typeof proof.checkpoint === 'string' ? proof.checkpoint : '';
  if (!checkpoint) throw new KeylessError('Rekor entry is missing a checkpoint');
  const rootHex = typeof proof.rootHash === 'string' ? proof.rootHash : '';
  if (!/^[0-9a-fA-F]{64}$/.test(rootHex)) throw new KeylessError('Rekor inclusion proof root hash is not sha256');
  const hashList = Array.isArray(proof.hashes) ? proof.hashes : [];
  const hashes: Buffer[] = [];
  for (const item of hashList) {
    if (typeof item !== 'string' || !/^[0-9a-fA-F]{64}$/.test(item)) {
      throw new KeylessError('Rekor inclusion proof hash is not sha256');
    }
    hashes.push(Buffer.from(item, 'hex'));
  }
  const logId = typeof entry.logID === 'string' ? entry.logID.toLowerCase() : '';
  if (!/^[0-9a-f]{64}$/.test(logId)) throw new KeylessError('Rekor logID is not 64 hex chars');
  let canonicalBody: Buffer;
  try {
    canonicalBody = decodeBase64(entry.body);
  } catch {
    throw new KeylessError('Rekor entry body is not base64');
  }
  return {
    canonicalBody,
    integratedTime: integerField(entry.integratedTime, 'Rekor integratedTime'),
    logIndex: integerField(entry.logIndex, 'Rekor logIndex'),
    logIdHex: logId,
    setSignature: decodeBase64(setB64),
    inclusion: {
      logIndex: integerField(proof.logIndex, 'Rekor inclusion logIndex'),
      treeSize: integerField(proof.treeSize, 'Rekor inclusion treeSize'),
      rootHash: Buffer.from(rootHex, 'hex'),
      hashes,
      checkpoint,
    },
  };
}

function bodyMatches(canonicalBody: Buffer, payloadB64: string, sigB64: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonicalBody.toString('utf8'));
  } catch {
    return false;
  }
  const doc = asRecord(parsed);
  const spec = doc ? asRecord(doc.spec) : null;
  const content = spec ? asRecord(spec.content) : null;
  const envelope = content ? asRecord(content.envelope) : null;
  if (!envelope || envelope.payload !== payloadB64) return false;
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) return false;
  const sig = asRecord(envelope.signatures[0]);
  return Boolean(sig && sig.sig === sigB64);
}

function bundleDocument(
  certDer: Buffer,
  envelope: DsseEnvelope,
  entry: RekorEntry,
): Record<string, unknown> {
  return {
    mediaType: BUNDLE_MEDIA_TYPE,
    verificationMaterial: {
      certificate: { rawBytes: encodeBase64(certDer) },
      tlogEntries: [
        {
          logIndex: String(entry.logIndex),
          logId: { keyId: encodeBase64(Buffer.from(entry.logIdHex, 'hex')) },
          kindVersion: { kind: 'intoto', version: '0.0.2' },
          integratedTime: String(entry.integratedTime),
          inclusionPromise: { signedEntryTimestamp: encodeBase64(entry.setSignature) },
          inclusionProof: {
            logIndex: String(entry.inclusion.logIndex),
            treeSize: String(entry.inclusion.treeSize),
            rootHash: encodeBase64(entry.inclusion.rootHash),
            hashes: entry.inclusion.hashes.map((hash) => encodeBase64(hash)),
            checkpoint: { envelope: entry.inclusion.checkpoint },
          },
          canonicalizedBody: encodeBase64(entry.canonicalBody),
        },
      ],
    },
    dsseEnvelope: {
      payload: envelope.payload,
      payloadType: envelope.payloadType,
      signatures: [{ keyid: envelope.signatures[0]?.keyid ?? '', sig: envelope.signatures[0]?.sig ?? '' }],
    },
  };
}

/**
 * Sign `body` (the raw in-toto statement) and return a bundle. Throws
 * before any file is written. The ephemeral private key is not exported.
 */
export async function signKeyless(body: Buffer, opts: KeylessSignOptions = {}): Promise<KeylessBundleResult> {
  const env = opts.env ?? process.env;
  const timeout = timeoutMs(opts.timeoutMs, env);
  const secrets: string[] = [];
  try {
    const token = await resolveOidcToken(opts.identityTokenPath, env, timeout);
    secrets.push(token);
    const claims = decodeJwtPayload(token);
    assertFresh(claims);
    const sub = typeof claims.sub === 'string' ? claims.sub : '';
    if (!sub) throw new KeylessError('OIDC token is missing sub');
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const proof = cryptoSign('sha256', Buffer.from(sub, 'utf8'), privateKey);
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const spkiBuf = typeof spki === 'string' ? Buffer.from(spki) : spki;
    const fulcio = httpUrl(opts.fulcioUrl || DEFAULT_FULCIO_URL, '--fulcio-url');
    const rekor = httpUrl(opts.rekorUrl || DEFAULT_REKOR_URL, '--rekor-url');
    const fulcioBody = {
      credentials: { oidcIdentityToken: token },
      publicKeyRequest: {
        publicKey: { algorithm: 'ECDSA', content: encodeBase64(spkiBuf) },
        proofOfPossession: encodeBase64(proof),
      },
    };
    const issued = await postJson(new URL('/api/v2/signingCert', fulcio), fulcioBody, timeout, `Fulcio (${originOf(fulcio)})`);
    const certDer = leafFromFulcio(issued);
    const cert = new X509Certificate(certDer);
    let sameKey = false;
    try {
      sameKey = cert.publicKey.equals(publicKey);
    } catch {
      sameKey = false;
    }
    if (!sameKey) throw new KeylessError('Fulcio certificate public key does not match the ephemeral key');
    const pae = dssePae(DSSE_PAYLOAD_TYPE, body);
    const signature = cryptoSign('sha256', pae, privateKey);
    const publicPem = pemPublic(publicKey);
    const envelope: DsseEnvelope = {
      payload: encodeBase64(body),
      payloadType: DSSE_PAYLOAD_TYPE,
      signatures: [{ keyid: fingerprint(publicPem), sig: encodeBase64(signature), publicKey: publicPem }],
    };
    const sigB64 = envelope.signatures[0].sig;
    const proposed = {
      apiVersion: '0.0.2',
      kind: 'intoto',
      spec: {
        content: {
          envelope: {
            payload: envelope.payload,
            payloadType: envelope.payloadType,
            signatures: [{ sig: sigB64, publicKey: encodeBase64(certDer) }],
          },
        },
      },
    };
    const logged = await postJson(new URL('/api/v1/log/entries', rekor), proposed, timeout, `Rekor (${originOf(rekor)})`);
    const entry = parseRekor(logged);
    if (!bodyMatches(entry.canonicalBody, envelope.payload, sigB64)) {
      throw new KeylessError('Rekor entry does not match the signed envelope');
    }
    const bundle = bundleDocument(certDer, envelope, entry);
    const bundleJson = JSON.stringify(bundle);
    if (bundleJson.includes('PRIVATE KEY') || bundleJson.includes(token)) {
      throw new KeylessError('refusing to write a bundle that contains a private key or an OIDC token');
    }
    const identities = identitySans(cert);
    const issuer = fulcioIssuer(certDer) || '';
    return {
      bundle,
      bundleJson,
      envelope,
      identity: identities[0] || '',
      issuer,
      integratedTime: entry.integratedTime,
      logIndex: entry.logIndex,
    };
  } catch (err) {
    if (err instanceof KeylessError) {
      throw new KeylessError(scrub(err.message, secrets), err.exitCode);
    }
    const message = err instanceof Error ? err.message : String(err);
    throw new KeylessError(scrub(message, secrets));
  }
}

export interface ParsedBundle {
  certDer: Buffer;
  payload: Buffer;
  payloadB64: string;
  payloadType: string;
  signature: Buffer;
  sigB64: string;
  canonicalBody: Buffer;
  integratedTime: number;
  logIndex: number;
  logId: Buffer;
  setSignature: Buffer;
  proofLogIndex: bigint;
  treeSize: bigint;
  rootHash: Buffer;
  hashes: Buffer[];
  checkpoint: string;
}

function b64field(value: unknown, label: string): Buffer {
  if (typeof value !== 'string' || !value) throw new KeylessError(`${label} is missing`, 1);
  try {
    return decodeBase64(value);
  } catch {
    throw new KeylessError(`${label} is not base64`, 1);
  }
}

function bigField(value: unknown, label: string): bigint {
  const text = typeof value === 'number' ? String(value) : typeof value === 'string' ? value : '';
  if (!/^-?\d+$/.test(text)) throw new KeylessError(`${label} is not an integer`, 1);
  try {
    return BigInt(text);
  } catch {
    throw new KeylessError(`${label} is not an integer`, 1);
  }
}

export function parseBundle(value: unknown): ParsedBundle {
  const doc = asRecord(value);
  if (!doc) throw new KeylessError('Sigstore bundle must be a JSON object', 1);
  if (doc.mediaType !== BUNDLE_MEDIA_TYPE) {
    throw new KeylessError('Sigstore bundle mediaType is not v0.3', 1);
  }
  const material = asRecord(doc.verificationMaterial);
  const certificate = material ? asRecord(material.certificate) : null;
  if (!certificate) throw new KeylessError('Sigstore bundle is missing a certificate', 1);
  let certDer: Buffer;
  try {
    certDer = certificateDer(b64field(certificate.rawBytes, 'certificate'));
  } catch (err) {
    if (err instanceof KeylessError) throw err;
    throw new KeylessError('Sigstore bundle certificate is not X.509', 1);
  }
  const entries = material && Array.isArray(material.tlogEntries) ? material.tlogEntries : null;
  if (!entries || entries.length !== 1) throw new KeylessError('Sigstore bundle must contain one transparency log entry', 1);
  const entry = asRecord(entries[0]);
  if (!entry) throw new KeylessError('Sigstore bundle log entry is not an object', 1);
  const logIdDoc = asRecord(entry.logId);
  const logId = b64field(logIdDoc?.keyId, 'log id');
  const promise = asRecord(entry.inclusionPromise);
  const proof = asRecord(entry.inclusionProof);
  if (!promise || !proof) throw new KeylessError('Sigstore bundle is missing a Rekor proof', 1);
  const checkpointDoc = asRecord(proof.checkpoint);
  const checkpoint = checkpointDoc && typeof checkpointDoc.envelope === 'string' ? checkpointDoc.envelope : '';
  if (!checkpoint) throw new KeylessError('Sigstore bundle is missing a Rekor checkpoint', 1);
  const hashList = Array.isArray(proof.hashes) ? proof.hashes : null;
  if (!hashList) throw new KeylessError('Sigstore bundle inclusion proof hashes are missing', 1);
  const dsse = asRecord(doc.dsseEnvelope);
  if (!dsse) throw new KeylessError('Sigstore bundle is missing a DSSE envelope', 1);
  if (dsse.payloadType !== DSSE_PAYLOAD_TYPE) throw new KeylessError('Sigstore bundle payloadType is not in-toto', 2);
  if (!Array.isArray(dsse.signatures) || dsse.signatures.length !== 1) {
    throw new KeylessError('Sigstore bundle DSSE envelope must have one signature', 1);
  }
  const sig = asRecord(dsse.signatures[0]);
  const payloadB64 = typeof dsse.payload === 'string' ? dsse.payload : '';
  const sigB64 = sig && typeof sig.sig === 'string' ? sig.sig : '';
  return {
    certDer,
    payload: b64field(payloadB64, 'DSSE payload'),
    payloadB64,
    payloadType: DSSE_PAYLOAD_TYPE,
    signature: b64field(sigB64, 'DSSE signature'),
    sigB64,
    canonicalBody: b64field(entry.canonicalizedBody, 'canonicalized body'),
    integratedTime: Number(bigField(entry.integratedTime, 'integrated time')),
    logIndex: Number(bigField(entry.logIndex, 'log index')),
    logId,
    setSignature: b64field(promise.signedEntryTimestamp, 'signed entry timestamp'),
    proofLogIndex: bigField(proof.logIndex, 'inclusion log index'),
    treeSize: bigField(proof.treeSize, 'inclusion tree size'),
    rootHash: b64field(proof.rootHash, 'inclusion root hash'),
    hashes: hashList.map((item, index) => b64field(item, `inclusion hash ${index + 1}`)),
    checkpoint,
  };
}

export function isSigstoreBundle(value: unknown): boolean {
  const doc = asRecord(value);
  return Boolean(doc && typeof doc.mediaType === 'string' && doc.mediaType.includes('sigstore.bundle'));
}

export interface IdentityPolicy {
  identity?: string;
  identityRegexp?: string;
  issuer: string;
}

function deny(reason: string, exitCode: 1 | 2 = 2): KeylessVerifyFailure {
  return { ok: false, reason, exitCode };
}

function matchIdentity(
  sans: string[],
  policy: IdentityPolicy,
): { ok: true; identity: string } | KeylessVerifyFailure {
  if (!policy.issuer) return deny('certificate OIDC issuer is required', 1);
  const exact = policy.identity !== undefined;
  const regexp = policy.identityRegexp !== undefined;
  if (exact === regexp) {
    return deny('exactly one of certificate identity or certificate identity regexp is required', 1);
  }
  if (!sans.length) return deny('certificate has no email or URI SAN');
  if (exact) {
    const found = sans.find((value) => value === policy.identity);
    if (!found) return deny('certificate identity does not match');
    return { ok: true, identity: found };
  }
  const pattern = policy.identityRegexp || '';
  if (pattern.length > 512) return deny('certificate identity regexp is too long', 1);
  let re: RegExp;
  try {
    re = new RegExp(`^(?:${pattern})$`);
  } catch {
    return deny('certificate identity regexp is invalid', 1);
  }
  const found = sans.find((value) => re.test(value));
  if (!found) return deny('certificate identity does not match');
  return { ok: true, identity: found };
}

function logFor(root: TrustedRoot, logId: Buffer): TrustedLog | null {
  return root.logs.find((log) => log.logId.equals(logId)) ?? null;
}

export interface KeylessVerifyResult {
  ok: true;
  identity: string;
  issuer: string;
  integratedTime: number;
  logIndex: number;
  payload: Buffer;
}

export interface KeylessVerifyFailure {
  ok: false;
  reason: string;
  exitCode: 1 | 2;
}

/**
 * Offline checks: chain, SAN, issuer extension, certificate validity at
 * the Rekor integrated time, DSSE PAE, SET, checkpoint, and inclusion.
 * Statement subject checks stay with the caller.
 */
export function verifyKeylessBundle(
  value: unknown,
  policy: IdentityPolicy,
  root: TrustedRoot,
): KeylessVerifyResult | KeylessVerifyFailure {
  let bundle: ParsedBundle;
  try {
    bundle = parseBundle(value);
  } catch (err) {
    if (err instanceof KeylessError) return deny(err.message, err.exitCode);
    const message = err instanceof Error ? err.message : String(err);
    return deny(message, 1);
  }
  const chain = chainToTrustedRoot(bundle.certDer, root.cas);
  if (!chain.ok) return deny(chain.reason);
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(bundle.certDer);
  } catch {
    return deny('signing certificate is not a valid X.509 certificate');
  }
  const issuer = fulcioIssuer(bundle.certDer);
  if (!issuer) return deny('certificate has no OIDC issuer extension');
  if (issuer !== policy.issuer) return deny('certificate OIDC issuer does not match');
  const identity = matchIdentity(identitySans(cert), policy);
  if (!identity.ok) return identity;
  const log = logFor(root, bundle.logId);
  if (!log) return deny('Rekor log id is not in the trusted root');
  if (bundle.proofLogIndex !== BigInt(bundle.logIndex)) {
    return deny('Rekor inclusion proof index does not match the log entry');
  }
  if (!verifyEntryTimestamp(
    log.publicKey,
    bundle.setSignature,
    bundle.canonicalBody,
    bundle.integratedTime,
    bundle.logIndex,
    bundle.logId,
  )) {
    return deny('Rekor signed entry timestamp does not verify');
  }
  const checkpoint = verifyCheckpoint(bundle.checkpoint, bundle.rootHash, bundle.treeSize, [log]);
  if (!checkpoint.ok) return deny(checkpoint.reason);
  const merkle = rootFromInclusion(bundle.canonicalBody, bundle.proofLogIndex, bundle.treeSize, bundle.hashes);
  if (!merkle.ok) return deny(merkle.reason);
  if (!merkle.root.equals(bundle.rootHash)) {
    return deny('Rekor inclusion proof does not match the checkpoint root');
  }
  for (const hop of chain.path) {
    if (!validAt(hop, bundle.integratedTime)) {
      return deny('certificate was not valid at the Rekor integrated time');
    }
  }
  if (!bodyMatches(bundle.canonicalBody, bundle.payloadB64, bundle.sigB64)) {
    return deny('Rekor entry does not match the DSSE envelope');
  }
  let signed = false;
  try {
    signed = cryptoVerify('sha256', dssePae(bundle.payloadType, bundle.payload), cert.publicKey, bundle.signature);
  } catch {
    signed = false;
  }
  if (!signed) return deny('DSSE signature does not verify');
  return {
    ok: true,
    identity: identity.identity,
    issuer,
    integratedTime: bundle.integratedTime,
    logIndex: bundle.logIndex,
    payload: bundle.payload,
  };
}

export function verifyKeylessFile(
  value: unknown,
  policy: IdentityPolicy,
  trustedRootPath: string | undefined,
): KeylessVerifyResult | KeylessVerifyFailure {
  let root: TrustedRoot;
  try {
    root = loadTrustedRoot(trustedRootPath);
  } catch (err) {
    if (err instanceof TrustedRootError) return deny(err.message, 1);
    const message = err instanceof Error ? err.message : String(err);
    return deny(message, 1);
  }
  return verifyKeylessBundle(value, policy, root);
}

export { buildCheckpoint, logIdForKey, signEntryTimestamp };
