/**
 * Sigstore trusted_root.json (application/vnd.dev.sigstore.trustedroot+json).
 * The default root is the embedded public-good Fulcio chain and Rekor key.
 * A file passed to `--trusted-root` replaces that set entirely.
 */
import { readFileSync } from 'node:fs';
import { X509Certificate, createPublicKey, type KeyObject } from 'node:crypto';
import { decodeBase64 } from '../dsse.js';
import { FULCIO_INTERMEDIATE_PEM, FULCIO_ROOT_PEM, REKOR_PUBLIC_KEY_PEM } from './public-good.js';
import { logIdForKey, publicKeyFromMaterial } from './tlog.js';

export interface TrustedLog {
  baseUrl: string;
  publicKey: KeyObject;
  logId: Buffer;
}

export interface TrustedRoot {
  cas: Buffer[][];
  logs: TrustedLog[];
}

export class TrustedRootError extends Error {
  readonly exitCode = 1 as const;
  constructor(message: string) {
    super(message);
    this.name = 'TrustedRootError';
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function rawBytes(value: unknown, label: string): Buffer {
  const doc = asRecord(value);
  const raw = doc && typeof doc.rawBytes === 'string' ? doc.rawBytes : '';
  if (!raw) throw new TrustedRootError(`${label} is missing rawBytes`);
  try {
    return decodeBase64(raw);
  } catch {
    throw new TrustedRootError(`${label} rawBytes is not base64`);
  }
}

export function parseTrustedRoot(value: unknown): TrustedRoot {
  const doc = asRecord(value);
  if (!doc) throw new TrustedRootError('trusted root must be a JSON object');
  if (typeof doc.mediaType === 'string' && doc.mediaType && !doc.mediaType.includes('trustedroot')) {
    throw new TrustedRootError(`unsupported trusted root mediaType: ${doc.mediaType}`);
  }
  if (!Array.isArray(doc.certificateAuthorities) || doc.certificateAuthorities.length === 0) {
    throw new TrustedRootError('trusted root is missing certificateAuthorities');
  }
  const cas: Buffer[][] = [];
  for (const item of doc.certificateAuthorities) {
    const ca = asRecord(item);
    const chain = ca ? asRecord(ca.certChain) : null;
    const certs = chain && Array.isArray(chain.certificates) ? chain.certificates : null;
    if (!certs || !certs.length) throw new TrustedRootError('trusted root certificate authority has no certChain');
    const ders: Buffer[] = [];
    for (const cert of certs) {
      const der = rawBytes(cert, 'trusted root certificate');
      try {
        ders.push(new X509Certificate(der).raw);
      } catch {
        throw new TrustedRootError('trusted root contains a certificate that is not X.509');
      }
    }
    cas.push(ders);
  }
  if (!Array.isArray(doc.tlogs) || doc.tlogs.length === 0) {
    throw new TrustedRootError('trusted root is missing tlogs');
  }
  const logs: TrustedLog[] = [];
  for (const item of doc.tlogs) {
    const log = asRecord(item);
    if (!log) throw new TrustedRootError('trusted root tlog must be an object');
    const baseUrl = typeof log.baseUrl === 'string' ? log.baseUrl : '';
    if (!baseUrl) throw new TrustedRootError('trusted root tlog is missing baseUrl');
    let publicKey: KeyObject;
    try {
      publicKey = publicKeyFromMaterial(rawBytes(log.publicKey, 'trusted root tlog public key'));
    } catch (err) {
      if (err instanceof TrustedRootError) throw err;
      throw new TrustedRootError('trusted root tlog public key is not a valid key');
    }
    const computed = logIdForKey(publicKey);
    const logIdDoc = asRecord(log.logId);
    let logId = computed;
    if (logIdDoc && typeof logIdDoc.keyId === 'string' && logIdDoc.keyId) {
      try {
        logId = decodeBase64(logIdDoc.keyId);
      } catch {
        throw new TrustedRootError('trusted root tlog logId is not base64');
      }
      if (!logId.equals(computed)) {
        throw new TrustedRootError('trusted root tlog logId does not match the public key');
      }
    }
    logs.push({ baseUrl, publicKey, logId });
  }
  return { cas, logs };
}

export function loadTrustedRoot(filePath: string | undefined): TrustedRoot {
  if (!filePath) return defaultTrustedRoot();
  let text: string;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch {
    throw new TrustedRootError(`trusted root not found: ${filePath}`);
  }
  try {
    return parseTrustedRoot(JSON.parse(text));
  } catch (err) {
    if (err instanceof TrustedRootError) throw err;
    throw new TrustedRootError('trusted root is not JSON');
  }
}

export function defaultTrustedRoot(): TrustedRoot {
  const intermediate = new X509Certificate(FULCIO_INTERMEDIATE_PEM);
  const root = new X509Certificate(FULCIO_ROOT_PEM);
  const publicKey = createPublicKey(REKOR_PUBLIC_KEY_PEM);
  return {
    cas: [[intermediate.raw, root.raw]],
    logs: [
      {
        baseUrl: 'https://rekor.sigstore.dev',
        publicKey,
        logId: logIdForKey(publicKey),
      },
    ],
  };
}
