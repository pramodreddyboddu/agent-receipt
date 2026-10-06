/**
 * DSSE JSON envelope (spec 1.0.2) for in-toto Statement payloads.
 *
 * PAE is `DSSEv1 <len(type)> <type> <len(body)> <body>`. Lengths are the
 * ASCII decimal byte counts with no leading zeros. The signature is raw
 * Ed25519 over those PAE bytes, not over the receipt sha256 hex.
 *
 * Known vector (protocol.md): payloadType `http://example.com/HelloWorld`
 * and body `hello world` encode as
 * `DSSEv1 29 http://example.com/HelloWorld 11 hello world`.
 *
 * The private key never enters the envelope. `publicKey` is an extra
 * signature field (SPKI PEM). DSSE consumers ignore unrecognized fields.
 * `keyid` is the same fingerprint `sign` writes. It is a hint; verify
 * checks the key that actually validates the PAE.
 */
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { fingerprint, type LoadedKeys } from './sign.js';

/** in-toto statement payload type. Lowercase media type, per DSSE. */
export const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

const PAYLOAD_TYPE_RE = /^[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,200}\/[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,200}$/;

export interface DsseSignature {
  keyid: string;
  sig: string;
  /** SPKI PEM. Absent on an unsigned envelope. Never a private key. */
  publicKey?: string;
}

export interface DsseEnvelope {
  payload: string;
  payloadType: string;
  signatures: DsseSignature[];
}

export class DsseError extends Error {
  readonly exitCode: 1 | 2;
  constructor(message: string, exitCode: 1 | 2) {
    super(message);
    this.name = 'DsseError';
    this.exitCode = exitCode;
  }
}

/** Pre-Authentication Encoding. `body` is the raw payload, not base64. */
export function dssePae(payloadType: string, body: Buffer): Buffer {
  const typeBytes = Buffer.from(payloadType, 'utf8');
  const prefix = `DSSEv1 ${typeBytes.length} ${payloadType} ${body.length} `;
  return Buffer.concat([Buffer.from(prefix, 'utf8'), body]);
}

/** Standard base64, no newlines. Verifiers also accept URL-safe. */
export function encodeBase64(bytes: Buffer): string {
  return bytes.toString('base64');
}

/** Standard or URL-safe base64. Empty input is an empty buffer. */
export function decodeBase64(value: string): Buffer {
  const trimmed = value.replace(/\s+/g, '');
  if (!trimmed) return Buffer.alloc(0);
  const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, 'base64');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

/** One compact JSON object. Key order matches the DSSE example. */
export function envelopeJson(envelope: DsseEnvelope): string {
  const signatures = envelope.signatures.map((sig) => {
    const row: Record<string, string> = { keyid: sig.keyid, sig: sig.sig };
    if (sig.publicKey) row.publicKey = sig.publicKey;
    return row;
  });
  return JSON.stringify({
    payload: envelope.payload,
    payloadType: envelope.payloadType,
    signatures,
  });
}

export function signEnvelope(body: Buffer, keys: LoadedKeys): DsseEnvelope {
  if (keys.publicKeyPem.includes('PRIVATE KEY')) {
    throw new DsseError('refusing to sign with a public key that contains a private key', 1);
  }
  const pae = dssePae(DSSE_PAYLOAD_TYPE, body);
  const sig = cryptoSign(null, pae, createPrivateKey(keys.privateKeyPem));
  const envelope: DsseEnvelope = {
    payload: encodeBase64(body),
    payloadType: DSSE_PAYLOAD_TYPE,
    signatures: [
      {
        keyid: keys.fingerprint,
        sig: encodeBase64(sig),
        publicKey: keys.publicKeyPem.trim(),
      },
    ],
  };
  const line = envelopeJson(envelope);
  if (line.includes('PRIVATE KEY')) {
    throw new DsseError('refusing to write an attestation that contains a private key', 1);
  }
  return envelope;
}

export function unsignedEnvelope(body: Buffer): DsseEnvelope {
  return {
    payload: encodeBase64(body),
    payloadType: DSSE_PAYLOAD_TYPE,
    signatures: [],
  };
}

export interface ParsedEnvelope {
  envelope: DsseEnvelope;
  /** Exact payload bytes that were base64-decoded. Callers must parse these. */
  body: Buffer;
}

/**
 * Decode one envelope object. Does not verify the signature.
 * Malformed JSON shape is exit 1. A wrong payloadType is exit 2.
 */
export function parseEnvelope(value: unknown): ParsedEnvelope {
  const doc = asRecord(value);
  if (!doc) throw new DsseError('DSSE envelope must be a JSON object', 1);
  if (typeof doc.payloadType !== 'string' || !doc.payloadType) {
    throw new DsseError('DSSE envelope payloadType is missing', 1);
  }
  if (!PAYLOAD_TYPE_RE.test(doc.payloadType)) {
    throw new DsseError('DSSE envelope payloadType is not a media type', 1);
  }
  if (typeof doc.payload !== 'string' || !doc.payload) {
    throw new DsseError('DSSE envelope payload is missing', 1);
  }
  if (!Array.isArray(doc.signatures)) {
    throw new DsseError('DSSE envelope signatures must be an array', 1);
  }
  const signatures: DsseSignature[] = [];
  for (const item of doc.signatures) {
    const sig = asRecord(item);
    if (!sig) throw new DsseError('DSSE signature must be an object', 1);
    if (typeof sig.sig !== 'string' || !sig.sig) {
      throw new DsseError('DSSE signature sig is missing', 1);
    }
    const keyid = typeof sig.keyid === 'string' ? sig.keyid : '';
    const publicKey = typeof sig.publicKey === 'string' ? sig.publicKey : undefined;
    if (publicKey && publicKey.includes('PRIVATE KEY')) {
      throw new DsseError('DSSE signature must not contain a private key', 2);
    }
    signatures.push({ keyid, sig: sig.sig, ...(publicKey ? { publicKey } : {}) });
  }
  let body: Buffer;
  try {
    body = decodeBase64(doc.payload);
  } catch {
    throw new DsseError('DSSE payload is not base64', 1);
  }
  if (encodeBase64(body) !== doc.payload.replace(/\s+/g, '') &&
      encodeBase64(body).replace(/=+$/, '') !== doc.payload.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '')) {
    throw new DsseError('DSSE payload is not valid base64', 1);
  }
  if (doc.payloadType !== DSSE_PAYLOAD_TYPE) {
    throw new DsseError(
      `unsupported DSSE payloadType: ${doc.payloadType}`,
      2,
    );
  }
  return {
    envelope: { payload: doc.payload, payloadType: doc.payloadType, signatures },
    body,
  };
}

export interface SignatureCheck {
  ok: boolean;
  /** Fingerprint of the key that verified, when one did. */
  fingerprint: string | null;
  publicKey: string | null;
  reason: string | null;
}

/**
 * Verify every signature over the PAE of `body`. An empty list fails closed
 * (`unsigned envelope`). A bad signature fails closed. `resolveKey` returns
 * the SPKI PEM for a signature, or null when this process has no key for it.
 */
export function verifyEnvelopeSignatures(
  envelope: DsseEnvelope,
  body: Buffer,
  resolveKey: (sig: DsseSignature) => string | null,
): SignatureCheck {
  if (!envelope.signatures.length) {
    return { ok: false, fingerprint: null, publicKey: null, reason: 'unsigned envelope' };
  }
  let fingerprintHex: string | null = null;
  let publicKey: string | null = null;
  for (const sig of envelope.signatures) {
    const pem = resolveKey(sig);
    if (!pem) {
      return {
        ok: false,
        fingerprint: null,
        publicKey: null,
        reason: sig.keyid
          ? `no public key for signature keyid ${sig.keyid}`
          : 'no public key for signature',
      };
    }
    if (pem.includes('PRIVATE KEY')) {
      return { ok: false, fingerprint: null, publicKey: null, reason: 'public key material contains a private key' };
    }
    let derived: string;
    try {
      derived = fingerprint(pem);
    } catch {
      return { ok: false, fingerprint: null, publicKey: null, reason: 'signature public key is not a valid SPKI key' };
    }
    if (sig.keyid && sig.keyid.toLowerCase() !== derived) {
      return {
        ok: false,
        fingerprint: derived,
        publicKey: pem,
        reason: 'public key does not match keyid',
      };
    }
    const sigBuf = decodeBase64(sig.sig);
    if (sigBuf.length !== 64) {
      const ecdsa = sigBuf.length > 0 && sigBuf[0] === 0x30;
      return {
        ok: false,
        fingerprint: derived,
        publicKey: pem,
        reason: ecdsa
          ? 'DSSE signature is not a 64-byte Ed25519 signature. Verify the Sigstore bundle (.sigstore.json) with attest --verify, --certificate-identity, and --certificate-oidc-issuer.'
          : 'DSSE signature is not 64 bytes',
      };
    }
    let ok = false;
    try {
      ok = cryptoVerify(null, dssePae(envelope.payloadType, body), createPublicKey(pem), sigBuf);
    } catch {
      ok = false;
    }
    if (!ok) {
      return {
        ok: false,
        fingerprint: derived,
        publicKey: pem,
        reason: 'DSSE signature does not verify',
      };
    }
    fingerprintHex = derived;
    publicKey = pem;
  }
  return { ok: true, fingerprint: fingerprintHex, publicKey, reason: null };
}
