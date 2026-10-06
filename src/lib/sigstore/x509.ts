/**
 * X.509 chain check and the small certificate builder the tests use as a
 * Fulcio stand-in. Verification uses Node's X509Certificate. The builder
 * exists so tests never call the public Fulcio service.
 *
 * Fulcio's OIDC issuer is extension 1.3.6.1.4.1.57264.1.1. The value is a
 * UTF8String inside the extension octet string. Identity is the email or
 * URI subjectAltName, not the common name.
 */
import { createHash, randomBytes, sign as cryptoSign, X509Certificate, type KeyObject } from 'node:crypto';
import {
  bitString,
  boolTrue,
  derChildren,
  derTag,
  encodeOid,
  integer,
  oid,
  parseDer,
  seq,
  utcTime,
  utf8,
} from './der.js';

const ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
const OID_CN = '2.5.4.3';
const OID_BASIC = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_SAN = '2.5.29.17';
/** Fulcio issuer v2. https://docs.sigstore.dev/certificate_authority/certificate-specification/ */
export const OID_FULCIO_ISSUER = '1.3.6.1.4.1.57264.1.1';

const ALG_ECDSA_SHA256 = seq([oid(ECDSA_WITH_SHA256)]);

export interface CertSpec {
  subjectCn: string;
  issuerCn: string;
  publicKey: KeyObject;
  /** Private key that signs the TBS. The root passes its own key. */
  signer: KeyObject;
  notBefore: Date;
  notAfter: Date;
  isCa: boolean;
  sanUri?: string;
  sanEmail?: string;
  /** OIDC issuer URL placed in the Fulcio issuer extension. Leaf certs only. */
  oidcIssuer?: string;
}

function spkiDer(key: KeyObject): Buffer {
  const exported = key.export({ type: 'spki', format: 'der' });
  return typeof exported === 'string' ? Buffer.from(exported) : exported;
}

function name(cn: string): Buffer {
  const atv = seq([oid(OID_CN), utf8(cn)]);
  return seq([derTag(0x31, atv)]);
}

function extension(oidDotted: string, critical: boolean, value: Buffer): Buffer {
  const parts = [oid(oidDotted)];
  if (critical) parts.push(boolTrue());
  parts.push(derTag(0x04, value));
  return seq(parts);
}

function keyUsage(ca: boolean): Buffer {
  // BIT STRING. CA: keyCertSign (bit 5) and cRLSign (bit 6) → 0x06, one unused bit.
  // Leaf: digitalSignature (bit 0) → 0x80, seven unused bits.
  const body = ca ? Buffer.from([0x01, 0x06]) : Buffer.from([0x07, 0x80]);
  return derTag(0x03, body);
}

/** Issue one certificate. The private key is the caller's; this function does not keep it. */
export function buildCertificate(spec: CertSpec): Buffer {
  if (spec.notAfter.getTime() <= spec.notBefore.getTime()) {
    throw new Error('certificate notAfter must be after notBefore');
  }
  if (spec.notAfter.getUTCFullYear() >= 2050 || spec.notBefore.getUTCFullYear() < 2000) {
    throw new Error('certificate builder only emits UTCTime years 2000-2049');
  }
  const extensions = [
    extension(OID_BASIC, true, spec.isCa ? seq([boolTrue()]) : seq([])),
    extension(OID_KEY_USAGE, true, keyUsage(spec.isCa)),
  ];
  if (spec.sanEmail || spec.sanUri) {
    const names: Buffer[] = [];
    if (spec.sanEmail) names.push(derTag(0x81, Buffer.from(spec.sanEmail, 'ascii')));
    if (spec.sanUri) names.push(derTag(0x86, Buffer.from(spec.sanUri, 'ascii')));
    extensions.push(extension(OID_SAN, false, seq(names)));
  }
  if (spec.oidcIssuer) {
    extensions.push(extension(OID_FULCIO_ISSUER, false, utf8(spec.oidcIssuer)));
  }
  const serial = randomBytes(16);
  serial[0] &= 0x7f;
  if (serial[0] === 0) serial[0] = 1;
  const tbs = seq([
    derTag(0xa0, integer(Buffer.from([0x02]))),
    integer(serial),
    ALG_ECDSA_SHA256,
    name(spec.issuerCn),
    seq([utcTime(spec.notBefore), utcTime(spec.notAfter)]),
    name(spec.subjectCn),
    spkiDer(spec.publicKey),
    derTag(0xa3, seq(extensions)),
  ]);
  const signature = cryptoSign('sha256', tbs, spec.signer);
  return seq([tbs, ALG_ECDSA_SHA256, bitString(signature)]);
}

export function extensionOctets(certDer: Buffer, oidDotted: string): Buffer | null {
  const want = encodeOid(oidDotted);
  const top = parseDer(certDer, 0).node;
  if (top.tag !== 0x30) return null;
  const tbs = derChildren(top.value)[0];
  if (!tbs || tbs.tag !== 0x30) return null;
  const wrap = derChildren(tbs.value).find((node) => node.tag === 0xa3);
  if (!wrap) return null;
  const extSeq = derChildren(wrap.value)[0];
  if (!extSeq || extSeq.tag !== 0x30) return null;
  for (const ext of derChildren(extSeq.value)) {
    if (ext.tag !== 0x30) continue;
    const parts = derChildren(ext.value);
    const id = parts[0];
    if (!id || id.tag !== 0x06 || !id.value.equals(want)) continue;
    const octets = parts.find((part) => part.tag === 0x04);
    return octets ? Buffer.from(octets.value) : null;
  }
  return null;
}

/** Decode a Fulcio string extension. UTF8String, IA5String, or raw UTF-8. */
export function derText(value: Buffer): string {
  try {
    const parsed = parseDer(value, 0).node;
    if (parsed.tag === 0x0c || parsed.tag === 0x16 || parsed.tag === 0x13) {
      return parsed.value.toString('utf8');
    }
  } catch {
    /* treat the octets as text */
  }
  return value.toString('utf8');
}

export function fulcioIssuer(certDer: Buffer): string | null {
  const raw = extensionOctets(certDer, OID_FULCIO_ISSUER);
  if (!raw) return null;
  const text = derText(raw).replace(/\0/g, '').trim();
  return text || null;
}

export function certificateDer(value: string | Buffer): Buffer {
  const buf = typeof value === 'string' ? Buffer.from(value) : value;
  const text = buf.toString('utf8');
  if (text.includes('BEGIN CERTIFICATE')) return new X509Certificate(text).raw;
  return new X509Certificate(buf).raw;
}

export interface ChainOk {
  ok: true;
  /** Leaf first, trust anchor last. */
  path: X509Certificate[];
}

export function chainToTrustedRoot(
  leafDer: Buffer,
  authorities: Buffer[][],
): ChainOk | { ok: false; reason: string } {
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(leafDer);
  } catch {
    return { ok: false, reason: 'signing certificate is not a valid X.509 certificate' };
  }
  const pool: X509Certificate[] = [];
  for (const chain of authorities) {
    for (const der of chain) {
      try {
        pool.push(new X509Certificate(der));
      } catch {
        return { ok: false, reason: 'trusted root contains a certificate that is not X.509' };
      }
    }
  }
  if (!pool.length) return { ok: false, reason: 'trusted root has no certificate authorities' };
  const trusted = new Set(pool.map((cert) => cert.fingerprint256));
  const path = [leaf];
  let current = leaf;
  for (let hop = 0; hop < 6; hop += 1) {
    if (issuedBy(current, current) && trusted.has(current.fingerprint256)) {
      return { ok: true, path };
    }
    const issuers = pool.filter((parent) => parent.fingerprint256 !== current.fingerprint256 && issuedBy(current, parent));
    if (issuers.length !== 1) break;
    current = issuers[0];
    if (path.some((cert) => cert.fingerprint256 === current.fingerprint256)) break;
    path.push(current);
  }
  return { ok: false, reason: 'certificate does not chain to a trusted root' };
}

function issuedBy(child: X509Certificate, parent: X509Certificate): boolean {
  if (child.issuer !== parent.subject) return false;
  try {
    return child.verify(parent.publicKey);
  } catch {
    return false;
  }
}

/** Inclusive X.509 window. `unixSeconds` is the Rekor integrated time. */
export function validAt(cert: X509Certificate, unixSeconds: number): boolean {
  if (!Number.isFinite(unixSeconds)) return false;
  const at = unixSeconds * 1000;
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  return Number.isFinite(from) && Number.isFinite(to) && at >= from && at <= to;
}

/**
 * Email and URI SANs. Node prints `email:user@host, URI:https://…`.
 * Other name types are ignored. A URI is taken after the first colon.
 */
export function identitySans(cert: X509Certificate): string[] {
  const raw = cert.subjectAltName || '';
  if (!raw) return [];
  const parts = raw.split(/, (?=(?:DNS|URI|email|IP Address|Registered ID|othername):)/);
  const out: string[] = [];
  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx < 0) continue;
    const type = part.slice(0, idx);
    const value = part.slice(idx + 1);
    if ((type === 'email' || type === 'URI') && value) out.push(value);
  }
  return out;
}

export function spkiSha256(key: KeyObject): Buffer {
  return createHash('sha256').update(spkiDer(key)).digest();
}
