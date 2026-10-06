/**
 * Rekor signed entry timestamp, RFC 6962 inclusion, and a signed checkpoint.
 * The SET payload is the canonical JSON object Rekor signs: body,
 * integratedTime, logID, logIndex. body is standard base64 of the
 * canonicalized entry. logID is lowercase hex of the log's key id.
 *
 * Checkpoint notes follow the transparency.dev signed-note format. The
 * signature name must be a literal substring of the trusted log base URL.
 */
import {
  createHash,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export function sha256(...parts: Buffer[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function logIdForKey(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const buf = typeof der === 'string' ? Buffer.from(der) : der;
  return sha256(buf);
}

/** RFC 6962 leaf hash of the canonicalized Rekor body. */
export function leafHash(canonicalBody: Buffer): Buffer {
  return sha256(LEAF_PREFIX, canonicalBody);
}

function hashChildren(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

function bitLength(n: bigint): number {
  if (n === 0n) return 0;
  return n.toString(2).length;
}

function onesCount(n: bigint): number {
  return n.toString(2).split('1').length - 1;
}

/**
 * Rebuild the Merkle root for one inclusion proof.
 * `hashes` are the proof nodes from leaf toward the root, not including either.
 */
export function rootFromInclusion(
  canonicalBody: Buffer,
  logIndex: bigint,
  treeSize: bigint,
  hashes: Buffer[],
): { ok: true; root: Buffer } | { ok: false; reason: string } {
  if (logIndex < 0n || treeSize <= 0n || logIndex >= treeSize) {
    return { ok: false, reason: 'Rekor inclusion proof index is outside the tree' };
  }
  if (hashes.length > 64) return { ok: false, reason: 'Rekor inclusion proof is too long' };
  const inner = bitLength(logIndex ^ (treeSize - 1n));
  const border = onesCount(logIndex >> BigInt(inner));
  if (hashes.length !== inner + border) {
    return { ok: false, reason: 'Rekor inclusion proof hash count does not match the tree' };
  }
  let acc = leafHash(canonicalBody);
  for (let i = 0; i < inner; i += 1) {
    const sibling = hashes[i];
    if (sibling.length !== 32) return { ok: false, reason: 'Rekor inclusion proof hash is not 32 bytes' };
    acc = ((logIndex >> BigInt(i)) & 1n) === 1n ? hashChildren(sibling, acc) : hashChildren(acc, sibling);
  }
  for (let i = inner; i < hashes.length; i += 1) {
    const sibling = hashes[i];
    if (sibling.length !== 32) return { ok: false, reason: 'Rekor inclusion proof hash is not 32 bytes' };
    acc = hashChildren(sibling, acc);
  }
  return { ok: true, root: acc };
}

export interface CheckpointNote {
  origin: string;
  treeSize: bigint;
  rootHash: Buffer;
}

/**
 * Signed checkpoint. `origin` is both the first line and the signature
 * name, so the trusted root base URL must contain it.
 */
export function buildCheckpoint(
  origin: string,
  treeSize: number,
  rootHash: Buffer,
  logId: Buffer,
  privateKey: KeyObject,
): string {
  if (!origin || /[\r\n]/.test(origin)) throw new Error('checkpoint origin must be one line');
  const note = `${origin}\n${treeSize}\n${rootHash.toString('base64')}\n`;
  const signature = cryptoSign('sha256', Buffer.from(note, 'utf8'), privateKey);
  const blob = Buffer.concat([logId.subarray(0, 4), signature]).toString('base64');
  return `${note}\n\u2014 ${origin} ${blob}\n`;
}

export function verifyCheckpoint(
  envelope: string,
  expectedRoot: Buffer,
  expectedSize: bigint,
  logs: Array<{ baseUrl: string; publicKey: KeyObject; logId: Buffer }>,
): { ok: true; origin: string } | { ok: false; reason: string } {
  if (envelope.length > 65536) return { ok: false, reason: 'Rekor checkpoint is too large' };
  const split = envelope.indexOf('\n\n');
  if (split < 0) return { ok: false, reason: 'Rekor checkpoint is missing its signature' };
  const note = envelope.slice(0, split + 1);
  const signatures = envelope.slice(split + 2);
  const lines = note.replace(/\n$/, '').split('\n');
  if (lines.length < 3) return { ok: false, reason: 'Rekor checkpoint is missing the tree head' };
  const origin = lines[0];
  if (!/^\d+$/.test(lines[1])) return { ok: false, reason: 'Rekor checkpoint size is not an integer' };
  let treeSize: bigint;
  try {
    treeSize = BigInt(lines[1]);
  } catch {
    return { ok: false, reason: 'Rekor checkpoint size is not an integer' };
  }
  const rootHash = Buffer.from(lines[2], 'base64');
  if (treeSize !== expectedSize) return { ok: false, reason: 'Rekor checkpoint size does not match the inclusion proof' };
  if (rootHash.length !== expectedRoot.length || !rootHash.equals(expectedRoot)) {
    return { ok: false, reason: 'Rekor checkpoint root hash does not match the inclusion proof' };
  }
  const matches = signatures.matchAll(/\u2014 (\S+) (\S+)\n/g);
  const data = Buffer.from(note, 'utf8');
  for (const match of matches) {
    const name = match[1];
    const raw = Buffer.from(match[2], 'base64');
    if (raw.length < 5) continue;
    const hint = raw.subarray(0, 4);
    const sig = raw.subarray(4);
    const log = logs.find(
      (item) => item.logId.subarray(0, 4).equals(hint) && item.baseUrl.includes(name),
    );
    if (!log) continue;
    try {
      if (cryptoVerify('sha256', data, log.publicKey, sig)) return { ok: true, origin };
    } catch {
      /* try the next signature */
    }
  }
  return { ok: false, reason: 'Rekor checkpoint signature does not verify' };
}

/** Canonical JSON for the four SET fields. Key order is alphabetical. */
export function setPayload(bodyB64: string, integratedTime: number, logIndex: number, logIdHex: string): string {
  return JSON.stringify({
    body: bodyB64,
    integratedTime,
    logID: logIdHex,
    logIndex,
  });
}

export function signEntryTimestamp(
  privateKey: KeyObject,
  canonicalBody: Buffer,
  integratedTime: number,
  logIndex: number,
  logId: Buffer,
): Buffer {
  const payload = setPayload(canonicalBody.toString('base64'), integratedTime, logIndex, logId.toString('hex'));
  return cryptoSign('sha256', Buffer.from(payload, 'utf8'), privateKey);
}

export function verifyEntryTimestamp(
  publicKey: KeyObject,
  signature: Buffer,
  canonicalBody: Buffer,
  integratedTime: number,
  logIndex: number,
  logId: Buffer,
): boolean {
  const payload = setPayload(canonicalBody.toString('base64'), integratedTime, logIndex, logId.toString('hex'));
  try {
    return cryptoVerify('sha256', Buffer.from(payload, 'utf8'), publicKey, signature);
  } catch {
    return false;
  }
}

export function publicKeyFromMaterial(raw: Buffer): KeyObject {
  const asText = raw.toString('utf8');
  if (asText.includes('BEGIN PUBLIC KEY') || asText.includes('BEGIN CERTIFICATE')) {
    return createPublicKey(asText);
  }
  try {
    return createPublicKey({ key: raw, format: 'der', type: 'spki' });
  } catch {
    return createPublicKey(asText);
  }
}
