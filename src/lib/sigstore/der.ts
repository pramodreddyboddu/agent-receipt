/**
 * Minimal DER helpers for the certificates and extensions this cut reads
 * and writes. Not a general ASN.1 library.
 */

export interface DerNode {
  tag: number;
  /** Contents, without the tag and length. */
  value: Buffer;
  /** Absolute offset of the tag in the buffer that was parsed. */
  start: number;
  end: number;
}

export function derLen(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  if (bytes.length > 4) throw new Error('DER length is too large');
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function derTag(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

export function seq(items: Buffer[]): Buffer {
  return derTag(0x30, Buffer.concat(items));
}

export function oid(dotted: string): Buffer {
  return derTag(0x06, encodeOid(dotted));
}

export function encodeOid(dotted: string): Buffer {
  const parts = dotted.split('.').map((part) => {
    if (!/^\d+$/.test(part)) throw new Error(`bad OID: ${dotted}`);
    return Number(part);
  });
  if (parts.length < 2) throw new Error(`bad OID: ${dotted}`);
  const out: number[] = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    let n = Math.floor(part / 128);
    while (n > 0) {
      chunk.unshift((n & 0x7f) | 0x80);
      n = Math.floor(n / 128);
    }
    out.push(...chunk);
  }
  return Buffer.from(out);
}

/** Positive INTEGER. A leading 0x00 is added when the high bit is set. */
export function integer(raw: Buffer): Buffer {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0 && (raw[i + 1] & 0x80) === 0) i += 1;
  let body = raw.subarray(i);
  if (body.length === 0) body = Buffer.from([0]);
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0x00]), body]);
  return derTag(0x02, body);
}

export function octet(content: Buffer): Buffer {
  return derTag(0x04, content);
}

export function utf8(text: string): Buffer {
  return derTag(0x0c, Buffer.from(text, 'utf8'));
}

export function bitString(content: Buffer): Buffer {
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), content]));
}

export function boolTrue(): Buffer {
  return derTag(0x01, Buffer.from([0xff]));
}

/** UTCTime. Years are the last two digits. Callers stay before 2050. */
export function utcTime(date: Date): Buffer {
  const yy = String(date.getUTCFullYear() % 100).padStart(2, '0');
  const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(date.getUTCDate()).padStart(2, '0');
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const mi = String(date.getUTCMinutes()).padStart(2, '0');
  const ss = String(date.getUTCSeconds()).padStart(2, '0');
  return derTag(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${mi}${ss}Z`, 'ascii'));
}

export function parseDer(buf: Buffer, offset = 0): { node: DerNode; next: number } {
  if (offset < 0 || offset >= buf.length) throw new Error('truncated DER');
  const tag = buf[offset];
  let pos = offset + 1;
  if (pos >= buf.length) throw new Error('truncated DER length');
  let length = buf[pos];
  pos += 1;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('unsupported DER length');
    length = 0;
    for (let i = 0; i < count; i += 1) {
      if (pos >= buf.length) throw new Error('truncated DER length');
      length = (length << 8) | buf[pos];
      pos += 1;
    }
  }
  const end = pos + length;
  if (end > buf.length) throw new Error('truncated DER value');
  return { node: { tag, value: buf.subarray(pos, end), start: offset, end }, next: end };
}

export function derChildren(buf: Buffer): DerNode[] {
  const out: DerNode[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const parsed = parseDer(buf, pos);
    out.push(parsed.node);
    if (parsed.next <= pos) throw new Error('DER did not advance');
    pos = parsed.next;
  }
  return out;
}
