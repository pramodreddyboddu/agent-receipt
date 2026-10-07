/**
 * Exact Host allowlist for `view`.
 * `net.isIP` checks address syntax only. Nothing here resolves DNS or
 * enumerates interfaces. Forwarded headers are not an input.
 *
 * IPv6 is stored and compared in compressed lowercase form, so
 * `fd00:0::1` and `[fd00::1]` are one entry. A last label that is all
 * digits or `0x` hex is rejected unless the host is a canonical IPv4
 * dotted quad. Browsers parse the other forms (`127.1`, `2130706433`,
 * `0x7f000001`, `010.0.0.1`) as addresses, not as hostnames.
 */
import { isIP } from 'node:net';

export interface AllowedHost {
  /** Lowercase hostname or address. IPv6 is compressed, with brackets removed. */
  host: string;
  /** Set only when the flag included `:port`. Otherwise the bound port is used. */
  port?: number;
  /** Canonical entry: `host`, `[ipv6]`, or either form with `:port`. */
  normalized: string;
  loopback: boolean;
}

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DECIMAL_LABEL = /^[0-9]+$/;
const HEX_LABEL = /^0x[0-9a-f]+$/;

function reject(value: string, reason: string): never {
  throw new Error(`Invalid --allowed-host ${JSON.stringify(value)}. ${reason}`);
}

function parsePort(value: string, raw: string): number {
  if (!/^[0-9]{1,5}$/.test(value) || (value.length > 1 && value.startsWith('0'))) {
    reject(raw, 'The port must be an integer from 1 to 65535.');
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    reject(raw, 'The port must be an integer from 1 to 65535.');
  }
  return port;
}

function isHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split('.');
  return labels.every((label) => HOST_LABEL.test(label));
}

function isLoopbackName(host: string): boolean {
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

/** Same loopback names `view` already accepts as a bind address. */
export function isLoopbackBindHost(host: string): boolean {
  const bare = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return isLoopbackName(bare);
}

/**
 * Four decimal octets, each 0-255, with no leading zeros.
 * `192.168.1.20` and `0.0.0.0` pass. `010.0.0.1` and `127.1` do not.
 */
function isCanonicalDottedIPv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return false;
    if (Number(part) > 255) return false;
  }
  return isIP(host) === 4;
}

/** Last label is all digits or `0x` hex, and the host is not a canonical IPv4. */
function isNonCanonicalNumericHost(host: string): boolean {
  if (isCanonicalDottedIPv4(host)) return false;
  const dot = host.lastIndexOf('.');
  const label = dot === -1 ? host : host.slice(dot + 1);
  return DECIMAL_LABEL.test(label) || HEX_LABEL.test(label);
}

/**
 * Compressed lowercase IPv6, no brackets.
 * Node's URL hostname includes brackets in current releases; both forms are stripped.
 * `fd00:0::1` and `FD00:0:0:0:0:0:0:1` become `fd00::1`.
 */
function canonicalizeIpv6(host: string): string | undefined {
  if (isIP(host) !== 6) return undefined;
  let rendered: string;
  try {
    rendered = new URL(`http://[${host}]/`).hostname;
  } catch {
    return undefined;
  }
  if (rendered.startsWith('[') && rendered.endsWith(']')) {
    rendered = rendered.slice(1, -1);
  }
  rendered = rendered.toLowerCase();
  if (isIP(rendered) !== 6) return undefined;
  return rendered;
}

function finish(host: string, port: number | undefined, ipv6: boolean): AllowedHost {
  const normalizedHost = ipv6 ? `[${host}]` : host;
  const normalized = port === undefined ? normalizedHost : `${normalizedHost}:${port}`;
  return {
    host,
    port,
    normalized,
    loopback: isLoopbackName(host),
  };
}

const NUMERIC_REASON =
  'Non-canonical numeric addresses are rejected. Pass a hostname, or a canonical IPv4 address of four decimal octets from 0 to 255 with no leading zeros (for example 192.168.1.20).';

const IDN_REASON =
  'Unicode internationalized names are rejected. Pass the punycode label (xn--) instead.';

const HOST_REASON = 'Pass a hostname, IPv4 address, or IPv6 address, optionally with :port.';

/**
 * One `--allowed-host` value. Hostnames and addresses are lowercased.
 * Bracketed and bare IPv6 become compressed `[addr]`. A missing port is
 * left unset so the caller can match the bound port only.
 * Punycode labels (`xn--`) are hostnames. Unicode IDN is rejected.
 */
export function normalizeAllowedHost(value: string): AllowedHost {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('--allowed-host requires a hostname, IPv4 address, or IPv6 address.');
  }
  if (value.startsWith('-')) {
    reject(
      value,
      'A value that starts with "-" is not a hostname. Pass a hostname, IPv4 address, or IPv6 address.',
    );
  }
  if (/\s/.test(value)) {
    throw new Error('--allowed-host does not accept whitespace.');
  }
  if (value.includes(',')) {
    throw new Error(
      '--allowed-host does not accept a comma-separated list. Repeat the flag: --allowed-host <name> --allowed-host <name>',
    );
  }
  if (value.includes('*')) {
    throw new Error('--allowed-host does not accept wildcards. Pass an exact hostname or IP address.');
  }
  if (value.includes('@')) {
    throw new Error('--allowed-host does not accept userinfo. Pass a hostname or IP address.');
  }
  if (value.includes('://')) {
    throw new Error('--allowed-host does not accept a URL or scheme. Pass a hostname or IP address.');
  }
  if (value.includes('/') || value.includes('\\') || value.includes('?') || value.includes('#')) {
    throw new Error('--allowed-host does not accept a path.');
  }
  if (value.includes('%')) {
    reject(value, HOST_REASON);
  }

  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    if (close <= 1 || value.indexOf('[', 1) !== -1) {
      reject(value, HOST_REASON);
    }
    const inner = value.slice(1, close);
    const rest = value.slice(close + 1);
    let port: number | undefined;
    if (rest !== '') {
      if (!rest.startsWith(':')) {
        reject(value, 'An IPv6 address with a port must look like [fd00::1]:4173.');
      }
      port = parsePort(rest.slice(1), value);
    }
    const canonical = canonicalizeIpv6(inner.toLowerCase());
    if (!canonical) reject(value, HOST_REASON);
    return finish(canonical, port, true);
  }

  if (isIP(value) === 6) {
    const canonical = canonicalizeIpv6(value.toLowerCase());
    if (!canonical) reject(value, HOST_REASON);
    return finish(canonical, undefined, true);
  }

  const colon = value.lastIndexOf(':');
  let hostPart = value;
  let port: number | undefined;
  if (colon !== -1) {
    if (value.indexOf(':') !== colon) {
      reject(value, 'An IPv6 address with a port must be bracketed, for example [fd00::1]:4173.');
    }
    hostPart = value.slice(0, colon);
    port = parsePort(value.slice(colon + 1), value);
  }
  const host = hostPart.toLowerCase();
  if (isCanonicalDottedIPv4(host)) return finish(host, port, false);
  if (isNonCanonicalNumericHost(host)) reject(value, NUMERIC_REASON);
  if (/[^\u0000-\u007f]/.test(host)) reject(value, IDN_REASON);
  if (isHostname(host)) return finish(host, port, false);
  reject(value, HOST_REASON);
}

/** Repeatable flag values, deduped by their normalized entry. First one wins. */
export function normalizeAllowedHosts(values: readonly string[]): AllowedHost[] {
  const out: AllowedHost[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const entry = normalizeAllowedHost(value);
    if (seen.has(entry.normalized)) continue;
    seen.add(entry.normalized);
    out.push(entry);
  }
  return out;
}

function parseHeaderPort(value: string): number | undefined {
  if (!/^[0-9]{1,5}$/.test(value) || (value.length > 1 && value.startsWith('0'))) return undefined;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) return undefined;
  return port;
}

function stripBrackets(host: string): string {
  if (host.startsWith('[') && host.endsWith(']') && host.indexOf('[', 1) === -1) {
    return host.slice(1, -1);
  }
  return host;
}

/** Host header with its port. Missing or extra colons are not a match. */
function splitHostHeader(header: string): { host: string; port: number } | undefined {
  if (header.startsWith('[')) {
    const close = header.indexOf(']');
    const nested = header.indexOf('[', 1);
    if (close <= 1 || (nested !== -1 && nested < close)) return undefined;
    const inner = header.slice(1, close);
    const rest = header.slice(close + 1);
    if (!rest.startsWith(':')) return undefined;
    const port = parseHeaderPort(rest.slice(1));
    if (port === undefined || inner.length === 0) return undefined;
    return { host: inner, port };
  }
  const first = header.indexOf(':');
  if (first <= 0) return undefined;
  if (header.lastIndexOf(':') !== first) return undefined;
  const port = parseHeaderPort(header.slice(first + 1));
  if (port === undefined) return undefined;
  return { host: header.slice(0, first), port };
}

/**
 * Comparable host, or null when the header must not match.
 * Non-canonical numeric forms are null even if the bound string is identical.
 */
function comparableHost(host: string): string | null {
  const lower = host.toLowerCase();
  if (lower.includes(':')) return canonicalizeIpv6(lower) ?? null;
  if (isNonCanonicalNumericHost(lower)) return null;
  return lower;
}

/**
 * True when `header` is the bound host:port or one allowed entry.
 * An allowed entry without a port matches `boundPort` only.
 * An entry with a port matches that port only.
 * IPv6 is compared after compression. A last label that is all digits
 * or `0x` hex does not match unless it is a canonical dotted quad.
 * The header is not trimmed and is not taken from any forwarded-host field.
 */
export function hostHeaderAllowed(
  header: string | undefined,
  boundHost: string,
  boundPort: number,
  allowed: readonly AllowedHost[],
): boolean {
  if (typeof header !== 'string' || header.length === 0 || /\s/.test(header)) return false;
  const parsed = splitHostHeader(header);
  if (!parsed) return false;
  const got = comparableHost(parsed.host);
  if (got === null) return false;
  const bound = comparableHost(stripBrackets(boundHost));
  if (bound !== null && got === bound && parsed.port === boundPort) return true;
  for (const entry of allowed) {
    const port = entry.port ?? boundPort;
    if (parsed.port === port && got === entry.host) return true;
  }
  return false;
}
