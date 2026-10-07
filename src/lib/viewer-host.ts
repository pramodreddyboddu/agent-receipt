/**
 * Exact Host allowlist for `view`.
 * `net.isIP` checks address syntax only. Nothing here resolves DNS or
 * enumerates interfaces. Forwarded headers are not an input.
 */
import { isIP } from 'node:net';

export interface AllowedHost {
  /** Lowercase hostname or address, with IPv6 brackets removed. */
  host: string;
  /** Set only when the flag included `:port`. Otherwise the bound port is used. */
  port?: number;
  /** Canonical entry: `host`, `[ipv6]`, or either form with `:port`. */
  normalized: string;
  loopback: boolean;
}

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

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

function finish(raw: string, host: string, port: number | undefined, ipv6: boolean): AllowedHost {
  const normalizedHost = ipv6 ? `[${host}]` : host;
  const normalized = port === undefined ? normalizedHost : `${normalizedHost}:${port}`;
  return {
    host,
    port,
    normalized,
    loopback: isLoopbackName(host),
  };
}

/**
 * One `--allowed-host` value. Hostnames and addresses are lowercased.
 * Bracketed and bare IPv6 become `[addr]`. A missing port is left unset
 * so the caller can match the bound port only.
 */
export function normalizeAllowedHost(value: string): AllowedHost {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('--allowed-host requires a hostname, IPv4 address, or IPv6 address.');
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
    reject(value, 'Pass a hostname, IPv4 address, or IPv6 address, optionally with :port.');
  }

  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    if (close <= 1 || value.indexOf('[', 1) !== -1) {
      reject(value, 'Pass a hostname, IPv4 address, or IPv6 address, optionally with :port.');
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
    const host = inner.toLowerCase();
    if (isIP(host) !== 6) {
      reject(value, 'Pass a hostname, IPv4 address, or IPv6 address, optionally with :port.');
    }
    return finish(value, host, port, true);
  }

  if (isIP(value) === 6) {
    return finish(value, value.toLowerCase(), undefined, true);
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
  if (isIP(host) === 4) return finish(value, host, port, false);
  // Four numeric labels that are not a canonical IPv4 address (leading
  // zeros, octets above 255) are not a hostname either.
  if (/^\d+(\.\d+){3}$/.test(host)) {
    reject(value, 'Pass a hostname, IPv4 address, or IPv6 address, optionally with :port.');
  }
  if (isHostname(host)) return finish(value, host, port, false);
  reject(value, 'Pass a hostname, IPv4 address, or IPv6 address, optionally with :port.');
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

function hostPort(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

/**
 * True when `header` is the bound host:port or one allowed entry.
 * An allowed entry without a port matches `boundPort` only.
 * An entry with a port matches that port only. Match is exact after
 * lowercasing. The header is not trimmed and is not taken from any
 * forwarded-host field.
 */
export function hostHeaderAllowed(
  header: string | undefined,
  boundHost: string,
  boundPort: number,
  allowed: readonly AllowedHost[],
): boolean {
  if (typeof header !== 'string' || header.length === 0 || /\s/.test(header)) return false;
  const got = header.toLowerCase();
  if (got === hostPort(boundHost, boundPort).toLowerCase()) return true;
  for (const entry of allowed) {
    const port = entry.port ?? boundPort;
    if (got === hostPort(entry.host, port)) return true;
  }
  return false;
}
