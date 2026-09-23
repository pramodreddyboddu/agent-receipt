import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { loadConfig } from './config.js';
import type { SignatureStatus } from './sign.js';

/**
 * Local known-keys allowlist. Already under gitignored `.agent-receipt/`.
 * Teams that want the list in git can keep a copy under `examples/` or
 * `docs/` and copy it here. This is not a CA, a cert chain, or a revocation list.
 */
export const TRUSTED_KEYS_REL = '.agent-receipt/trusted-keys.txt';
export const CONFIG_TRUST_SOURCE = 'config:trustedFingerprints';
export const CLI_TRUST_SOURCE = '--trusted-key';

const FP64 = /^[0-9a-f]{64}$/;

export interface TrustStore {
  /** Lowercase 64-hex fingerprints. Empty when the allowlist is inactive or unloadable. */
  fingerprints: Set<string>;
  /** Where fingerprints were read from. Empty when no store is configured. */
  sources: string[];
  /**
   * Set when a configured store cannot be parsed (invalid line, unreadable
   * file, bad config entry). Callers that gate on the store fail closed.
   */
  reason?: string;
}

export interface TrustCheck {
  ok: boolean;
  /** Null when the fingerprint is allowed (including when the allowlist is inactive). */
  reason: string | null;
}

export interface LoadTrustOptions {
  /**
   * Invocation-only fingerprints (`verify` / `prove --trusted-key`).
   * Union with the file and `trustedFingerprints`. Already validated by the CLI.
   */
  extra?: string[];
}

export function trustedKeysPath(cwd: string): string {
  return join(cwd, TRUSTED_KEYS_REL);
}

export function isFingerprintHex(value: string): boolean {
  return FP64.test(value);
}

/** True when at least one fingerprint is listed and the store loaded cleanly. */
export function trustStoreActive(store: TrustStore): boolean {
  return !store.reason && store.fingerprints.size > 0;
}

/**
 * One lowercase 64-hex fingerprint per non-empty line.
 * `#` comments and blank lines are ignored. Trailing whitespace is stripped.
 * Any other non-empty line is an error (fail closed), not a silent skip.
 */
export function parseTrustedKeysText(
  text: string,
  label: string,
): { fingerprints: string[]; reason?: string } {
  const fingerprints: string[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].replace(/\s+$/, '').trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const fp = trimmed.toLowerCase();
    if (!FP64.test(fp)) {
      return {
        fingerprints: [],
        reason: `invalid fingerprint in ${label} line ${i + 1}: expected 64 hex chars`,
      };
    }
    fingerprints.push(fp);
  }
  return { fingerprints };
}

function withReason(sources: string[], reason: string): TrustStore {
  return { fingerprints: new Set(), sources, reason };
}

/**
 * Union of `.agent-receipt/trusted-keys.txt`, config `trustedFingerprints`,
 * and optional `--trusted-key` extras. Either source alone is enough.
 * Both missing (and no extras) → empty set, no reason: the allowlist is inactive.
 */
export function loadTrustedFingerprints(
  cwd: string,
  opts: LoadTrustOptions = {},
): TrustStore {
  const fingerprints = new Set<string>();
  const sources: string[] = [];
  const path = trustedKeysPath(cwd);

  if (existsSync(path)) {
    let text: string;
    try {
      text = readFileSync(path, 'utf8');
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      return withReason(
        [TRUSTED_KEYS_REL],
        `unreadable trust store ${TRUSTED_KEYS_REL} (${detail})`,
      );
    }
    const parsed = parseTrustedKeysText(text, TRUSTED_KEYS_REL);
    if (parsed.reason) return withReason([TRUSTED_KEYS_REL], parsed.reason);
    sources.push(TRUSTED_KEYS_REL);
    for (const fp of parsed.fingerprints) fingerprints.add(fp);
  }

  const cfg = loadConfig(cwd);
  if (cfg.trustedFingerprintsInvalid) {
    return withReason(
      [...sources, CONFIG_TRUST_SOURCE],
      cfg.trustedFingerprintsInvalid,
    );
  }
  if (cfg.trustedFingerprints !== undefined) {
    sources.push(CONFIG_TRUST_SOURCE);
    for (const fp of cfg.trustedFingerprints) fingerprints.add(fp);
  }

  if (opts.extra && opts.extra.length) {
    const extras: string[] = [];
    for (const raw of opts.extra) {
      for (const part of raw.split(',')) {
        const fp = part.trim().toLowerCase();
        if (!fp) continue;
        if (!FP64.test(fp)) {
          return withReason(
            [...sources, CLI_TRUST_SOURCE],
            '--trusted-key must be 64 hex chars',
          );
        }
        extras.push(fp);
      }
    }
    if (extras.length) {
      sources.push(CLI_TRUST_SOURCE);
      for (const fp of extras) fingerprints.add(fp);
    }
  }

  return { fingerprints, sources };
}

/**
 * Allowlist inactive (empty store, no load error) → true.
 * A load error fails closed (false). An active store checks membership.
 */
export function isFingerprintTrusted(fp: string, store: TrustStore): boolean {
  if (store.reason) return false;
  if (!trustStoreActive(store)) return true;
  return store.fingerprints.has(fp.trim().toLowerCase());
}

/**
 * After a cryptographically valid sidecar, apply the known-keys allowlist.
 * Inactive store → `trusted: null` and `ok` stays true.
 * Active store miss, or a store that failed to load → `ok: false`.
 * A signature that is absent or already invalid is not re-labeled.
 */
export function applyTrust(signature: SignatureStatus, store: TrustStore): SignatureStatus {
  if (!signature.present || signature.ok !== true) {
    return { ...signature, trusted: null };
  }
  if (store.reason) {
    return {
      ...signature,
      ok: false,
      trusted: false,
      reason: store.reason,
    };
  }
  if (!trustStoreActive(store)) {
    return { ...signature, trusted: null };
  }
  const checked = checkTrusted(signature.fingerprint ?? '', store);
  if (!checked.ok) {
    return {
      ...signature,
      ok: false,
      trusted: false,
      reason: `fingerprint not trusted: ${checked.reason}`,
    };
  }
  return { ...signature, trusted: true };
}

/**
 * When the allowlist is active and `fp` is missing:
 * `{ ok: false, reason: "fingerprint not in trust store: <fp>" }`.
 */
export function checkTrusted(fp: string, store: TrustStore): TrustCheck {
  if (store.reason) return { ok: false, reason: store.reason };
  if (!trustStoreActive(store)) return { ok: true, reason: null };
  const normalized = fp.trim().toLowerCase();
  if (store.fingerprints.has(normalized)) return { ok: true, reason: null };
  return {
    ok: false,
    reason: `fingerprint not in trust store: ${normalized}`,
  };
}

export interface TrustDoctorView {
  /** absent = nothing configured; empty = configured but no fingerprints; invalid = fail closed; ok = N > 0. */
  kind: 'absent' | 'empty' | 'invalid' | 'ok';
  detail: string;
  count: number;
}

/** Doctor row. Does not apply `--trusted-key` (that flag is invocation-only). */
export function inspectTrustForDoctor(cwd: string): TrustDoctorView {
  const store = loadTrustedFingerprints(cwd);
  if (store.reason) {
    return { kind: 'invalid', detail: store.reason, count: 0 };
  }
  if (store.fingerprints.size > 0) {
    const first = [...store.fingerprints][0];
    const shown = `${first.slice(0, 12)}…`;
    const n = store.fingerprints.size;
    const noun = n === 1 ? 'fingerprint' : 'fingerprints';
    return {
      kind: 'ok',
      count: n,
      detail: `${n} trusted ${noun} (${shown}) from ${store.sources.join(', ')}`,
    };
  }
  if (store.sources.length > 0) {
    return {
      kind: 'empty',
      count: 0,
      detail:
        'trust store present but empty — allowlist inactive until a 64-hex fingerprint is listed',
    };
  }
  return {
    kind: 'absent',
    count: 0,
    detail:
      'no fingerprint trust store — allowlist inactive (any valid sidecar passes verify --require-sig)',
  };
}

function ensureTrustDir(cwd: string): string {
  const path = trustedKeysPath(cwd);
  mkdirSync(dirname(path), { recursive: true });
  return path;
}

function readTrustFile(cwd: string): { text: string; reason?: string } {
  const path = trustedKeysPath(cwd);
  if (!existsSync(path)) return { text: '' };
  try {
    return { text: readFileSync(path, 'utf8') };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { text: '', reason: `unreadable trust store ${TRUSTED_KEYS_REL} (${detail})` };
  }
}

/**
 * Append one fingerprint to `trusted-keys.txt`. Invalid existing lines are
 * not rewritten. A fingerprint that is already listed is left as-is.
 */
export function addTrustedFingerprint(
  cwd: string,
  fp: string,
): { added: boolean; fingerprints: string[]; reason?: string } {
  const normalized = fp.trim().toLowerCase();
  if (!FP64.test(normalized)) {
    return {
      added: false,
      fingerprints: [],
      reason: 'fingerprint must be 64 hex chars',
    };
  }
  const file = readTrustFile(cwd);
  if (file.reason) return { added: false, fingerprints: [], reason: file.reason };
  const parsed = parseTrustedKeysText(file.text, TRUSTED_KEYS_REL);
  if (parsed.reason) return { added: false, fingerprints: [], reason: parsed.reason };
  if (parsed.fingerprints.includes(normalized)) {
    return { added: false, fingerprints: parsed.fingerprints };
  }
  const path = ensureTrustDir(cwd);
  const base = file.text.length === 0 ? '' : file.text.endsWith('\n') ? file.text : `${file.text}\n`;
  writeFileSync(path, `${base}${normalized}\n`, { mode: 0o644 });
  return { added: true, fingerprints: [...parsed.fingerprints, normalized] };
}

/** Remove one fingerprint. Comments and other lines stay. A missing file is a no-op. */
export function removeTrustedFingerprint(
  cwd: string,
  fp: string,
): { removed: boolean; fingerprints: string[]; reason?: string } {
  const normalized = fp.trim().toLowerCase();
  if (!FP64.test(normalized)) {
    return {
      removed: false,
      fingerprints: [],
      reason: 'fingerprint must be 64 hex chars',
    };
  }
  const path = trustedKeysPath(cwd);
  const file = readTrustFile(cwd);
  if (file.reason) return { removed: false, fingerprints: [], reason: file.reason };
  if (!existsSync(path)) return { removed: false, fingerprints: [] };
  const parsed = parseTrustedKeysText(file.text, TRUSTED_KEYS_REL);
  if (parsed.reason) return { removed: false, fingerprints: [], reason: parsed.reason };
  if (!parsed.fingerprints.includes(normalized)) {
    return { removed: false, fingerprints: parsed.fingerprints };
  }
  const kept = file.text.split(/\r?\n/).filter((line) => {
    const trimmed = line.replace(/\s+$/, '').trim();
    if (!trimmed || trimmed.startsWith('#')) return true;
    return trimmed.toLowerCase() !== normalized;
  });
  const body = kept.join('\n').replace(/\n*$/, '');
  writeFileSync(path, body.length ? `${body}\n` : '', { mode: 0o644 });
  return {
    removed: true,
    fingerprints: parsed.fingerprints.filter((item) => item !== normalized),
  };
}
