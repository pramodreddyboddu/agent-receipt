import { color } from '../lib/color.js';
import { loadKeys } from '../lib/sign.js';
import { VERSION } from '../lib/version.js';
import {
  addTrustedFingerprint,
  loadTrustedFingerprints,
  removeTrustedFingerprint,
  trustStoreActive,
  TRUSTED_KEYS_REL,
} from '../lib/trust.js';

export interface TrustCommandOptions {
  json?: boolean;
  /** Resolve the local keygen fingerprint and append it (`trust add --self`). */
  self?: boolean;
}

export interface TrustReport {
  ok: boolean;
  command: 'trust';
  action: 'list' | 'add' | 'rm' | 'show';
  version: string;
  exitCode: 0 | 1;
  active: boolean;
  count: number;
  fingerprints: string[];
  sources: string[];
  added?: boolean;
  removed?: boolean;
  /**
   * Local keygen fingerprint when `--self` (or the `self` alias) resolved.
   * Omitted for `trust add <64-hex>`.
   */
  fingerprint?: string;
  /**
   * Trusted-keys path for `trust show` (`TRUSTED_KEYS_REL`).
   * Omitted for list, add, and rm.
   */
  path?: string;
  /**
   * Local keygen fingerprint for `trust show`.
   * Null when keys do not load. Omitted for list, add, and rm.
   */
  localFingerprint?: string | null;
  /**
   * Whether the local key is on the allowlist.
   * Null when no local key loaded. Omitted for list, add, and rm.
   */
  localListed?: boolean | null;
  reason: string | null;
}

function emit(report: TrustReport, json: boolean): TrustReport {
  if (json) {
    console.log(JSON.stringify(report));
    return report;
  }
  if (report.exitCode !== 0) {
    console.error(color.red('Error:') + ` ${report.reason ?? 'trust failed'}`);
    return report;
  }
  if (report.action === 'list') {
    if (!report.active) {
      console.log('trust store inactive (no allowlist)');
      if (report.sources.length) {
        console.log(`  sources: ${report.sources.join(', ')}`);
      }
      console.log(color.dim(`File: ${TRUSTED_KEYS_REL}`));
      return report;
    }
    console.log(`trusted-keys (${report.count})`);
    for (const fp of report.fingerprints) console.log(`  ${fp}`);
    console.log(color.dim(`sources: ${report.sources.join(', ')}`));
    return report;
  }
  if (report.action === 'show') {
    console.log('trust show');
    console.log('trusted-keys');
    console.log(`active: ${report.active}`);
    console.log(`count: ${report.count}`);
    console.log(`file: ${TRUSTED_KEYS_REL}`);
    const sources = report.sources.length ? report.sources.join(', ') : '(none)';
    console.log(`sources: ${sources}`);
    if (report.active) {
      for (const fp of report.fingerprints) console.log(`  ${fp}`);
    }
    if (report.localFingerprint) {
      console.log(`local: ${report.localFingerprint}`);
    } else {
      console.log('local: (none — run keygen)');
    }
    const listed = report.localListed === null ? 'n/a' : String(report.localListed);
    console.log(`localListed: ${listed}`);
    if (report.localListed === false) {
      console.log('tip: local key is not listed. Run `agent-receipt trust add --self`.');
    }
    return report;
  }
  const verb = report.action === 'add' ? (report.added ? 'added' : 'already listed') : report.removed ? 'removed' : 'not listed';
  console.log(`${color.green('OK')}  ${verb}`);
  if (report.fingerprint) console.log(`  fingerprint: ${report.fingerprint}`);
  console.log(`  count: ${report.count}`);
  console.log(color.dim(`  file: ${TRUSTED_KEYS_REL}`));
  return report;
}

function failed(action: TrustReport['action'], reason: string): TrustReport {
  return {
    ok: false,
    command: 'trust',
    action,
    version: VERSION,
    exitCode: 1,
    active: false,
    count: 0,
    fingerprints: [],
    sources: [],
    reason,
  };
}

function listReport(cwd: string): TrustReport {
  const store = loadTrustedFingerprints(cwd);
  const fingerprints = [...store.fingerprints];
  if (store.reason) {
    return {
      ok: false,
      command: 'trust',
      action: 'list',
      version: VERSION,
      exitCode: 1,
      active: false,
      count: 0,
      fingerprints: [],
      sources: store.sources,
      reason: store.reason,
    };
  }
  return {
    ok: true,
    command: 'trust',
    action: 'list',
    version: VERSION,
    exitCode: 0,
    active: trustStoreActive(store),
    count: fingerprints.length,
    fingerprints,
    sources: store.sources,
    reason: null,
  };
}

function localKeyFingerprint(cwd: string): string | null {
  try {
    return loadKeys(cwd).fingerprint;
  } catch {
    return null;
  }
}

/** Read-only status. Missing keys stay exit 0. A bad store fails like `trust list`. */
function showReport(cwd: string): TrustReport {
  const store = loadTrustedFingerprints(cwd);
  const localFingerprint = localKeyFingerprint(cwd);
  const base = {
    command: 'trust' as const,
    action: 'show' as const,
    version: VERSION,
    path: TRUSTED_KEYS_REL,
    localFingerprint,
  };
  if (store.reason) {
    return {
      ...base,
      ok: false,
      exitCode: 1,
      active: false,
      count: 0,
      fingerprints: [],
      sources: store.sources,
      localListed: localFingerprint === null ? null : false,
      reason: store.reason,
    };
  }
  const fingerprints = [...store.fingerprints];
  return {
    ...base,
    ok: true,
    exitCode: 0,
    active: trustStoreActive(store),
    count: fingerprints.length,
    fingerprints,
    sources: store.sources,
    localListed: localFingerprint === null ? null : fingerprints.includes(localFingerprint),
    reason: null,
  };
}

export function cmdTrust(
  cwd: string,
  action: string | undefined,
  fingerprint: string | undefined,
  opts: TrustCommandOptions = {},
): TrustReport {
  const json = Boolean(opts.json);
  const selfFlag = Boolean(opts.self);
  const verb = action === 'status' ? 'show' : action;
  if (verb !== 'list' && verb !== 'add' && verb !== 'rm' && verb !== 'show') {
    return emit(
      failed(
        'list',
        'trust requires list, show, add <fingerprint>, add --self, or rm <fingerprint>',
      ),
      json,
    );
  }
  if (selfFlag && verb !== 'add') {
    return emit(failed(verb, `trust ${verb} does not accept --self`), json);
  }
  if (verb === 'list') return emit(listReport(cwd), json);
  if (verb === 'show') {
    if (fingerprint && fingerprint.trim()) {
      return emit(
        {
          ...failed('show', 'trust show takes no fingerprint'),
          path: TRUSTED_KEYS_REL,
          localFingerprint: null,
          localListed: null,
        },
        json,
      );
    }
    return emit(showReport(cwd), json);
  }

  let resolved = fingerprint;
  let selfFingerprint: string | undefined;
  const bareSelf = resolved?.trim() === 'self';
  if (verb === 'add' && (selfFlag || bareSelf)) {
    if (resolved && resolved.trim() !== 'self') {
      return emit(failed('add', 'trust add --self does not take a fingerprint'), json);
    }
    try {
      selfFingerprint = loadKeys(cwd).fingerprint;
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      return emit(failed('add', detail), json);
    }
    resolved = selfFingerprint;
  }

  if (!resolved || !resolved.trim()) {
    const reason =
      verb === 'add'
        ? 'trust add requires a 64-hex fingerprint or --self'
        : `trust ${verb} requires a 64-hex fingerprint`;
    return emit(failed(verb, reason), json);
  }

  const changed =
    verb === 'add'
      ? addTrustedFingerprint(cwd, resolved)
      : removeTrustedFingerprint(cwd, resolved);
  if (changed.reason) {
    return emit(
      {
        ...failed(verb, changed.reason),
        sources: [TRUSTED_KEYS_REL],
        fingerprint: selfFingerprint,
      },
      json,
    );
  }
  const store = loadTrustedFingerprints(cwd);
  const fingerprints = store.reason ? changed.fingerprints : [...store.fingerprints];
  return emit(
    {
      ok: true,
      command: 'trust',
      action: verb,
      version: VERSION,
      exitCode: 0,
      active: fingerprints.length > 0 && !store.reason,
      count: fingerprints.length,
      fingerprints,
      sources: store.sources,
      added: verb === 'add' ? (changed as { added: boolean }).added : undefined,
      removed: verb === 'rm' ? (changed as { removed: boolean }).removed : undefined,
      fingerprint: selfFingerprint,
      reason: null,
    },
    json,
  );
}
