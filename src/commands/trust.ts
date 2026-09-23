import { color } from '../lib/color.js';
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
}

export interface TrustReport {
  ok: boolean;
  command: 'trust';
  action: 'list' | 'add' | 'rm';
  version: string;
  exitCode: 0 | 1;
  active: boolean;
  count: number;
  fingerprints: string[];
  sources: string[];
  added?: boolean;
  removed?: boolean;
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
  const verb = report.action === 'add' ? (report.added ? 'added' : 'already listed') : report.removed ? 'removed' : 'not listed';
  console.log(`${color.green('OK')}  ${verb}`);
  console.log(`  count: ${report.count}`);
  console.log(color.dim(`  file: ${TRUSTED_KEYS_REL}`));
  return report;
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

export function cmdTrust(
  cwd: string,
  action: string | undefined,
  fingerprint: string | undefined,
  opts: TrustCommandOptions = {},
): TrustReport {
  const json = Boolean(opts.json);
  if (action !== 'list' && action !== 'add' && action !== 'rm') {
    return emit(
      {
        ok: false,
        command: 'trust',
        action: 'list',
        version: VERSION,
        exitCode: 1,
        active: false,
        count: 0,
        fingerprints: [],
        sources: [],
        reason: 'trust requires list, add <fingerprint>, or rm <fingerprint>',
      },
      json,
    );
  }
  if (action === 'list') return emit(listReport(cwd), json);

  if (!fingerprint || !fingerprint.trim()) {
    return emit(
      {
        ok: false,
        command: 'trust',
        action,
        version: VERSION,
        exitCode: 1,
        active: false,
        count: 0,
        fingerprints: [],
        sources: [],
        reason: `trust ${action} requires a 64-hex fingerprint`,
      },
      json,
    );
  }

  const changed =
    action === 'add'
      ? addTrustedFingerprint(cwd, fingerprint)
      : removeTrustedFingerprint(cwd, fingerprint);
  if (changed.reason) {
    return emit(
      {
        ok: false,
        command: 'trust',
        action,
        version: VERSION,
        exitCode: 1,
        active: false,
        count: 0,
        fingerprints: [],
        sources: [TRUSTED_KEYS_REL],
        reason: changed.reason,
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
      action,
      version: VERSION,
      exitCode: 0,
      active: fingerprints.length > 0 && !store.reason,
      count: fingerprints.length,
      fingerprints,
      sources: store.sources,
      added: action === 'add' ? (changed as { added: boolean }).added : undefined,
      removed: action === 'rm' ? (changed as { removed: boolean }).removed : undefined,
      reason: null,
    },
    json,
  );
}
