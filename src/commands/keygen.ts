import { existsSync } from 'node:fs';
import { color } from '../lib/color.js';
import { VERSION } from '../lib/version.js';
import {
  loadKeys,
  privateKeyPath,
  publicKeyPath,
  writeKeyPair,
} from '../lib/sign.js';

export interface KeygenOptions {
  /** Overwrite an existing keypair. */
  force?: boolean;
  /** One JSON object on stdout. */
  json?: boolean;
}

export interface KeygenReport {
  ok: boolean;
  command: 'keygen';
  version: string;
  exitCode: 0 | 1;
  fingerprint: string | null;
  privateKeyPath: string | null;
  publicKeyPath: string | null;
  created: boolean;
  rotated: boolean;
  reason: string | null;
}

function emit(report: KeygenReport, json: boolean): KeygenReport {
  if (json) {
    console.log(JSON.stringify(report));
    return report;
  }
  if (report.exitCode !== 0) {
    console.error(color.red('Error:') + ` ${report.reason ?? 'keygen failed'}`);
    return report;
  }
  const label = report.rotated ? 'rotated' : report.created ? 'created' : 'unchanged';
  console.log(`${color.green('Ed25519 keypair')} ${label}`);
  console.log(`  private: ${report.privateKeyPath}`);
  console.log(`  public: ${report.publicKeyPath}`);
  console.log(`  fingerprint: ${report.fingerprint}`);
  console.log(color.dim('Next: agent-receipt sign'));
  return report;
}

export function printKeygenError(reason: string): void {
  console.log(
    JSON.stringify({
      ok: false,
      command: 'keygen',
      version: VERSION,
      exitCode: 1,
      fingerprint: null,
      privateKeyPath: null,
      publicKeyPath: null,
      created: false,
      rotated: false,
      reason,
    } satisfies KeygenReport),
  );
}

/**
 * Create a local Ed25519 keypair under `.agent-receipt/keys/`.
 * Idempotent when both keys already exist. `--force` overwrites.
 * No network. The private key is never printed.
 */
export function cmdKeygen(cwd: string, opts: KeygenOptions = {}): KeygenReport {
  const privPath = privateKeyPath(cwd);
  const pubPath = publicKeyPath(cwd);
  const havePriv = existsSync(privPath);
  const havePub = existsSync(pubPath);
  const json = Boolean(opts.json);

  if (havePriv && havePub && !opts.force) {
    try {
      const keys = loadKeys(cwd);
      return emit(
        {
          ok: true,
          command: 'keygen',
          version: VERSION,
          exitCode: 0,
          fingerprint: keys.fingerprint,
          privateKeyPath: privPath,
          publicKeyPath: pubPath,
          created: false,
          rotated: false,
          reason: null,
        },
        json,
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      return emit(
        {
          ok: false,
          command: 'keygen',
          version: VERSION,
          exitCode: 1,
          fingerprint: null,
          privateKeyPath: privPath,
          publicKeyPath: pubPath,
          created: false,
          rotated: false,
          reason: `${detail} Pass --force to rotate.`,
        },
        json,
      );
    }
  }

  if ((havePriv || havePub) && !opts.force) {
    const which = havePriv ? 'private key exists, public key missing' : 'public key exists, private key missing';
    return emit(
      {
        ok: false,
        command: 'keygen',
        version: VERSION,
        exitCode: 1,
        fingerprint: null,
        privateKeyPath: privPath,
        publicKeyPath: pubPath,
        created: false,
        rotated: false,
        reason: `Ed25519 keypair is incomplete (${which}). Run \`agent-receipt keygen --force\` to rotate.`,
      },
      json,
    );
  }

  try {
    const written = writeKeyPair(cwd);
    const rotated = Boolean(opts.force && (havePriv || havePub));
    return emit(
      {
        ok: true,
        command: 'keygen',
        version: VERSION,
        exitCode: 0,
        fingerprint: written.fingerprint,
        privateKeyPath: privPath,
        publicKeyPath: pubPath,
        created: !rotated,
        rotated,
        reason: null,
      },
      json,
    );
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return emit(
      {
        ok: false,
        command: 'keygen',
        version: VERSION,
        exitCode: 1,
        fingerprint: null,
        privateKeyPath: privPath,
        publicKeyPath: pubPath,
        created: false,
        rotated: false,
        reason: detail,
      },
      json,
    );
  }
}
