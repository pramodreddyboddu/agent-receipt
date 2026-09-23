import { color } from '../lib/color.js';
import { VERSION } from '../lib/version.js';
import {
  createSignatureDocument,
  loadKeys,
  writeSignatureSidecar,
} from '../lib/sign.js';
import { cmdVerify } from './verify.js';

export interface SignOptions {
  /** One JSON object on stdout. */
  json?: boolean;
}

export interface SignReport {
  ok: boolean;
  command: 'sign';
  version: string;
  exitCode: 0 | 1 | 2;
  verified: boolean | null;
  path: string | null;
  sigPath: string | null;
  sha256: string | null;
  fingerprint: string | null;
  reason: string | null;
}

function emit(report: SignReport, json: boolean): SignReport {
  if (json) {
    console.log(JSON.stringify(report));
    return report;
  }
  if (report.exitCode === 0) {
    console.log(`${color.green('SIGNED')}  ${report.path ?? ''}`);
    console.log(`  sha256: ${report.sha256 ?? ''}`);
    console.log(`  fingerprint: ${report.fingerprint ?? ''}`);
    console.log(`  sig: ${report.sigPath ?? ''}`);
    return report;
  }
  if (report.exitCode === 2) {
    console.log(`${color.red('FAILED')}  ${report.path ?? ''}`);
    console.log('  verified: no');
    if (report.sha256) console.log(`  sha256: ${report.sha256}`);
    if (report.reason) console.log(`  reason: ${report.reason}`);
    console.log(color.dim('No signature sidecar was written.'));
    return report;
  }
  console.error(color.red('Error:') + ` ${report.reason ?? 'sign failed'}`);
  return report;
}

export function printSignError(reason: string): void {
  console.log(
    JSON.stringify({
      ok: false,
      command: 'sign',
      version: VERSION,
      exitCode: 1,
      verified: null,
      path: null,
      sigPath: null,
      sha256: null,
      fingerprint: null,
      reason,
    } satisfies SignReport),
  );
}

/**
 * Hash-check the receipt, then write `foo.sig.json` beside `foo.md`.
 * Signs the sha256 hex string (UTF-8), not the Markdown. Does not run from
 * capture, wrap, or share. Exit 2 on hash failure writes nothing.
 * Exit 1 when keys or the receipt are missing.
 */
export function cmdSign(cwd: string, pathArg?: string, opts: SignOptions = {}): SignReport {
  const json = Boolean(opts.json);
  const verified = cmdVerify(cwd, pathArg, { quiet: true });
  if (!verified.ok) {
    return emit(
      {
        ok: false,
        command: 'sign',
        version: VERSION,
        exitCode: 2,
        verified: false,
        path: verified.path,
        sigPath: null,
        sha256: verified.sha256,
        fingerprint: null,
        reason: verified.reason || 'Hash mismatch — receipt may have been tampered with',
      },
      json,
    );
  }

  let keys;
  try {
    keys = loadKeys(cwd);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return emit(
      {
        ok: false,
        command: 'sign',
        version: VERSION,
        exitCode: 1,
        verified: true,
        path: verified.path,
        sigPath: null,
        sha256: verified.sha256,
        fingerprint: null,
        reason: detail,
      },
      json,
    );
  }

  const doc = createSignatureDocument(verified.sha256, keys);
  const sigPath = writeSignatureSidecar(verified.path, doc);
  return emit(
    {
      ok: true,
      command: 'sign',
      version: VERSION,
      exitCode: 0,
      verified: true,
      path: verified.path,
      sigPath,
      sha256: verified.sha256,
      fingerprint: keys.fingerprint,
      reason: null,
    },
    json,
  );
}
