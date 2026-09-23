import { existsSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { color } from '../lib/color.js';
import { finalizeGate, printGate, riskToGate, type GateReport } from '../lib/gate.js';
import type { FailOnThreshold } from '../lib/risk.js';
import {
  RECEIPT_HTML_NAME,
  RECEIPT_MD_NAME,
  SharePackageUsageError,
  checkSharePackageFiles,
  inspectManifestSignature,
  loadShareManifest,
  locateSharePackage,
  type ManifestSigReport,
  type ShareManifest,
} from '../lib/share-package.js';
import {
  ABSENT_SIGNATURE,
  inspectReceiptSignature,
  signaturePathFor,
  type SignatureStatus,
} from '../lib/sign.js';
import { applyTrust, loadTrustedFingerprints } from '../lib/trust.js';
import { cmdVerify } from './verify.js';

export interface VerifyPackageOptions {
  /** Print one gate object. Suppresses the human banner. */
  json?: boolean;
  /** Suppress stdout. Callers that print their own summary set this. */
  quiet?: boolean;
  /** Explicit `--fail-on` only. Config failOn is not applied. */
  failOn?: FailOnThreshold;
  /**
   * After the package checks, require a valid receipt sidecar. When a
   * known-keys allowlist is active, the fingerprint must be trusted.
   */
  requireSig?: boolean;
  /** Extra fingerprints for this invocation (`--trusted-key`). */
  trustedKeys?: string[];
}

export interface PackageVerifyReport {
  ok: boolean;
  command: 'verify' | 'import';
  exitCode: 0 | 2;
  path: string;
  packagePath: string;
  sha256: string | null;
  verified: boolean;
  signed: boolean;
  fingerprint: string | null;
  filesOk: boolean;
  manifestOk: boolean;
  manifestSig: ManifestSigReport;
  signature: SignatureStatus;
  reason: string | null;
  receiptPath: string;
  htmlPath: string;
  trailingIgnored: boolean | null;
  failedOn: boolean;
  redacted: boolean;
  risk: GateReport['risk'];
  failOn: string | null;
  /** Set by import. Omitted from verify JSON. */
  importPath?: string | null;
  importSigPath?: string | null;
  dryRun?: boolean;
}

/**
 * Fail-closed check of a share package: manifest shape, file byte hashes,
 * receipt integrity, optional receipt sidecar, optional manifest sidecar.
 * HTML is hashed as a file. It is not treated as signed.
 * Malformed input throws SharePackageUsageError (exit 1). Integrity
 * failures return exitCode 2.
 */
export function cmdVerifyPackage(
  cwd: string,
  pathArg: string | undefined,
  opts: VerifyPackageOptions = {},
): PackageVerifyReport {
  const report = verifySharePackage(cwd, pathArg, opts);
  if (!opts.quiet) emitPackageReport(report, { json: Boolean(opts.json) });
  return report;
}

export function verifySharePackage(
  cwd: string,
  pathArg: string | undefined,
  opts: VerifyPackageOptions = {},
): PackageVerifyReport {
  if (!pathArg) {
    throw new SharePackageUsageError(
      'verify --package requires a share package directory or manifest.json.',
    );
  }
  const loc = locateSharePackage(cwd, pathArg);
  if (loc.inputKind === 'missing' || !existsSync(loc.inputPath)) {
    throw new SharePackageUsageError(`share package not found: ${loc.inputPath}`);
  }
  if (loc.inputKind === 'other') {
    throw new SharePackageUsageError(
      `not a share package: ${loc.inputPath}. Pass a directory that contains manifest.json, or manifest.json itself.`,
    );
  }
  if (!loc.manifestExists) {
    throw new SharePackageUsageError(`manifest.json not found in ${loc.packageDir}`);
  }
  const manifest = loadShareManifest(loc.manifestPath);
  return assessPackage(cwd, loc.packageDir, manifest, opts);
}

function assessPackage(
  cwd: string,
  packageDir: string,
  manifest: ShareManifest,
  opts: VerifyPackageOptions,
): PackageVerifyReport {
  const receiptPath = join(packageDir, RECEIPT_MD_NAME);
  const htmlPath = join(packageDir, RECEIPT_HTML_NAME);
  const fileCheck = checkSharePackageFiles(packageDir, manifest);

  let computedSha: string | null = null;
  let receiptOk = false;
  let receiptReason = '';
  let trailingIgnored: boolean | null = null;
  let failedOn = false;
  let risk: GateReport['risk'] = null;
  let redacted = manifest.redacted;

  if (isRegularFile(receiptPath)) {
    const checked = cmdVerify(cwd, receiptPath, {
      quiet: true,
      failOn: opts.failOn,
    });
    computedSha = checked.sha256;
    receiptOk = checked.ok;
    receiptReason = checked.reason;
    trailingIgnored = checked.trailingIgnored;
    failedOn = checked.failedOn;
    risk = riskToGate(checked.risk);
    redacted = checked.redacted || manifest.redacted;
  } else if (!fileCheck.reasons.some((r) => r === 'missing package file: receipt.md')) {
    receiptReason = 'missing package file: receipt.md';
  }

  const shaMatches = Boolean(computedSha && computedSha === manifest.sha256);
  const verified = Boolean(receiptOk && shaMatches);
  const manifestOk = shaMatches;
  const signatureEval = evaluatePackageSignature(cwd, receiptPath, computedSha, opts);
  const manifestSig = inspectManifestSignature(packageDir);
  const manifestSigFailed = manifestSig.present && manifestSig.ok !== true;

  const reasons: string[] = [];
  if (!fileCheck.ok) reasons.push(...fileCheck.reasons);
  if (computedSha && receiptOk && !shaMatches) {
    reasons.push('manifest sha256 does not match receipt hash');
  } else if (!receiptOk && receiptReason) {
    reasons.push(receiptReason);
  } else if (!computedSha && !fileCheck.reasons.some((r) => r.includes('receipt.md'))) {
    reasons.push('missing package file: receipt.md');
  }
  if (signatureEval.failed && signatureEval.signature.reason) {
    reasons.push(signatureEval.signature.reason);
  }
  if (manifestSigFailed) {
    reasons.push(manifestSig.reason || 'manifest signature invalid');
  }
  if (failedOn && receiptReason && !reasons.includes(receiptReason)) {
    reasons.push(receiptReason);
  }

  const exitCode: 0 | 2 =
    !fileCheck.ok || !verified || signatureEval.failed || manifestSigFailed || failedOn ? 2 : 0;
  const reason = reasons.length ? reasons.join('; ') : null;

  return {
    ok: exitCode === 0,
    command: 'verify',
    exitCode,
    path: packageDir,
    packagePath: packageDir,
    sha256: computedSha ?? manifest.sha256,
    verified,
    signed: manifest.signed,
    fingerprint: manifest.fingerprint,
    filesOk: fileCheck.ok,
    manifestOk,
    manifestSig,
    signature: signatureEval.signature,
    reason,
    receiptPath,
    htmlPath,
    trailingIgnored,
    failedOn,
    redacted,
    risk,
    failOn: opts.failOn ?? null,
  };
}

function isRegularFile(filePath: string): boolean {
  try {
    return lstatSync(filePath).isFile();
  } catch {
    return false;
  }
}

function evaluatePackageSignature(
  cwd: string,
  receiptPath: string,
  computedSha: string | null,
  opts: VerifyPackageOptions,
): { signature: SignatureStatus; failed: boolean } {
  const inspected = computedSha
    ? inspectReceiptSignature(receiptPath, computedSha)
    : { ...ABSENT_SIGNATURE };
  if (!computedSha && existsSync(signaturePathFor(receiptPath))) {
    return {
      signature: {
        present: true,
        ok: false,
        alg: null,
        fingerprint: null,
        reason: 'signature present but receipt hash was not computed',
        trusted: null,
      },
      failed: true,
    };
  }
  if (!inspected.present) {
    if (opts.requireSig) {
      return {
        signature: {
          present: false,
          ok: false,
          alg: null,
          fingerprint: null,
          reason: 'signature required: signature absent',
          trusted: null,
        },
        failed: true,
      };
    }
    return { signature: inspected, failed: false };
  }
  if (inspected.ok !== true) {
    return { signature: inspected, failed: true };
  }
  if (opts.requireSig) {
    const trusted = applyTrust(
      inspected,
      loadTrustedFingerprints(cwd, { extra: opts.trustedKeys }),
    );
    return { signature: trusted, failed: trusted.ok !== true };
  }
  return { signature: inspected, failed: false };
}

export function packageGate(report: PackageVerifyReport): GateReport {
  const importing = report.command === 'import';
  return finalizeGate({
    command: report.command,
    exitCode: report.exitCode,
    verified: report.verified,
    failedOn: report.failedOn,
    failOn: report.failOn,
    redacted: report.redacted,
    uncommitted: null,
    path: report.path,
    jsonPath: null,
    htmlPath: report.htmlPath,
    markdownPath: report.receiptPath,
    tldr: null,
    sha256: report.sha256,
    risk: report.risk,
    ignored: null,
    trailingIgnored: report.trailingIgnored,
    reason: report.reason,
    signature: report.signature,
    packagePath: report.packagePath,
    signed: report.signed,
    fingerprint: report.fingerprint,
    filesOk: report.filesOk,
    manifestOk: report.manifestOk,
    manifestSig: report.manifestSig,
    ...(importing
      ? {
          importPath: report.importPath ?? null,
          importSigPath: report.importSigPath ?? null,
          dryRun: Boolean(report.dryRun),
        }
      : {}),
  });
}

export function emitPackageReport(report: PackageVerifyReport, opts: { json?: boolean }): void {
  if (opts.json) {
    printGate(packageGate(report));
    return;
  }
  const banner = report.exitCode === 0 ? color.green('VERIFIED') : color.red('FAILED');
  const fp = report.fingerprint ?? '(none)';
  const lines = [
    `${banner}  ${report.packagePath}`,
    `  sha256: ${report.sha256 ?? ''}`,
    `  signed: ${report.signed ? 'true' : 'false'}`,
    `  fingerprint: ${fp}`,
    `  files: ${report.filesOk ? 'ok' : 'FAIL'}`,
    `  receipt: ${report.verified ? 'ok' : 'FAIL'}`,
    `  signature: ${formatSignature(report.signature)}`,
    `  manifestSig: ${formatManifestSig(report.manifestSig)}`,
  ];
  if (report.reason) lines.push(`  reason: ${report.reason}`);
  if (report.command === 'import') {
    if (report.exitCode === 0 && report.importPath) {
      const label = report.dryRun ? 'dry-run' : 'imported';
      lines.push(`  ${label}: ${report.importPath}`);
      if (report.importSigPath) lines.push(`  ${label} sig: ${report.importSigPath}`);
    } else if (report.exitCode !== 0) {
      lines.push('  import: refused');
    }
  }
  lines.push(`  tip: open ${report.htmlPath}`);
  console.log(lines.join('\n'));
}

function formatSignature(signature: SignatureStatus): string {
  if (!signature.present) return 'absent';
  if (signature.ok === true) {
    const trust = signature.trusted === true ? ' trusted' : '';
    return `ok ${signature.alg ?? 'ed25519'} ${signature.fingerprint ?? ''}${trust}`.trim();
  }
  return signature.reason ? `FAIL ${signature.reason}` : 'FAIL';
}

function formatManifestSig(sig: ManifestSigReport): string {
  if (!sig.present) return 'absent';
  if (sig.ok === true) return `ok ${sig.fingerprint ?? ''}`.trim();
  return sig.reason ? `FAIL ${sig.reason}` : 'FAIL';
}
