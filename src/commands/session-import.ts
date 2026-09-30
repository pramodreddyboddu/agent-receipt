import { copyFileSync, existsSync, readFileSync, unlinkSync } from 'node:fs';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import { color } from '../lib/color.js';
import { ensureOutDir, loadConfig } from '../lib/config.js';
import { verifyMarkdown } from '../lib/hash.js';
import { listOutDirReceipts, parseLinkMeta, validateLegacySession } from '../lib/link.js';
import { receiptsDir } from '../lib/receipt-index.js';
import {
  SESSION_WARNING_MISSING_SESSION,
  SessionPackageUsageError,
  inspectSessionManifestSignature,
  isRegularFile,
  isSafeReceiptRel,
  loadSessionManifest,
  locateSessionPackage,
  type ManifestSigReport,
  type SessionManifest,
  type SessionManifestReceipt,
} from '../lib/session-package.js';
import { sha256FileBytes } from '../lib/share-package.js';
import {
  inspectReceiptSignature,
  signaturePathFor,
} from '../lib/sign.js';
import { applyTrust, loadTrustedFingerprints } from '../lib/trust.js';
import { VERSION } from '../lib/version.js';
import { cmdVerify } from './verify.js';

export interface SessionImportOptions {
  json?: boolean;
  dryRun?: boolean;
  requireSig?: boolean;
  trustedKeys?: string[];
}

export interface SessionImportFile {
  action: 'copy' | 'skip' | 'conflict';
  id: string;
  sha256: string;
  from: string;
  to: string;
  reason: string | null;
}

export interface SessionImportReport {
  ok: boolean;
  command: 'session-import';
  version: string;
  exitCode: 0 | 1 | 2;
  session: string | null;
  packagePath: string | null;
  dryRun: boolean;
  requireSig: boolean;
  copied: number;
  skipped: number;
  conflicts: number;
  written: boolean;
  files: SessionImportFile[];
  manifestSig: ManifestSigReport;
  reason: string | null;
}

const ABSENT_MANIFEST_SIG: ManifestSigReport = {
  present: false,
  ok: null,
  fingerprint: null,
  reason: null,
};

/**
 * Verify a session package, then copy receipts and sidecars into outDir.
 * Same id and same canonical sha256 is a skip. Same id or the same
 * basename with a different sha256 refuses the whole import and writes
 * nothing. Does not append the audit log and does not add an index row.
 * `session <id>` lists the copied receipts because they keep their Session id.
 */
export function cmdSessionImport(
  cwd: string,
  pathArg: string | undefined,
  opts: SessionImportOptions = {},
): SessionImportReport {
  const dryRun = Boolean(opts.dryRun);
  const requireSig = Boolean(opts.requireSig);
  const finish = (
    partial: Omit<SessionImportReport, 'command' | 'version' | 'ok' | 'dryRun' | 'requireSig'>,
  ): SessionImportReport => {
    const report: SessionImportReport = {
      command: 'session-import',
      version: VERSION,
      ok: partial.exitCode === 0,
      dryRun,
      requireSig,
      ...partial,
    };
    emitImport(report, Boolean(opts.json));
    return report;
  };

  if (!pathArg || !pathArg.trim()) {
    return finish(failedReport(
      1,
      null,
      null,
      'session import requires a package directory. Usage: agent-receipt session import <packageDir> [--dry-run] [--json] [--require-sig]',
    ));
  }

  let packageDir: string;
  let manifest: SessionManifest;
  try {
    const loc = locateSessionPackage(cwd, pathArg);
    if (loc.inputKind === 'missing' || !existsSync(loc.inputPath)) {
      throw new SessionPackageUsageError(`session package not found: ${loc.inputPath}`);
    }
    if (loc.inputKind === 'other') {
      throw new SessionPackageUsageError(
        `not a session package: ${loc.inputPath}. Pass a directory that contains session-manifest.json, or session-manifest.json itself.`,
      );
    }
    if (!loc.manifestExists) {
      throw new SessionPackageUsageError(`session-manifest.json not found in ${loc.packageDir}`);
    }
    manifest = loadSessionManifest(loc.manifestPath);
    validateLegacySession(manifest.session);
    packageDir = loc.packageDir;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return finish(failedReport(1, null, pathArg, message));
  }

  const assessed = assessSessionPackage(cwd, packageDir, manifest, opts);
  if (assessed.exitCode !== 0) {
    return finish({
      exitCode: assessed.exitCode,
      session: manifest.session,
      packagePath: packageDir,
      copied: 0,
      skipped: 0,
      conflicts: 0,
      written: false,
      files: [],
      manifestSig: assessed.manifestSig,
      reason: assessed.reason,
    });
  }

  const outDir = dryRun ? receiptsDir(cwd) : ensureOutDir(cwd, loadConfig(cwd).outDir);
  const plan = planMerge(cwd, packageDir, manifest, outDir);
  const copied = plan.filter((file) => file.action === 'copy').length;
  const skipped = plan.filter((file) => file.action === 'skip').length;
  const conflicts = plan.filter((file) => file.action === 'conflict').length;
  if (conflicts > 0) {
    const detail = plan
      .filter((file) => file.action === 'conflict')
      .map((file) => file.reason || file.to)
      .join('; ');
    return finish({
      exitCode: 1,
      session: manifest.session,
      packagePath: packageDir,
      copied: 0,
      skipped,
      conflicts,
      written: false,
      files: plan,
      manifestSig: assessed.manifestSig,
      reason: `import refused: ${detail}`,
    });
  }

  if (!dryRun) {
    const written: string[] = [];
    try {
      for (const file of plan) {
        if (file.action !== 'copy') continue;
        copyFileSync(file.from, file.to);
        written.push(file.to);
        const sigFrom = signaturePathFor(file.from);
        const sigTo = signaturePathFor(file.to);
        if (existsSync(sigFrom) && isRegularFile(sigFrom)) {
          copyFileSync(sigFrom, sigTo);
          written.push(sigTo);
        }
      }
    } catch (err) {
      for (const path of written) {
        if (existsSync(path)) unlinkSync(path);
      }
      const message = err instanceof Error ? err.message : String(err);
      return finish({
        exitCode: 2,
        session: manifest.session,
        packagePath: packageDir,
        copied: 0,
        skipped,
        conflicts: 0,
        written: false,
        files: plan,
        manifestSig: assessed.manifestSig,
        reason: `import failed (${message})`,
      });
    }
  }

  return finish({
    exitCode: 0,
    session: manifest.session,
    packagePath: packageDir,
    copied,
    skipped,
    conflicts: 0,
    written: !dryRun && copied > 0,
    files: plan,
    manifestSig: assessed.manifestSig,
    reason: null,
  });
}

function failedReport(
  exitCode: 0 | 1 | 2,
  session: string | null,
  packagePath: string | null,
  reason: string,
): Omit<SessionImportReport, 'command' | 'version' | 'ok' | 'dryRun' | 'requireSig'> {
  return {
    exitCode,
    session,
    packagePath,
    copied: 0,
    skipped: 0,
    conflicts: 0,
    written: false,
    files: [],
    manifestSig: ABSENT_MANIFEST_SIG,
    reason,
  };
}

interface AssessedPackage {
  exitCode: 0 | 2;
  reason: string | null;
  manifestSig: ManifestSigReport;
}

function assessSessionPackage(
  cwd: string,
  packageDir: string,
  manifest: SessionManifest,
  opts: SessionImportOptions,
): AssessedPackage {
  const reasons: string[] = [];
  const manifestSig = inspectSessionManifestSignature(packageDir);
  if (manifestSig.present && manifestSig.ok !== true) {
    reasons.push(manifestSig.reason || 'session manifest signature invalid');
  } else if (opts.requireSig && !manifestSig.present) {
    reasons.push('signature required: session manifest signature absent');
  }

  const store = opts.requireSig
    ? loadTrustedFingerprints(cwd, { extra: opts.trustedKeys })
    : null;

  if (opts.requireSig && manifestSig.present && manifestSig.ok === true && store && manifestSig.fingerprint) {
    const trusted = applyTrust(
      {
        present: true,
        ok: true,
        alg: 'ed25519',
        fingerprint: manifestSig.fingerprint,
        reason: null,
        trusted: null,
      },
      store,
    );
    if (trusted.ok !== true) {
      reasons.push(trusted.reason || 'session manifest fingerprint is not trusted');
    }
  }

  for (const entry of manifest.receipts) {
    reasons.push(...checkReceipt(cwd, packageDir, manifest, entry, opts, store));
  }

  const exitCode: 0 | 2 = reasons.length ? 2 : 0;
  return {
    exitCode,
    reason: reasons.length ? reasons.join('; ') : null,
    manifestSig,
  };
}

function checkReceipt(
  cwd: string,
  packageDir: string,
  manifest: SessionManifest,
  entry: SessionManifestReceipt,
  opts: SessionImportOptions,
  store: ReturnType<typeof loadTrustedFingerprints> | null,
): string[] {
  const reasons: string[] = [];
  if (!isSafeReceiptRel(entry.path)) {
    return [`unsafe receipt path: ${entry.path}`];
  }
  const receiptAbs = resolve(packageDir, entry.path);
  const rel = relative(packageDir, receiptAbs);
  if (rel.startsWith('..') || isAbsolute(rel)) {
    return [`receipt path escapes the package: ${entry.path}`];
  }
  if (!isRegularFile(receiptAbs)) {
    return [`missing package file: ${entry.path}`];
  }
  const actualBytes = sha256FileBytes(receiptAbs);
  if (actualBytes !== entry.bytes) {
    reasons.push(`file hash mismatch: ${entry.path}`);
  }

  const sigAbs = signaturePathFor(receiptAbs);
  const sigPresent = isRegularFile(sigAbs);
  if (entry.signed) {
    if (!sigPresent) {
      reasons.push(`missing package file: ${signaturePathFor(entry.path)}`);
    } else if (entry.sigBytes && sha256FileBytes(sigAbs) !== entry.sigBytes) {
      reasons.push(`file hash mismatch: ${signaturePathFor(entry.path)}`);
    }
  } else if (existsSync(sigAbs)) {
    reasons.push(`manifest signed is false but sidecar is present: ${entry.path}`);
  }

  const checked = cmdVerify(cwd, receiptAbs, { quiet: true });
  if (!checked.ok) {
    reasons.push(checked.reason || `receipt failed verify: ${entry.path}`);
  } else if (checked.sha256 !== entry.sha256) {
    reasons.push(`canonical sha256 does not match manifest entry: ${entry.path}`);
  }

  let text = '';
  try {
    text = readFileSync(receiptAbs, 'utf8');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    reasons.push(`unreadable receipt ${entry.path} (${detail})`);
  }
  if (text) {
    const meta = parseLinkMeta(text);
    if (meta.host !== entry.host) {
      reasons.push(`manifest host does not match receipt: ${entry.path}`);
    }
    if (meta.parent !== entry.parent) {
      reasons.push(`manifest parent does not match receipt: ${entry.path}`);
    }
    if (meta.agent !== entry.agent) {
      reasons.push(`manifest agent does not match receipt: ${entry.path}`);
    }
    if (meta.id) {
      if (meta.id !== entry.id) reasons.push(`manifest id does not match receipt: ${entry.path}`);
    } else if (checked.sha256 && entry.id !== checked.sha256) {
      reasons.push(`manifest id does not match receipt hash: ${entry.path}`);
    }
    if (entry.warnings.includes(SESSION_WARNING_MISSING_SESSION)) {
      if (meta.session) {
        reasons.push(`missing-session receipt has a Session line: ${entry.path}`);
      }
    } else if (meta.session !== manifest.session) {
      reasons.push(`manifest session does not match receipt: ${entry.path}`);
    }
  }

  if (entry.signed && sigPresent && checked.sha256) {
    const inspected = inspectReceiptSignature(receiptAbs, checked.sha256);
    if (inspected.ok !== true) {
      reasons.push(inspected.reason || `invalid signature sidecar: ${entry.path}`);
    } else if (inspected.fingerprint !== entry.fingerprint) {
      reasons.push(`manifest fingerprint does not match sidecar: ${entry.path}`);
    } else if (opts.requireSig && store) {
      const trusted = applyTrust(inspected, store);
      if (trusted.ok !== true) {
        reasons.push(trusted.reason || `signature not trusted: ${entry.path}`);
      }
    }
  } else if (opts.requireSig && !entry.signed) {
    reasons.push(`signature required: signature absent (${entry.path})`);
  }

  return reasons;
}

interface LocalFile {
  path: string;
  sha256: string;
  id: string | null;
}

function planMerge(
  cwd: string,
  packageDir: string,
  manifest: SessionManifest,
  outDir: string,
): SessionImportFile[] {
  const local = listLocal(cwd);
  const byId = new Map<string, LocalFile>();
  for (const file of local) {
    if (file.id && !byId.has(file.id)) byId.set(file.id, file);
  }
  const plan: SessionImportFile[] = [];
  for (const entry of manifest.receipts) {
    const from = resolve(packageDir, entry.path);
    const base = basename(entry.path);
    const dest = join(outDir, base);
    const sameId = byId.get(entry.id);
    if (sameId) {
      if (sameId.sha256 === entry.sha256) {
        plan.push({
          action: 'skip',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: sameId.path,
          reason: 'same id and sha256',
        });
      } else {
        plan.push({
          action: 'conflict',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: sameId.path,
          reason: `id ${entry.id} already exists with a different sha256 (${basename(sameId.path)})`,
        });
      }
      continue;
    }
    const samePath = local.find((file) => file.path === dest);
    if (samePath) {
      if (samePath.sha256 === entry.sha256) {
        plan.push({
          action: 'skip',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: dest,
          reason: 'same basename and sha256',
        });
      } else {
        plan.push({
          action: 'conflict',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: dest,
          reason: `basename ${base} already exists with a different sha256`,
        });
      }
      continue;
    }
    plan.push({
      action: 'copy',
      id: entry.id,
      sha256: entry.sha256,
      from,
      to: dest,
      reason: null,
    });
  }
  return plan;
}

function listLocal(cwd: string): LocalFile[] {
  const out: LocalFile[] = [];
  for (const filePath of listOutDirReceipts(cwd)) {
    let text: string;
    try {
      text = readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    const sha256 = verifyMarkdown(text).actual;
    const meta = parseLinkMeta(text);
    out.push({ path: filePath, sha256, id: meta.id });
  }
  return out;
}

function emitImport(report: SessionImportReport, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(report));
    return;
  }
  const banner = report.exitCode === 0 ? color.green('VERIFIED') : color.red('FAILED');
  const where = report.packagePath ?? '(none)';
  const lines = [
    `${banner}  ${where}`,
    `  session: ${report.session ?? '(none)'}`,
    `  copied: ${report.copied}`,
    `  skipped: ${report.skipped}`,
    `  conflicts: ${report.conflicts}`,
    `  manifestSig: ${formatManifestSig(report.manifestSig)}`,
  ];
  if (report.dryRun) lines.push('  dry-run: true');
  const verb = report.exitCode === 0 && !report.dryRun && report.written ? 'wrote' : 'plan';
  for (const file of report.files) {
    if (file.action === 'copy') lines.push(`  ${verb}: ${file.to}`);
    else if (file.action === 'skip') lines.push(`  skip: ${file.to}`);
    else lines.push(`  conflict: ${file.reason || file.to}`);
  }
  if (report.reason) lines.push(`  reason: ${report.reason}`);
  if (report.exitCode !== 0) lines.push('  import: refused');
  console.log(lines.join('\n'));
}

function formatManifestSig(sig: ManifestSigReport): string {
  if (!sig.present) return 'absent';
  if (sig.ok === true) {
    return `ok ${sig.fingerprint ?? ''}`.trim();
  }
  return sig.reason ? `FAIL ${sig.reason}` : 'FAIL';
}
