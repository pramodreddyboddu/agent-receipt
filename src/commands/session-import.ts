import { randomBytes } from 'node:crypto';
import {
  copyFileSync,
  constants,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { ByteLimitError, assertReadableSize, resolveByteLimits, type ByteLimits } from '../lib/byte-limit.js';
import { color } from '../lib/color.js';
import { ensureOutDir, loadConfig } from '../lib/config.js';
import { verifyMarkdown } from '../lib/hash.js';
import { parseLinkMeta, validateLegacySession } from '../lib/link.js';
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
  /** Override the receipt read cap. Default 32 MiB. Stat before read. */
  maxReceiptBytes?: number;
  /** Override the sidecar read cap. Default 256 KiB. */
  maxSidecarBytes?: number;
  /** Override the manifest read cap. Default 8 MiB. */
  maxManifestBytes?: number;
  /**
   * Test seam. Throw after this many files have been copied into the
   * staging directory and before any final name is published. Cleans the
   * stage so outDir is unchanged.
   */
  failAfterStageCopies?: number;
}

export interface SessionImportFile {
  action: 'copy' | 'skip' | 'conflict' | 'symlink';
  id: string;
  sha256: string;
  from: string;
  to: string;
  reason: string | null;
  fingerprint: string | null;
  originalFingerprint: string | null;
  resignedBy: string | null;
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
 * basename (case-insensitive) with a different sha256 refuses the whole
 * import and writes nothing. A symlink destination, or a symlink parent
 * inside outDir, exits 2 and writes nothing. Files are staged inside
 * outDir and published with exclusive no-overwrite semantics. An existing
 * destination, including a stray sidecar, is a conflict unless it is a
 * byte-identical skip. An unreadable destination is a conflict. Does not
 * append the audit log and does not add an index row. `session <id>`
 * lists the copied receipts because they keep their Session id.
 */
export function cmdSessionImport(
  cwd: string,
  pathArg: string | undefined,
  opts: SessionImportOptions = {},
): SessionImportReport {
  const dryRun = Boolean(opts.dryRun);
  const requireSig = Boolean(opts.requireSig);
  const limits = resolveByteLimits(opts);
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
    manifest = loadSessionManifest(loc.manifestPath, limits.maxManifestBytes);
    validateLegacySession(manifest.session);
    packageDir = loc.packageDir;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const code = err instanceof ByteLimitError ? 2 : 1;
    return finish(failedReport(code, null, pathArg, message));
  }

  const assessed = assessSessionPackage(cwd, packageDir, manifest, opts, limits);
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

  const configuredOut = receiptsDir(cwd);
  const outLink = symlinkReason(configuredOut);
  if (outLink) {
    return finish({
      exitCode: 2,
      session: manifest.session,
      packagePath: packageDir,
      copied: 0,
      skipped: 0,
      conflicts: 0,
      written: false,
      files: [],
      manifestSig: assessed.manifestSig,
      reason: `import refused: ${outLink}`,
    });
  }
  const outDir = dryRun ? configuredOut : ensureOutDir(cwd, loadConfig(cwd).outDir);
  const planned = planMerge(packageDir, manifest, outDir, limits);
  const plan = planned.files;
  const copied = plan.filter((file) => file.action === 'copy').length;
  const skipped = plan.filter((file) => file.action === 'skip').length;
  const conflicts = plan.filter((file) => file.action === 'conflict').length;
  const symlinks = plan.filter((file) => file.action === 'symlink').length;
  if (symlinks > 0 || conflicts > 0) {
    const detail = plan
      .filter((file) => file.action === 'conflict' || file.action === 'symlink')
      .map((file) => file.reason || file.to)
      .join('; ');
    return finish({
      exitCode: symlinks > 0 ? 2 : 1,
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

  if (!dryRun && copied > 0) {
    const stage = join(outDir, `.import-staging-${randomBytes(4).toString('hex')}`);
    const published: string[] = [];
    try {
      mkdirSync(stage, { recursive: false });
      const jobs = stageJobs(plan, planned.sidecars, stage);
      let stagedCopies = 0;
      for (const job of jobs) {
        copyFileSync(job.from, job.stage);
        stagedCopies += 1;
        if (
          opts.failAfterStageCopies !== undefined &&
          stagedCopies >= opts.failAfterStageCopies
        ) {
          throw new Error('simulated mid-copy failure');
        }
      }
      for (const job of jobs) {
        publishExclusive(job.stage, job.to);
        published.push(job.to);
      }
    } catch (err) {
      for (const path of published) {
        try {
          if (lstatSync(path).isFile()) unlinkSync(path);
        } catch {
          /* already gone */
        }
      }
      rmSync(stage, { recursive: true, force: true });
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
    rmSync(stage, { recursive: true, force: true });
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
  limits: ByteLimits,
): AssessedPackage {
  const reasons: string[] = [];
  let manifestSig: ManifestSigReport;
  try {
    manifestSig = inspectSessionManifestSignature(packageDir, {
      manifest: limits.maxManifestBytes,
      sidecar: limits.maxSidecarBytes,
    });
  } catch (err) {
    if (err instanceof ByteLimitError) {
      return { exitCode: 2, reason: err.message, manifestSig: ABSENT_MANIFEST_SIG };
    }
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 2, reason: message, manifestSig: ABSENT_MANIFEST_SIG };
  }
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
    try {
      reasons.push(...checkReceipt(cwd, packageDir, manifest, entry, opts, store, limits));
    } catch (err) {
      if (err instanceof ByteLimitError) {
        reasons.push(err.message);
      } else {
        const message = err instanceof Error ? err.message : String(err);
        reasons.push(message);
      }
    }
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
  limits: ByteLimits,
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
  assertReadableSize(receiptAbs, limits.maxReceiptBytes, `receipt ${entry.path}`, '--max-receipt-bytes');
  const actualBytes = sha256FileBytes(receiptAbs);
  if (actualBytes !== entry.bytes) {
    reasons.push(`file hash mismatch: ${entry.path}`);
  }

  const sigAbs = signaturePathFor(receiptAbs);
  const sigPresent = isRegularFile(sigAbs);
  if (entry.signed) {
    if (!sigPresent) {
      reasons.push(`missing package file: ${signaturePathFor(entry.path)}`);
    } else {
      assertReadableSize(
        sigAbs,
        limits.maxSidecarBytes,
        `signature sidecar ${signaturePathFor(entry.path)}`,
        '--max-sidecar-bytes',
      );
      if (entry.sigBytes && sha256FileBytes(sigAbs) !== entry.sigBytes) {
        reasons.push(`file hash mismatch: ${signaturePathFor(entry.path)}`);
      }
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
  name: string;
  sha256: string | null;
  id: string | null;
  /** Set when the file exists but cannot be read. Never treated as absent. */
  unreadable: boolean;
  /** Symlink, including dangling. Not followed. */
  symlink: boolean;
  /** Directory or other non-file. */
  other: boolean;
}

interface PlannedMerge {
  files: SessionImportFile[];
  /** Sidecars that must be published with a copied receipt. Keyed by receipt dest. */
  sidecars: Map<string, { from: string; to: string }>;
}

function planMerge(
  packageDir: string,
  manifest: SessionManifest,
  outDir: string,
  limits: ByteLimits,
): PlannedMerge {
  const local = listLocal(outDir, limits.maxReceiptBytes);
  const byId = new Map<string, LocalFile>();
  for (const file of local) {
    if (file.id && !byId.has(file.id)) byId.set(file.id, file);
  }
  const files: SessionImportFile[] = [];
  const sidecars = new Map<string, { from: string; to: string }>();
  const seenBase = new Set<string>();
  for (const entry of manifest.receipts) {
    const from = resolve(packageDir, entry.path);
    const base = basename(entry.path);
    const baseKey = base.toLowerCase();
    const dest = join(outDir, base);
    const signer = signerFields(entry);
    if (seenBase.has(baseKey)) {
      files.push({
        action: 'conflict',
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: dest,
        reason: `case-insensitive duplicate basename in package: ${base}`,
        ...signer,
      });
      continue;
    }
    seenBase.add(baseKey);

    const link = destinationSymlink(outDir, dest);
    if (link) {
      files.push({
        action: 'symlink',
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: dest,
        reason: `refusing to write through symlink ${link}`,
        ...signer,
      });
      continue;
    }

    const sameId = byId.get(entry.id);
    const nameMatches = local.filter((file) => file.name.toLowerCase() === baseKey);
    const symlinkHit = nameMatches.find((file) => file.symlink);
    if (symlinkHit) {
      files.push({
        action: 'symlink',
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: symlinkHit.path,
        reason: `refusing to write through symlink ${symlinkHit.path}`,
        ...signer,
      });
      continue;
    }
    if (nameMatches.some((file) => file.other)) {
      const other = nameMatches.find((file) => file.other) as LocalFile;
      files.push({
        action: 'conflict',
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: other.path,
        reason: `destination is not a regular file: ${other.name}`,
        ...signer,
      });
      continue;
    }
    if (sameId?.unreadable || nameMatches.some((file) => file.unreadable)) {
      const where = (sameId?.unreadable ? sameId : nameMatches.find((file) => file.unreadable)) as LocalFile;
      files.push({
        action: 'conflict',
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: where.path,
        reason: `unreadable destination is a conflict: ${basename(where.path)}`,
        ...signer,
      });
      continue;
    }
    if (sameId) {
      if (sameId.sha256 === entry.sha256) {
        files.push({
          action: 'skip',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: sameId.path,
          reason: 'same id and sha256',
          ...signer,
        });
      } else {
        files.push({
          action: 'conflict',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: sameId.path,
          reason: `id ${entry.id} already exists with a different sha256 (${basename(sameId.path)})`,
          ...signer,
        });
      }
      continue;
    }
    if (nameMatches.length > 1) {
      files.push({
        action: 'conflict',
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: dest,
        reason: `case-insensitive basename ${base} matches more than one file in outDir`,
        ...signer,
      });
      continue;
    }
    if (nameMatches.length === 1) {
      const samePath = nameMatches[0];
      if (samePath.sha256 === entry.sha256) {
        files.push({
          action: 'skip',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: samePath.path,
          reason: samePath.name === base ? 'same basename and sha256' : 'same basename (case-insensitive) and sha256',
          ...signer,
        });
      } else {
        files.push({
          action: 'conflict',
          id: entry.id,
          sha256: entry.sha256,
          from,
          to: samePath.path,
          reason: `basename ${base} already exists with a different sha256 (${samePath.name})`,
          ...signer,
        });
      }
      continue;
    }

    const sidecarPlan = planSidecar(packageDir, entry, dest, outDir, limits.maxSidecarBytes);
    if (sidecarPlan.block) {
      files.push({
        action: sidecarPlan.block.action,
        id: entry.id,
        sha256: entry.sha256,
        from,
        to: sidecarPlan.block.to,
        reason: sidecarPlan.block.reason,
        ...signer,
      });
      continue;
    }
    files.push({
      action: 'copy',
      id: entry.id,
      sha256: entry.sha256,
      from,
      to: dest,
      reason: null,
      ...signer,
    });
    if (sidecarPlan.copy) sidecars.set(dest, sidecarPlan.copy);
  }
  return { files, sidecars };
}

function signerFields(entry: SessionManifestReceipt): Pick<
  SessionImportFile,
  'fingerprint' | 'originalFingerprint' | 'resignedBy'
> {
  return {
    fingerprint: entry.fingerprint,
    originalFingerprint: entry.originalFingerprint,
    resignedBy: entry.resignedBy,
  };
}

function listLocal(outDir: string, maxBytes: number): LocalFile[] {
  let names: string[];
  try {
    names = readdirSync(outDir);
  } catch {
    return [];
  }
  const out: LocalFile[] = [];
  for (const name of names) {
    if (name.includes('/') || name.includes('\\')) continue;
    if (!name.toLowerCase().endsWith('.md')) continue;
    const filePath = join(outDir, name);
    let st;
    try {
      st = lstatSync(filePath);
    } catch {
      out.push({
        path: filePath,
        name,
        sha256: null,
        id: null,
        unreadable: true,
        symlink: false,
        other: false,
      });
      continue;
    }
    if (st.isSymbolicLink()) {
      out.push({
        path: filePath,
        name,
        sha256: null,
        id: null,
        unreadable: false,
        symlink: true,
        other: false,
      });
      continue;
    }
    if (!st.isFile()) {
      out.push({
        path: filePath,
        name,
        sha256: null,
        id: null,
        unreadable: false,
        symlink: false,
        other: true,
      });
      continue;
    }
    if (st.size > maxBytes) {
      out.push({
        path: filePath,
        name,
        sha256: null,
        id: null,
        unreadable: true,
        symlink: false,
        other: false,
      });
      continue;
    }
    let text: string;
    try {
      text = readFileSync(filePath, 'utf8');
    } catch {
      out.push({
        path: filePath,
        name,
        sha256: null,
        id: null,
        unreadable: true,
        symlink: false,
        other: false,
      });
      continue;
    }
    const sha256 = verifyMarkdown(text).actual;
    const meta = parseLinkMeta(text);
    out.push({
      path: filePath,
      name,
      sha256,
      id: meta.id,
      unreadable: false,
      symlink: false,
      other: false,
    });
  }
  return out;
}

interface SidecarBlock {
  action: 'conflict' | 'symlink';
  to: string;
  reason: string;
}

function planSidecar(
  packageDir: string,
  entry: SessionManifestReceipt,
  receiptDest: string,
  outDir: string,
  maxBytes: number,
): { block?: SidecarBlock; copy?: { from: string; to: string } } {
  const from = signaturePathFor(resolve(packageDir, entry.path));
  if (!entry.signed || !isRegularFile(from)) return {};
  const base = basename(from);
  const dest = signaturePathFor(receiptDest);
  const link = destinationSymlink(outDir, dest);
  if (link) {
    return {
      block: {
        action: 'symlink',
        to: dest,
        reason: `refusing to write through symlink ${link}`,
      },
    };
  }
  const matches = matchingNames(outDir, base, maxBytes);
  if (matches.length === 0) return { copy: { from, to: dest } };
  if (matches.length > 1) {
    return {
      block: {
        action: 'conflict',
        to: dest,
        reason: `case-insensitive basename ${base} matches more than one file in outDir`,
      },
    };
  }
  const existing = matches[0];
  if (existing.kind === 'symlink') {
    return {
      block: {
        action: 'symlink',
        to: existing.path,
        reason: `refusing to write through symlink ${existing.path}`,
      },
    };
  }
  if (existing.kind === 'unreadable') {
    return {
      block: {
        action: 'conflict',
        to: existing.path,
        reason: `unreadable destination is a conflict: ${basename(existing.path)}`,
      },
    };
  }
  if (existing.kind === 'other') {
    return {
      block: {
        action: 'conflict',
        to: existing.path,
        reason: `destination is not a regular file: ${basename(existing.path)}`,
      },
    };
  }
  const incoming = readFileSync(from);
  if (existing.bytes.equals(incoming)) return {};
  return {
    block: {
      action: 'conflict',
      to: existing.path,
      reason: `sidecar ${base} already exists and is not byte-identical (${existing.name})`,
    },
  };
}

interface NameMatch {
  path: string;
  name: string;
  kind: 'file' | 'symlink' | 'unreadable' | 'other';
  bytes: Buffer;
}

function matchingNames(dir: string, base: string, maxBytes: number): NameMatch[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const want = base.toLowerCase();
  const out: NameMatch[] = [];
  for (const name of names) {
    if (name.toLowerCase() !== want) continue;
    const path = join(dir, name);
    let st;
    try {
      st = lstatSync(path);
    } catch {
      out.push({ path, name, kind: 'unreadable', bytes: Buffer.alloc(0) });
      continue;
    }
    if (st.isSymbolicLink()) {
      out.push({ path, name, kind: 'symlink', bytes: Buffer.alloc(0) });
      continue;
    }
    if (!st.isFile()) {
      out.push({ path, name, kind: 'other', bytes: Buffer.alloc(0) });
      continue;
    }
    if (st.size > maxBytes) {
      out.push({ path, name, kind: 'unreadable', bytes: Buffer.alloc(0) });
      continue;
    }
    try {
      out.push({ path, name, kind: 'file', bytes: readFileSync(path) });
    } catch {
      out.push({ path, name, kind: 'unreadable', bytes: Buffer.alloc(0) });
    }
  }
  return out;
}

/**
 * Symlink at `dest`, or any parent of `dest` that is still inside `outDir`.
 * A missing final path is fine. Returns the symlink path when one is found.
 */
function destinationSymlink(outDir: string, dest: string): string | null {
  const root = resolve(outDir);
  const points: string[] = [];
  let cur = resolve(dest);
  while (true) {
    points.push(cur);
    if (cur === root) break;
    const parent = dirname(cur);
    if (parent === cur) break;
    const rel = relative(root, parent);
    if (rel.startsWith('..') || isAbsolute(rel)) break;
    cur = parent;
  }
  for (const point of points) {
    let st;
    try {
      st = lstatSync(point);
    } catch (err) {
      const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : '';
      if (code === 'ENOENT') continue;
      return point;
    }
    if (st.isSymbolicLink()) return point;
  }
  return null;
}

/** outDir itself is a symlink (including dangling). Missing is fine. */
function symlinkReason(outDir: string): string | null {
  try {
    if (lstatSync(outDir).isSymbolicLink()) {
      return `refusing to import into symlink outDir: ${outDir}`;
    }
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : '';
    if (code === 'ENOENT') return null;
    return `unreadable outDir ${outDir}`;
  }
  return null;
}

interface StageJob {
  from: string;
  to: string;
  stage: string;
}

function stageJobs(
  plan: SessionImportFile[],
  sidecars: Map<string, { from: string; to: string }>,
  stage: string,
): StageJob[] {
  const jobs: StageJob[] = [];
  for (const file of plan) {
    if (file.action !== 'copy') continue;
    jobs.push({
      from: file.from,
      to: file.to,
      stage: join(stage, basename(file.to)),
    });
    const sidecar = sidecars.get(file.to);
    if (sidecar) {
      jobs.push({
        from: sidecar.from,
        to: sidecar.to,
        stage: join(stage, basename(sidecar.to)),
      });
    }
  }
  return jobs;
}

/**
 * Publish `from` as `to` without overwriting. Hard-link is atomic and
 * fails with EEXIST when `to` is already there. COPYFILE_EXCL is the
 * fallback. A pre-existing file, including one created between the plan
 * and the publish, is left untouched.
 */
function publishExclusive(from: string, to: string): void {
  try {
    lstatSync(to);
    throw new Error(`refusing to overwrite ${to}`);
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('refusing to overwrite')) throw err;
    const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : '';
    if (code !== 'ENOENT') {
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(`refusing to overwrite ${to} (${detail})`);
    }
  }
  try {
    linkSync(from, to);
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : '';
    if (code === 'EEXIST') throw new Error(`refusing to overwrite ${to}`);
    copyFileSync(from, to, constants.COPYFILE_EXCL);
  }
  unlinkSync(from);
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
    else if (file.action === 'symlink') lines.push(`  symlink: ${file.reason || file.to}`);
    else lines.push(`  conflict: ${file.reason || file.to}`);
    if (file.originalFingerprint || file.resignedBy || file.fingerprint) {
      const original = file.originalFingerprint ?? 'unsigned';
      const current = file.fingerprint ?? 'unsigned';
      const resign = file.resignedBy ? ` re-signed-by: ${file.resignedBy}` : '';
      lines.push(`  signer: ${current} original: ${original}${resign}`);
    }
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
