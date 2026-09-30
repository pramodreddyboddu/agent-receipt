import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { ByteLimitError, assertReadableSize, resolveByteLimits } from '../lib/byte-limit.js';
import { color } from '../lib/color.js';
import { verifyMarkdown } from '../lib/hash.js';
import { parseLinkMeta, type SessionNode } from '../lib/link.js';
import { receiptsDir } from '../lib/receipt-index.js';
import {
  SESSION_MANIFEST_NAME,
  SESSION_MANIFEST_SIG_NAME,
  SESSION_RECEIPTS_DIR,
  SESSION_WARNING_CYCLE,
  SESSION_WARNING_ORPHAN,
  ensurePackageParent,
  isRegularFile,
  isSafeReceiptBasename,
  partialPackageDir,
  publishSessionReceipt,
  removeTree,
  resolveSessionPackageDir,
  signSessionManifest,
  writeSessionManifest,
  type SessionManifest,
  type SessionManifestReceipt,
} from '../lib/session-package.js';
import { sha256FileBytes, fingerprintFromSidecar } from '../lib/share-package.js';
import {
  handoffMarkdownSignature,
  inspectReceiptSignature,
  loadKeys,
  signaturePathFor,
} from '../lib/sign.js';
import { VERSION } from '../lib/version.js';
import { collectSession } from './session.js';

export interface SessionExportOptions {
  json?: boolean;
  /** Package directory. Default is the sibling of outDir, `<id>.session`. */
  out?: string;
  /**
   * Keep the original receipt bytes, including Host and any secrets.
   * Default runs share's redaction pipeline (secrets, nested receipt/index
   * bodies, and Host) and re-hashes.
   */
  includeHost?: boolean;
  /**
   * Re-sign a receipt whose sidecar was produced by a different key when
   * redaction must change the bytes. Default refuses (exit 2, nothing
   * written). Warns on stderr when it does re-sign.
   */
  resign?: boolean;
  /** Override the receipt read cap. Default 32 MiB. Stat before read. */
  maxReceiptBytes?: number;
  /** Override the sidecar read cap. Default 256 KiB. */
  maxSidecarBytes?: number;
  /** Override the manifest read cap. Default 8 MiB. Export writes the manifest; the cap is recorded for peers. */
  maxManifestBytes?: number;
}

export interface SessionExportReceipt {
  id: string;
  parent: string | null;
  agent: string | null;
  host: string | null;
  path: string;
  sha256: string;
  signed: boolean;
  fingerprint: string | null;
  originalFingerprint: string | null;
  resignedBy: string | null;
  orphan: boolean;
  cycle: boolean;
  warnings: string[];
}

export interface SessionExportReport {
  ok: boolean;
  command: 'session-export';
  version: string;
  exitCode: 0 | 1 | 2;
  session: string;
  packagePath: string | null;
  manifestPath: string | null;
  manifestSigPath: string | null;
  receiptCount: number;
  includeHost: boolean;
  written: boolean;
  warnings: string[];
  receipts: SessionExportReceipt[];
  reason: string | null;
}

const RESIGN_TIP =
  'a rewritten receipt was left unsigned (no stale sidecar). Run `agent-receipt keygen` to sign the package.';

/**
 * Pack every local receipt in a session into `<id>.session/` beside outDir.
 * Verifies first. A failure writes nothing. Unless `--include-host`, each
 * receipt goes through share's redaction pipeline (secrets, nested
 * receipt/index bodies, and Host) and is re-hashed. `--include-host`
 * keeps the original bytes. A rewritten body whose sidecar fingerprint is
 * not the local key is refused unless `--resign`. An unchanged body keeps
 * the original sidecar. A same-key rewrite is re-signed when local keys
 * load and left unsigned when they do not. Missing keys omit
 * `session-manifest.sig.json` and do not exit 2. Does not append the
 * audit log and does not edit the index. Cycles and orphans are included
 * and named in `warnings`.
 */
export function cmdSessionExport(
  cwd: string,
  sessionId: string | undefined,
  opts: SessionExportOptions = {},
): SessionExportReport {
  const includeHost = opts.includeHost === true;
  const resign = opts.resign === true;
  const limits = resolveByteLimits(opts);
  const finish = (partial: Omit<SessionExportReport, 'command' | 'version' | 'ok' | 'includeHost'> & {
    includeHost?: boolean;
  }): SessionExportReport => {
    const report: SessionExportReport = {
      command: 'session-export',
      version: VERSION,
      ok: partial.exitCode === 0,
      includeHost,
      ...partial,
    };
    emitExport(report, Boolean(opts.json));
    return report;
  };

  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    return finish(emptyReport(
      '',
      1,
      'session export requires an id. Usage: agent-receipt session export <id> [--out <dir>] [--include-host] [--resign] [--json]',
    ));
  }

  let collected;
  try {
    collected = collectSession(cwd, sessionId, { maxBytes: limits.maxReceiptBytes });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const code = err instanceof ByteLimitError ? 2 : 1;
    return finish(emptyReport(sessionId.trim(), code, message));
  }

  const session = collected.session;
  if (collected.empty) {
    return finish(emptyReport(session, 1, `no receipts in session ${session}`));
  }

  const failed = collected.nodes.filter((node) => !node.verified);
  if (failed.length) {
    const detail = failed
      .map((node) => `${basename(node.path)} (${node.id})`)
      .join(', ');
    return finish(emptyReport(
      session,
      2,
      `refusing to export: receipt failed verify: ${detail}`,
    ));
  }

  let packagePath: string;
  try {
    packagePath = resolveSessionPackageDir(cwd, session, opts.out);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return finish(emptyReport(session, 1, message));
  }
  if (existsSync(packagePath)) {
    return finish({
      ...emptyReport(session, 1, `session package already exists: ${packagePath}`),
      packagePath,
    });
  }
  const outDir = receiptsDir(cwd);
  if (packagePath === outDir) {
    return finish(emptyReport(session, 1, 'session export --out must not be the receipt outDir'));
  }

  const relBySource = allocateRelPaths(collected.nodes);
  const prepared: Array<{
    node: SessionNode;
    rel: string;
    markdown: string;
    sourceSha: string;
    masked: boolean;
    /** Valid source sidecar fingerprint, or null when the source is unsigned. */
    sourceFingerprint: string | null;
    /** Source sidecar was signed by a key that is not the local key. */
    foreign: boolean;
  }> = [];
  let resignTip = false;
  const localFp = localFingerprint(cwd);

  for (const node of collected.nodes) {
    let original: string;
    try {
      assertReadableSize(
        node.path,
        limits.maxReceiptBytes,
        `receipt ${basename(node.path)}`,
        '--max-receipt-bytes',
      );
      const sourceSig = signaturePathFor(node.path);
      const sigKind = sidecarKind(sourceSig);
      if (sigKind === 'other') {
        return finish(emptyReport(
          session,
          2,
          `refusing to export: signature sidecar for ${basename(node.path)} is not a regular file`,
        ));
      }
      if (sigKind === 'file') {
        assertReadableSize(
          sourceSig,
          limits.maxSidecarBytes,
          `signature sidecar ${basename(sourceSig)}`,
          '--max-sidecar-bytes',
        );
      }
      original = readFileSync(node.path, 'utf8');
    } catch (err) {
      if (err instanceof ByteLimitError) {
        return finish(emptyReport(session, 2, err.message));
      }
      const detail = err instanceof Error ? err.message : String(err);
      return finish(emptyReport(session, 2, `unreadable receipt ${node.path} (${detail})`));
    }
    const source = verifyMarkdown(original);
    if (!source.ok) {
      return finish(emptyReport(
        session,
        2,
        `refusing to export: receipt failed verify: ${node.path} (${source.reason})`,
      ));
    }
    const sidecar = inspectReceiptSignature(node.path, source.actual);
    if (sidecar.present && sidecar.ok !== true) {
      return finish(emptyReport(
        session,
        2,
        `refusing to export: invalid signature sidecar for ${basename(node.path)} (${sidecar.reason})`,
      ));
    }
    const published = publishSessionReceipt(original, includeHost);
    const publishedCheck = verifyMarkdown(published.markdown);
    if (!publishedCheck.ok) {
      return finish(emptyReport(
        session,
        2,
        `refusing to export: packaged receipt failed verify: ${node.path} (${publishedCheck.reason})`,
      ));
    }
    const sourceFingerprint = sidecar.present && sidecar.ok === true ? sidecar.fingerprint : null;
    const foreign = Boolean(sourceFingerprint && sourceFingerprint !== localFp);
    prepared.push({
      node,
      rel: relBySource.get(node.path) as string,
      markdown: published.markdown,
      sourceSha: source.actual,
      masked: published.masked,
      sourceFingerprint,
      foreign,
    });
  }

  const foreignRewrites = prepared.filter((item) => item.masked && item.foreign);
  if (foreignRewrites.length && !resign) {
    const detail = foreignRewrites
      .map((item) => `${basename(item.node.path)} (signer ${item.sourceFingerprint})`)
      .join(', ');
    return finish(emptyReport(
      session,
      2,
      `refusing to re-sign ${detail}: the sidecar was signed by a different key. Pass --resign to re-sign with the local key and record both fingerprints. Nothing was written.`,
    ));
  }

  const tmp = partialPackageDir(packagePath);
  try {
    ensurePackageParent(packagePath);
    mkdirSync(join(tmp, SESSION_RECEIPTS_DIR), { recursive: true });
    const entries: SessionManifestReceipt[] = [];
    for (const item of prepared) {
      const dest = join(tmp, item.rel);
      writeFileSync(dest, item.markdown, 'utf8');
      const check = verifyMarkdown(item.markdown);
      if (!check.ok) {
        throw new Error(`packaged receipt failed verify: ${item.rel} (${check.reason})`);
      }
      const handoff = handoffMarkdownSignature({
        cwd,
        sourcePath: item.node.path,
        sourceSha256: item.sourceSha,
        publishedPath: dest,
        publishedSha256: check.actual,
      });
      if (item.masked && !handoff.sigPath) resignTip = true;
      const meta = parseLinkMeta(item.markdown);
      const warnings = packageWarnings(item.node);
      const signed = Boolean(handoff.sigPath && isRegularFile(handoff.sigPath));
      const fingerprint = signed ? fingerprintFromSidecar(handoff.sigPath) : null;
      if (signed && !fingerprint) {
        throw new Error(`signed receipt is missing a fingerprint: ${item.rel}`);
      }
      const resignedBy =
        item.masked && item.sourceFingerprint && fingerprint && fingerprint !== item.sourceFingerprint
          ? fingerprint
          : null;
      if (resign && item.masked && item.foreign) {
        const next = fingerprint ?? '(unsigned — no local key)';
        console.error(
          `warning: --resign re-signed ${item.rel}\n` +
            `  original signer: ${item.sourceFingerprint}\n` +
            `  re-signer: ${next}\n` +
            'The manifest records both fingerprints. The packaged sidecar verifies as the re-signer.',
        );
      }
      const entry: SessionManifestReceipt = {
        id: item.node.id,
        parent: meta.parent,
        agent: meta.agent,
        host: meta.host,
        path: item.rel,
        sha256: check.actual,
        bytes: sha256FileBytes(dest),
        signed,
        fingerprint,
        originalFingerprint: item.sourceFingerprint,
        resignedBy,
        orphan: item.node.orphan,
        cycle: item.node.cycle,
        warnings,
      };
      if (signed && handoff.sigPath) {
        entry.sigBytes = sha256FileBytes(handoff.sigPath);
      }
      entries.push(entry);
    }

    const warnings = unionWarnings(entries);
    const manifest: SessionManifest = {
      kind: 'agent-receipt-session',
      version: 1,
      cliVersion: VERSION,
      session,
      receiptCount: entries.length,
      includeHost,
      warnings,
      receipts: entries,
    };
    const manifestPath = writeSessionManifest(tmp, manifest);
    const signedManifest = signSessionManifest(cwd, manifestPath);
    renameSync(tmp, packagePath);

    const report = finish({
      exitCode: 0,
      session,
      packagePath,
      manifestPath: join(packagePath, SESSION_MANIFEST_NAME),
      manifestSigPath: signedManifest.sigPath
        ? join(packagePath, SESSION_MANIFEST_SIG_NAME)
        : null,
      receiptCount: entries.length,
      written: true,
      warnings,
      receipts: entries.map(toExportReceipt),
      reason: null,
    });
    if (!opts.json && resignTip) {
      console.log(color.yellow(RESIGN_TIP));
    }
    return report;
  } catch (err) {
    removeTree(tmp);
    const message = err instanceof Error ? err.message : String(err);
    return finish({
      ...emptyReport(session, 2, `session export failed (${message})`),
      packagePath: null,
    });
  }
}

function localFingerprint(cwd: string): string | null {
  try {
    return loadKeys(cwd).fingerprint;
  } catch {
    return null;
  }
}

/** `absent` when missing, `file` for a regular file, `other` for a symlink or directory. */
function sidecarKind(filePath: string): 'absent' | 'file' | 'other' {
  try {
    const st = lstatSync(filePath);
    if (st.isSymbolicLink()) return 'other';
    if (st.isFile()) return 'file';
    return 'other';
  } catch {
    return 'absent';
  }
}

function packageWarnings(node: SessionNode): string[] {
  const warnings = [...node.warnings];
  if (node.orphan && !warnings.includes(SESSION_WARNING_ORPHAN)) {
    warnings.push(SESSION_WARNING_ORPHAN);
  }
  if (node.cycle && !warnings.includes(SESSION_WARNING_CYCLE)) {
    warnings.push(SESSION_WARNING_CYCLE);
  }
  return warnings;
}

function unionWarnings(entries: SessionManifestReceipt[]): string[] {
  const out: string[] = [];
  for (const entry of entries) {
    for (const warning of entry.warnings) {
      if (!out.includes(warning)) out.push(warning);
    }
  }
  return out;
}

function allocateRelPaths(nodes: SessionNode[]): Map<string, string> {
  const used = new Set<string>();
  const out = new Map<string, string>();
  for (const node of nodes) {
    let base = basename(node.path);
    if (!isSafeReceiptBasename(base) || used.has(base)) {
      const stem = node.id.replace(/[^a-z0-9]/gi, '').slice(0, 32) || 'receipt';
      base = `receipt-${stem}.md`;
      let n = 2;
      while (!isSafeReceiptBasename(base) || used.has(base)) {
        base = `receipt-${stem}-${n}.md`;
        n += 1;
      }
    }
    used.add(base);
    out.set(node.path, `${SESSION_RECEIPTS_DIR}/${base}`);
  }
  return out;
}

function toExportReceipt(entry: SessionManifestReceipt): SessionExportReceipt {
  return {
    id: entry.id,
    parent: entry.parent,
    agent: entry.agent,
    host: entry.host,
    path: entry.path,
    sha256: entry.sha256,
    signed: entry.signed,
    fingerprint: entry.fingerprint,
    originalFingerprint: entry.originalFingerprint,
    resignedBy: entry.resignedBy,
    orphan: entry.orphan,
    cycle: entry.cycle,
    warnings: entry.warnings,
  };
}

function emptyReport(
  session: string,
  exitCode: 0 | 1 | 2,
  reason: string,
): Omit<SessionExportReport, 'command' | 'version' | 'ok' | 'includeHost'> {
  return {
    exitCode,
    session,
    packagePath: null,
    manifestPath: null,
    manifestSigPath: null,
    receiptCount: 0,
    written: false,
    warnings: [],
    receipts: [],
    reason,
  };
}

function emitExport(report: SessionExportReport, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(report));
    return;
  }
  if (report.exitCode !== 0 || !report.packagePath) {
    const lines = [
      `${color.red('FAILED')}  session ${report.session || '(none)'}`,
    ];
    if (report.reason) lines.push(`  reason: ${report.reason}`);
    lines.push('  package: not written');
    console.log(lines.join('\n'));
    return;
  }
  const manifestSig = report.manifestSigPath ? 'present' : 'absent';
  const lines = [
    `${color.green('VERIFIED')}  ${report.packagePath}`,
    `  session: ${report.session}`,
    `  receipts: ${report.receiptCount}`,
    `  manifestSig: ${manifestSig}`,
  ];
  if (report.warnings.length) lines.push(`  warnings: ${report.warnings.join(', ')}`);
  for (const receipt of report.receipts) {
    lines.push(`  wrote: ${receipt.path}`);
    if (receipt.signed) {
      lines.push(`  wrote sig: ${signaturePathFor(receipt.path)}`);
    }
  }
  console.log(lines.join('\n'));
}
