import { copyFileSync, existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { ensureOutDir, loadConfig } from '../lib/config.js';
import { receiptsDir } from '../lib/receipt-index.js';
import { RECEIPT_MD_NAME, RECEIPT_SIG_NAME } from '../lib/share-package.js';
import { signaturePathFor } from '../lib/sign.js';
import {
  emitPackageReport,
  verifySharePackage,
  type PackageVerifyReport,
  type VerifyPackageOptions,
} from './verify-package.js';

export interface ImportOptions extends VerifyPackageOptions {
  /** Print planned paths and do not write. */
  dryRun?: boolean;
}

/** `receipt-import-<first 12 hex of the canonical sha256>.md`. */
export function importReceiptFileName(sha256: string): string {
  return `receipt-import-${sha256.slice(0, 12)}.md`;
}

/**
 * Verify a share package, then copy `receipt.md` and `receipt.sig.json`
 * (when present) into the local outDir. HTML and the manifest are not
 * copied. A failed verify copies nothing. This does not append the audit
 * log and does not add an index row.
 */
export function cmdImport(
  cwd: string,
  pathArg: string | undefined,
  opts: ImportOptions = {},
): PackageVerifyReport {
  const report = verifySharePackage(cwd, pathArg, opts);
  report.command = 'import';
  report.dryRun = Boolean(opts.dryRun);
  if (report.exitCode !== 0 || !report.sha256) {
    report.importPath = null;
    report.importSigPath = null;
    if (!opts.quiet) emitPackageReport(report, { json: Boolean(opts.json) });
    return report;
  }

  const dir = opts.dryRun ? receiptsDir(cwd) : ensureOutDir(cwd, loadConfig(cwd).outDir);
  const importPath = join(dir, importReceiptFileName(report.sha256));
  const sigSrc = join(report.packagePath, RECEIPT_SIG_NAME);
  const importSigPath = existsSync(sigSrc) ? signaturePathFor(importPath) : null;
  report.importPath = importPath;
  report.importSigPath = importSigPath;

  if (!opts.dryRun) {
    copyFileSync(join(report.packagePath, RECEIPT_MD_NAME), importPath);
    if (importSigPath) {
      copyFileSync(sigSrc, importSigPath);
    } else {
      const stale = signaturePathFor(importPath);
      if (existsSync(stale)) unlinkSync(stale);
    }
  }

  if (!opts.quiet) emitPackageReport(report, { json: Boolean(opts.json) });
  return report;
}
