import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { cmdExport } from './export.js';
import { cmdVerify, reportVerify } from './verify.js';
import { resolveReceiptPath } from './show.js';
import { verifyMarkdown } from '../lib/hash.js';
import { extractTldr } from '../lib/receipt.js';
import {
  meetsFailOn,
  parseRiskSummaryMarkdown,
  type FailOnThreshold,
} from '../lib/risk.js';
import { color } from '../lib/color.js';
import {
  emitLine,
  failOnReason,
  finalizeGate,
  printGate,
  riskToGate,
} from '../lib/gate.js';
import { recordAuditEvent } from '../lib/audit.js';
import {
  RECEIPT_HTML_NAME,
  RECEIPT_MD_NAME,
  buildShareManifest,
  fingerprintFromSidecar,
  resolveSharePackageDir,
  signShareManifest,
  writeShareManifest,
} from '../lib/share-package.js';

export interface ShareOptions {
  /** HTML output path. Default: sibling `.html` next to the receipt. */
  out?: string;
  /**
   * Also write Markdown. `true` → sibling `.redacted.md` (or `.export.md`
   * when not redacting). A string is an explicit path.
   */
  md?: string | boolean;
  /**
   * Mask high/secret findings before writing. Default **true** (share-safety).
   * Pass false via `--no-redact`.
   */
  redact?: boolean;
  failOn?: FailOnThreshold;
  /** One CI gate object on stdout; human summary on stderr. */
  json?: boolean;
  /**
   * Write a portable handoff directory (`<stem>.share/` by default) with
   * `receipt.html`, `receipt.md`, `manifest.json`, and optional sidecars.
   * Implies Markdown. Alias: `--pack`.
   */
  package?: boolean;
}

export interface ShareResult {
  source: string;
  htmlPath: string | null;
  markdownPath: string | null;
  tldr: string;
  verified: boolean;
  failedOn: boolean;
  redacted: boolean;
  sha256: string | null;
  exitCode: 0 | 2;
  /** Sidecar copied or re-signed beside published Markdown. Null otherwise. */
  sigPath: string | null;
  /** Handoff directory when `--package` wrote one. Null otherwise. */
  packagePath: string | null;
}

function sibling(source: string, suffix: string): string {
  return source.replace(/\.md$/i, '') + suffix;
}

function peerPackageTip(packageDir: string, markdownPath: string): string[] {
  return [
    'Peers: open the HTML (unsigned). Check the package, then the Markdown:',
    `  agent-receipt verify --package ${packageDir}`,
    `  agent-receipt import ${packageDir}`,
    `  agent-receipt verify ${markdownPath}`,
    `  agent-receipt prove ${markdownPath}`,
    `  agent-receipt verify --require-sig ${markdownPath}`,
  ];
}

function agentFromReceipt(markdown: string): string | null {
  const m = markdown.match(/^- \*\*Agent\*\*:\s*(.+)$/m);
  const agent = m?.[1]?.trim();
  return agent || null;
}

/**
 * One-shot share: verify the source receipt, apply redact (default on),
 * write HTML and optional Markdown, verify the published body, print
 * paths + TL;DR.
 *
 * A source that fails `verify` is not rewritten — share will not re-hash
 * a tampered receipt into a "clean" HTML file.
 *
 * Markdown handoff: a published `.md` whose sha256 matches the source and
 * has a valid source sidecar gets that sidecar copied. A redacted re-hash
 * is re-signed when local keys exist, and left unsigned (no stale sidecar)
 * when they do not. HTML is not signed.
 *
 * `--package` writes both files into `<stem>.share/` (or `--out` when that
 * path is a directory or ends with `/`), plus `manifest.json`. The HTML
 * body stays unsigned. The package is signed via `receipt.sig.json` and,
 * when local keys load, `manifest.sig.json`.
 */
export function cmdShare(
  cwd: string,
  pathArg: string | undefined,
  opts: ShareOptions = {},
): ShareResult {
  const source = resolveReceiptPath(cwd, pathArg);
  const original = readFileSync(source, 'utf8');
  const quiet = Boolean(opts.json);
  const say = (line: string) => emitLine(quiet, line);
  const redact = opts.redact !== false;
  const risk = parseRiskSummaryMarkdown(original);
  const failedOn = Boolean(opts.failOn && meetsFailOn(risk.maxSeverity, opts.failOn));
  const tldr = extractTldr(original) ?? '';
  const sourceCheck = verifyMarkdown(original);

  const finish = (partial: {
    htmlPath: string | null;
    markdownPath: string | null;
    verified: boolean;
    sha256: string | null;
    tldr: string;
    reason: string | null;
    trailingIgnored: boolean;
    sigPath: string | null;
    packagePath: string | null;
  }): ShareResult => {
    const exitCode: 0 | 2 = !partial.verified || failedOn ? 2 : 0;
    if (opts.json) {
      printGate(
        finalizeGate({
          command: 'share',
          exitCode,
          verified: partial.verified,
          failedOn,
          failOn: opts.failOn ?? null,
          redacted: redact,
          uncommitted: null,
          path: source,
          jsonPath: null,
          htmlPath: partial.htmlPath,
          markdownPath: partial.markdownPath,
          tldr: partial.tldr,
          sha256: partial.sha256,
          risk: riskToGate(risk),
          ignored: null,
          trailingIgnored: partial.trailingIgnored,
          reason: partial.reason,
          sigPath: partial.sigPath,
          ...(partial.packagePath ? { packagePath: partial.packagePath } : {}),
        }),
      );
    } else if (failedOn && opts.failOn && partial.verified) {
      console.error(
        color.red('✗') +
          ` ${failOnReason(opts.failOn, risk.maxSeverity)} — exiting 2`,
      );
    }
    recordAuditEvent(cwd, {
      event: 'share',
      path: partial.htmlPath || source,
      sha256: partial.sha256,
      agent: agentFromReceipt(original),
      redacted: redact,
      verified: partial.verified,
      failedOn,
      exitCode,
    });
    return {
      source,
      htmlPath: partial.htmlPath,
      markdownPath: partial.markdownPath,
      tldr: partial.tldr,
      verified: partial.verified,
      failedOn,
      redacted: redact,
      sha256: partial.sha256,
      exitCode,
      sigPath: partial.sigPath,
      packagePath: partial.packagePath,
    };
  };

  if (!sourceCheck.ok) {
    if (!quiet) {
      reportVerify(source, original, { quiet: false });
      say(color.red('share aborted — source receipt failed verify (nothing written).'));
    }
    return finish({
      htmlPath: null,
      markdownPath: null,
      verified: false,
      sha256: sourceCheck.actual,
      tldr,
      reason: sourceCheck.reason,
      trailingIgnored: Boolean(sourceCheck.trailingIgnored),
      sigPath: null,
      packagePath: null,
    });
  }

  const packaging = Boolean(opts.package);
  let packageDir: string | null = null;
  let htmlOut: string;
  let mdOut: string | undefined;
  if (packaging) {
    packageDir = resolveSharePackageDir(cwd, source, opts.out);
    htmlOut = join(packageDir, RECEIPT_HTML_NAME);
    mdOut = join(packageDir, RECEIPT_MD_NAME);
    if (resolve(htmlOut) === resolve(source) || resolve(mdOut) === resolve(source)) {
      throw new Error('share --package must not overwrite the source receipt.');
    }
  } else {
    htmlOut = opts.out ? resolve(cwd, opts.out) : sibling(source, '.html');
    if (resolve(htmlOut) === resolve(source)) {
      throw new Error('share --out must not overwrite the source receipt.');
    }
    if (opts.md) {
      mdOut =
        opts.md === true
          ? sibling(source, redact ? '.redacted.md' : '.export.md')
          : resolve(cwd, opts.md);
      if (resolve(mdOut) === resolve(source)) {
        throw new Error(
          'share --md must not overwrite the source receipt. Pick a different path.',
        );
      }
    }
  }

  const html = cmdExport(cwd, source, {
    out: htmlOut,
    redact,
    format: 'html',
    quiet: true,
    audit: false,
  });

  let markdownPath: string | null = null;
  let sigPath: string | null = null;
  let signatureTip: string | null = null;
  if (mdOut) {
    const md = cmdExport(cwd, source, {
      out: mdOut,
      redact,
      format: 'markdown',
      quiet: true,
      audit: false,
    });
    markdownPath = md.path;
    sigPath = md.sigPath;
    signatureTip = md.signatureTip;
  }

  const publishedTldr = extractTldr(html.markdown) ?? tldr;
  const bodyCheck = verifyMarkdown(html.markdown);
  let verified = bodyCheck.ok;
  let sha256: string | null = bodyCheck.actual;
  let reason: string | null = bodyCheck.ok ? null : bodyCheck.reason;
  let trailingIgnored = Boolean(bodyCheck.trailingIgnored);

  if (markdownPath) {
    const fileCheck = cmdVerify(cwd, markdownPath, { quiet: true });
    trailingIgnored = fileCheck.trailingIgnored;
    if (!fileCheck.ok) {
      verified = false;
      reason = fileCheck.reason;
      sha256 = fileCheck.sha256;
    }
  }

  if (packageDir && markdownPath && sha256) {
    const manifestPath = writeShareManifest(
      packageDir,
      buildShareManifest({
        packageDir,
        sha256,
        redacted: redact,
        fingerprint: fingerprintFromSidecar(sigPath),
      }),
    );
    signShareManifest(cwd, manifestPath);
  }

  if (signatureTip) say(color.yellow(signatureTip));
  if (!quiet) {
    say(color.bold('TL;DR') + `  ${publishedTldr}`);
    if (packageDir) say(color.bold('package:') + ` ${packageDir}`);
    say(color.bold('html') + `   ${html.path}`);
    if (markdownPath) say(color.bold('md') + `     ${markdownPath}`);
    if (sigPath) say(color.bold('sig') + `    ${sigPath}`);
    say(color.bold('source') + ` ${source}`);
    if (packageDir && markdownPath) {
      say('');
      for (const line of peerPackageTip(packageDir, markdownPath)) say(line);
    }
    say('');
    if (markdownPath) {
      cmdVerify(cwd, markdownPath, { quiet: false });
    } else {
      reportVerify(`${html.path} (markdown body)`, html.markdown, { quiet: false });
    }
  }

  if (verified && failedOn) {
    reason = failOnReason(opts.failOn, risk.maxSeverity);
  }

  return finish({
    htmlPath: html.path,
    markdownPath,
    verified,
    sha256,
    tldr: publishedTldr,
    reason,
    trailingIgnored,
    sigPath,
    packagePath: packageDir,
  });
}
