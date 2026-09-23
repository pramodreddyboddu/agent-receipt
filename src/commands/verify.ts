import { readFileSync } from 'node:fs';
import { verifyMarkdown } from '../lib/hash.js';
import { resolveReceiptPath } from './show.js';
import { color } from '../lib/color.js';
import {
  meetsFailOn,
  parseRiskSummaryMarkdown,
  type FailOnThreshold,
} from '../lib/risk.js';
import {
  failOnReason,
  finalizeGate,
  printGate,
  riskToGate,
  type GateReport,
} from '../lib/gate.js';
import { inspectReceiptSignature, type SignatureStatus } from '../lib/sign.js';

export interface VerifyCommandOptions {
  /** Suppress human stdout (JSON gate commands, or a caller that prints its own summary). */
  quiet?: boolean;
  /** Print one CI gate object on stdout. Implies quiet. */
  json?: boolean;
  /**
   * Explicit `--fail-on` only. Config `failOn` is not applied here so a
   * plain `verify` in existing hooks stays an integrity check.
   */
  failOn?: FailOnThreshold;
  /**
   * Opt-in. After a passing hash, require a valid `*.sig.json` beside the
   * receipt. Default verify stays hash-only.
   */
  requireSig?: boolean;
}

export interface VerifyCommandResult {
  ok: boolean;
  path: string;
  sha256: string;
  expected: string | null;
  reason: string;
  trailingIgnored: boolean;
  failedOn: boolean;
  exitCode: 0 | 2;
  redacted: boolean;
  risk: ReturnType<typeof parseRiskSummaryMarkdown>;
  /** Set when `--require-sig` ran after a passing hash. Null otherwise. */
  signature: SignatureStatus | null;
}

export function reportVerify(
  label: string,
  markdown: string,
  opts?: { quiet?: boolean },
): Pick<VerifyCommandResult, 'ok' | 'sha256' | 'expected' | 'reason' | 'trailingIgnored'> {
  const result = verifyMarkdown(markdown);
  if (!opts?.quiet) {
    console.log(`Verifying: ${label}`);
    if (result.ok) {
      console.log('✓ OK — receipt integrity verified');
      console.log(`  sha256: ${result.actual}`);
      if (result.trailingIgnored) {
        console.log(
          color.yellow(
            '  note: trailing content after ## Integrity is ignored by design (not part of the hash)',
          ),
        );
      }
    } else {
      console.error('✗ FAIL — ' + result.reason);
      if (result.expected) console.error(`  expected: ${result.expected}`);
      console.error(`  actual:   ${result.actual}`);
      console.error('The Markdown body no longer matches the embedded hash.');
      if (result.trailingIgnored) {
        console.error(
          '  note: trailing content after ## Integrity is ignored by design and did not cause this failure.',
        );
      }
    }
  }
  return {
    ok: result.ok,
    sha256: result.actual,
    expected: result.expected,
    reason: result.reason,
    trailingIgnored: Boolean(result.trailingIgnored),
  };
}

export function cmdVerify(
  cwd: string,
  pathArg?: string,
  opts: VerifyCommandOptions = {},
): VerifyCommandResult {
  const path = resolveReceiptPath(cwd, pathArg);
  const text = readFileSync(path, 'utf8');
  const quiet = Boolean(opts.quiet || opts.json);
  const reported = reportVerify(path, text, { quiet });
  const risk = parseRiskSummaryMarkdown(text);
  const failedOn = Boolean(opts.failOn && meetsFailOn(risk.maxSeverity, opts.failOn));
  const redacted = text.includes('**Redacted**');
  const requireSig = Boolean(opts.requireSig);

  // Hash failure exits 2 as today. The signature check runs only after a match.
  let signature: SignatureStatus | null = null;
  if (requireSig && reported.ok) {
    const inspected = inspectReceiptSignature(path, reported.sha256);
    if (!inspected.present) {
      signature = {
        present: false,
        ok: false,
        alg: null,
        fingerprint: null,
        reason: 'signature required: signature absent',
      };
    } else if (inspected.ok !== true) {
      signature = {
        present: true,
        ok: false,
        alg: inspected.alg,
        fingerprint: inspected.fingerprint,
        reason: inspected.reason || 'signature invalid',
      };
    } else {
      signature = inspected;
    }
  }
  const sigFailed = Boolean(signature && signature.ok !== true);

  if (!quiet && signature) {
    if (signature.ok === true) {
      console.log(
        color.green('✓') +
          ` signature ${signature.alg ?? 'ed25519'} ${signature.fingerprint ?? ''}`.trimEnd(),
      );
    } else if (signature.reason) {
      console.error(color.red('✗') + ` ${signature.reason}`);
    }
  }

  if (!quiet && failedOn && opts.failOn) {
    console.error(
      color.red('✗') +
        ` ${failOnReason(opts.failOn, risk.maxSeverity)} — exiting 2`,
    );
  }

  const exitCode: 0 | 2 = !reported.ok || failedOn || sigFailed ? 2 : 0;
  let reason = reported.ok ? '' : reported.reason;
  if (reported.ok && sigFailed && signature?.reason) {
    reason = signature.reason;
  }
  if (reported.ok && failedOn && opts.failOn) {
    const fail = failOnReason(opts.failOn, risk.maxSeverity);
    reason = reason ? `${reason}; ${fail}` : fail;
  }

  if (opts.json) {
    const gate: GateReport = finalizeGate({
      command: 'verify',
      exitCode,
      verified: reported.ok,
      failedOn,
      failOn: opts.failOn ?? null,
      redacted,
      uncommitted: null,
      path,
      jsonPath: null,
      htmlPath: null,
      markdownPath: null,
      tldr: null,
      sha256: reported.sha256,
      risk: riskToGate(risk),
      ignored: null,
      trailingIgnored: reported.trailingIgnored,
      reason: reason || null,
      ...(signature ? { signature } : {}),
    });
    printGate(gate);
  }

  return {
    ...reported,
    path,
    failedOn,
    exitCode,
    redacted,
    risk,
    reason,
    signature,
  };
}
