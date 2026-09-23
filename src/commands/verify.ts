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

  if (!quiet && failedOn && opts.failOn) {
    console.error(
      color.red('✗') +
        ` ${failOnReason(opts.failOn, risk.maxSeverity)} — exiting 2`,
    );
  }

  const exitCode: 0 | 2 = !reported.ok || failedOn ? 2 : 0;
  let reason = reported.ok ? '' : reported.reason;
  if (reported.ok && failedOn && opts.failOn) {
    reason = failOnReason(opts.failOn, risk.maxSeverity);
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
  };
}
