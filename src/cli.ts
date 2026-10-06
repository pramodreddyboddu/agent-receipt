import { resolve } from 'node:path';
import { parseArgs, flagString, flagBool, flagNumber } from './lib/args.js';
import { VERSION } from './lib/version.js';
import { color } from './lib/color.js';
import { helpFor, globalHelp } from './lib/help.js';
import { parseFailOn, type FailOnThreshold } from './lib/risk.js';
import { loadConfig } from './lib/config.js';
import { errorGate, printGate } from './lib/gate.js';
import { cmdInit } from './commands/init.js';
import { cmdCapture } from './commands/capture.js';
import { cmdShow } from './commands/show.js';
import { cmdVerify } from './commands/verify.js';
import { cmdVerifyPackage } from './commands/verify-package.js';
import { cmdImport } from './commands/import.js';
import { sharePackageAutoDetected } from './lib/share-package.js';
import { cmdProve, printProveError } from './commands/prove.js';
import { cmdKeygen, printKeygenError } from './commands/keygen.js';
import { cmdSign, printSignError } from './commands/sign.js';
import { cmdLast } from './commands/last.js';
import { cmdInstallHooks, cmdUninstallHooks } from './commands/hooks.js';
import { cmdDoctor } from './commands/doctor.js';
import { cmdCompare } from './commands/compare.js';
import { cmdHistory } from './commands/history.js';
import { cmdWatch } from './commands/watch.js';
import { cmdWrap } from './commands/wrap.js';
import { cmdSession } from './commands/session.js';
import { cmdSessionExport } from './commands/session-export.js';
import { cmdSessionImport } from './commands/session-import.js';
import { resolveLink, type ResolvedLink } from './lib/link.js';
import { cmdExport, cmdHtml } from './commands/export.js';
import { cmdShare } from './commands/share.js';
import { cmdAudit } from './commands/audit.js';
import { cmdPrune } from './commands/prune.js';
import { cmdTrust } from './commands/trust.js';
import { cmdReport, cmdReportVerify } from './commands/report.js';
import { cmdAdapters } from './commands/adapters.js';
import { cmdAttest, cmdAttestVerify, printAttestError } from './commands/attest.js';

const JSON_GATE_COMMANDS = new Set(['capture', 'wrap', 'share', 'verify', 'import']);

/**
 * `--fail-on` on the CLI wins. Otherwise capture/wrap/watch/share honor
 * config `failOn`. verify and prove do not (integrity-first unless the flag is passed).
 */
function resolveFailOn(
  cwd: string,
  flags: Record<string, string | boolean>,
  honorConfig: boolean,
): FailOnThreshold | undefined {
  if (flags['fail-on'] !== undefined) {
    return parseFailOn(flags['fail-on']);
  }
  if (!honorConfig) return undefined;
  const configured = loadConfig(cwd).failOn;
  if (!configured) return undefined;
  return parseFailOn(configured);
}

/** `--no-redact` wins, then `--redact`, then config `redact: true`. */
function resolveRedact(cwd: string, flags: Record<string, string | boolean>): boolean {
  if (flagBool(flags, 'no-redact')) return false;
  if (flagBool(flags, 'redact')) return true;
  return loadConfig(cwd).redact === true;
}

/**
 * `--no-sign` wins, then `--sign`, then config `sign: true`.
 * capture / wrap / watch only. Missing keys still tip and stay unsigned.
 */
function resolveSign(cwd: string, flags: Record<string, string | boolean>): boolean {
  if (flagBool(flags, 'no-sign')) return false;
  if (flagBool(flags, 'sign')) return true;
  return loadConfig(cwd).sign === true;
}

/**
 * `--no-prune` wins, then `--prune`, then config `autoPrune: true`.
 * capture / wrap / watch only. Does not pass `--force`. A broken audit
 * chain warns and does not change the command exit code.
 */
function resolveAutoPrune(cwd: string, flags: Record<string, string | boolean>): boolean {
  if (flagBool(flags, 'no-prune')) return false;
  if (flagBool(flags, 'prune')) return true;
  return loadConfig(cwd).autoPrune === true;
}

/**
 * Flags win over AGENT_RECEIPT_SESSION / PARENT / AGENT / HOST.
 * `link` is wrap-only: it generates a session when none is set and tells
 * wrap to export the session and this receipt's id to a child after `--`.
 * An absent agent is left unset so capture, wrap, and watch keep their defaults.
 */
function resolveCliLink(
  cwd: string,
  flags: Record<string, string | boolean>,
  link: boolean,
): ResolvedLink {
  const session = flags.session;
  const parent = flags.parent;
  const host = flags.host;
  const agentPresent = flags.agent !== undefined || flags.a !== undefined;
  return resolveLink(cwd, {
    sessionFlagPresent: session !== undefined,
    sessionFlag: typeof session === 'string' ? session : undefined,
    parentFlagPresent: parent !== undefined,
    parentFlag: typeof parent === 'string' ? parent : undefined,
    agentFlagPresent: agentPresent,
    agentFlag: flagString(flags, 'agent', 'a'),
    hostFlagPresent: host !== undefined,
    hostFlag: typeof host === 'string' ? host : undefined,
    link,
    env: process.env,
  });
}

function flagByteCap(
  flags: Record<string, string | boolean>,
  name: string,
): number | undefined {
  if (flags[name] === undefined) return undefined;
  const n = flagNumber(flags, name);
  if (n === undefined || !Number.isInteger(n) || n < 1) {
    throw new Error(`--${name} must be an integer number of bytes >= 1`);
  }
  return n;
}

function flagPositiveInt(
  flags: Record<string, string | boolean>,
  name: string,
): number | undefined {
  if (flags[name] === undefined) return undefined;
  const n = flagNumber(flags, name);
  if (n === undefined || !Number.isInteger(n) || n < 1) {
    throw new Error(`--${name} must be an integer >= 1`);
  }
  return n;
}

const AUDIT_FLAGS = new Set([
  'cwd',
  'json',
  'verify',
  'limit',
  'event',
  'agent',
  'failed',
]);

function assertKnownAuditFlags(flags: Record<string, string | boolean>): void {
  for (const key of Object.keys(flags)) {
    if (!AUDIT_FLAGS.has(key)) {
      throw new Error(
        `Unknown flag: --${key}. ` +
          'audit accepts --limit, --json, --event <name>, --agent <name>, --failed, --verify, and --cwd.',
      );
    }
  }
}

function flagAuditEvent(flags: Record<string, string | boolean>): string | undefined {
  if (flags.event === undefined) return undefined;
  if (typeof flags.event !== 'string' || flags.event.trim() === '') {
    throw new Error(
      '--event requires a name: capture, watch, wrap, share, export, or prune',
    );
  }
  return flags.event.trim();
}

function flagAuditAgent(flags: Record<string, string | boolean>): string | undefined {
  if (flags.agent === undefined) return undefined;
  if (typeof flags.agent !== 'string' || flags.agent.length === 0) {
    throw new Error(
      '--agent requires a name. The match is exact and case-sensitive. ' +
        'Events with agent null do not match any --agent filter.',
    );
  }
  return flags.agent;
}

function flagAuditFailed(flags: Record<string, string | boolean>): boolean {
  if (flags.failed === undefined) return false;
  if (flags.failed === true || flags.failed === 'true') return true;
  throw new Error(
    '--failed does not take a value. It keeps events with failedOn or a nonzero exitCode.',
  );
}

const HISTORY_FLAGS = new Set(['cwd', 'json', 'limit', 'agent', 'uncommitted', 'failed']);

function assertKnownHistoryFlags(flags: Record<string, string | boolean>): void {
  for (const key of Object.keys(flags)) {
    if (!HISTORY_FLAGS.has(key)) {
      throw new Error(
        `Unknown flag: --${key}. ` +
          'history/ls accepts --limit, --json, --agent <name>, --uncommitted, --failed, and --cwd.',
      );
    }
  }
}

function flagHistoryAgent(flags: Record<string, string | boolean>): string | undefined {
  if (flags.agent === undefined) return undefined;
  if (typeof flags.agent !== 'string' || flags.agent.length === 0) {
    throw new Error(
      '--agent requires a name. The match is exact and case-sensitive. ' +
        'Receipts with agent null do not match any --agent filter.',
    );
  }
  return flags.agent;
}

function flagHistoryUncommitted(flags: Record<string, string | boolean>): boolean {
  if (flags.uncommitted === undefined) return false;
  if (flags.uncommitted === true || flags.uncommitted === 'true') return true;
  throw new Error(
    '--uncommitted does not take a value. It keeps receipts where uncommitted is true.',
  );
}

const PROVE_FLAGS = new Set([
  'cwd',
  'json',
  'fail-on',
  'trusted-key',
  'page',
  'one-pager',
  'html',
  'out',
  'o',
]);
const TRUST_FLAGS = new Set(['cwd', 'json', 'self']);

const FP64 = /^[0-9a-f]{64}$/;

/** `--trusted-key <fp>` is repeatable and comma-separated. Invalid values are usage errors. */
function flagTrustedKeys(flags: Record<string, string | boolean>): string[] | undefined {
  const v = flags['trusted-key'];
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || !v.trim()) {
    throw new Error('--trusted-key requires a 64-hex fingerprint');
  }
  const parts = v
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (!parts.length) throw new Error('--trusted-key requires a 64-hex fingerprint');
  for (const fp of parts) {
    if (!FP64.test(fp)) {
      throw new Error('--trusted-key must be 64 hex chars');
    }
  }
  return parts;
}
const KEYGEN_FLAGS = new Set(['cwd', 'json', 'force']);
const SIGN_FLAGS = new Set(['cwd', 'json']);

function assertKnownKeygenFlags(flags: Record<string, string | boolean>): void {
  for (const key of Object.keys(flags)) {
    if (!KEYGEN_FLAGS.has(key)) {
      throw new Error(
        `Unknown flag: --${key}. keygen accepts --force, --json, and --cwd.`,
      );
    }
  }
}

function assertKnownSignFlags(flags: Record<string, string | boolean>): void {
  for (const key of Object.keys(flags)) {
    if (!SIGN_FLAGS.has(key)) {
      throw new Error(`Unknown flag: --${key}. sign accepts --json and --cwd.`);
    }
  }
}

const ATTEST_FLAGS = new Set([
  'cwd',
  'json',
  'out',
  'o',
  'verify',
  'predicate',
  'slsa',
  'session',
  'no-sign',
  'trusted-key',
  'no-redact',
  'include-host',
]);

function assertKnownAttestFlags(
  flags: Record<string, string | boolean>,
  extra: string[] = [],
): void {
  const known = new Set([...ATTEST_FLAGS, ...extra]);
  for (const key of Object.keys(flags)) {
    if (!known.has(key)) {
      throw new Error(
        `Unknown flag: --${key}. attest accepts --out, --predicate run|slsa, --slsa, --session, --no-sign, --verify, --trusted-key, --json, and --cwd.`,
      );
    }
  }
}

/** `run` unless `--slsa` or `--predicate slsa`. Those two conflict with `--predicate run`. */
function resolveAttestPredicate(flags: Record<string, string | boolean>): 'run' | 'slsa' {
  if (flags['no-redact'] !== undefined) {
    throw new Error('attest always redacts the predicate. There is no --no-redact.');
  }
  if (flags['include-host'] !== undefined) {
    throw new Error('attest omits the Host line. There is no --include-host.');
  }
  const slsa = flagBool(flags, 'slsa');
  const raw = flags.predicate;
  if (raw === true) throw new Error('--predicate requires run or slsa');
  const name = typeof raw === 'string' ? raw.toLowerCase() : undefined;
  if (name && name !== 'run' && name !== 'slsa') {
    throw new Error('--predicate must be run or slsa');
  }
  if (slsa && name === 'run') throw new Error('--slsa conflicts with --predicate run');
  return slsa || name === 'slsa' ? 'slsa' : 'run';
}

function assertKnownProveFlags(flags: Record<string, string | boolean>): void {
  for (const key of Object.keys(flags)) {
    if (!PROVE_FLAGS.has(key)) {
      throw new Error(
        `Unknown flag: --${key}. prove accepts --json, --page (alias --one-pager), --html, --out <path>, --fail-on [high|medium|low], --trusted-key <fp>, and --cwd.`,
      );
    }
  }
}

/** `--out` / `-o` for the prove one-pager / HTML report. A bare flag is a usage error. */
function flagProveOut(flags: Record<string, string | boolean>): string | undefined {
  const v = flags.out !== undefined ? flags.out : flags.o;
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || !v.trim()) {
    throw new Error('--out requires a path');
  }
  return v;
}

function flagHistoryFailed(flags: Record<string, string | boolean>): boolean {
  if (flags.failed === undefined) return false;
  if (flags.failed === true || flags.failed === 'true') return true;
  throw new Error(
    '--failed does not take a value. It keeps receipts that failed the gate.',
  );
}

/** share redacts unless `--no-redact` (share-safety from 1.0.3). */
function resolveShareRedact(flags: Record<string, string | boolean>): boolean {
  if (flagBool(flags, 'no-redact')) return false;
  return true;
}

/** A path flag. Bare `--name` (no value) is a usage error, not a silent skip. */
function flagPath(flags: Record<string, string | boolean>, name: string): string | undefined {
  if (flags[name] === undefined) return undefined;
  if (typeof flags[name] !== 'string' || !flags[name].trim()) {
    throw new Error(`--${name} requires a value`);
  }
  return flags[name];
}

function flagMd(flags: Record<string, string | boolean>): string | boolean | undefined {
  const v = flags.md !== undefined ? flags.md : flags.markdown;
  if (v === undefined) return undefined;
  if (v === true || v === 'true') return true;
  if (typeof v === 'string') return v;
  return undefined;
}

export async function run(argv: string[] = process.argv): Promise<number> {
  const { command, positional, flags } = parseArgs(argv);
  const cwdFlag = flagString(flags, 'cwd');
  const cwd = cwdFlag ? resolve(cwdFlag) : process.cwd();

  if (flagBool(flags, 'version', 'V') || command === 'version') {
    console.log(`agent-receipt ${VERSION}`);
    return 0;
  }

  if (flagBool(flags, 'help', 'h') || command === 'help') {
    const topic = command === 'help' ? positional[0] : command;
    // `agent-receipt capture --help` → topic = capture; bare --help → global
    if (flagBool(flags, 'help', 'h') && command !== 'help' && command) {
      console.log(helpFor(command));
      return 0;
    }
    console.log(helpFor(topic));
    return 0;
  }

  try {
    switch (command) {
      case 'init':
        cmdInit(cwd, {
          cursor: flagBool(flags, 'cursor'),
          grok: flagBool(flags, 'grok'),
          claude: flagBool(flags, 'claude'),
          codex: flagBool(flags, 'codex'),
          org: flagBool(flags, 'org', 'policy'),
          retention: flagBool(flags, 'retention'),
          autoPrune: flagBool(flags, 'auto-prune'),
        });
        return 0;
      case 'adapters': {
        const adapterFlags = new Set(['cwd', 'json', 'dry-run', 'stop', 'no-stop', 'force']);
        for (const key of Object.keys(flags)) {
          if (!adapterFlags.has(key)) {
            throw new Error(
              `Unknown flag: --${key}. adapters accepts --json, --dry-run, --stop, --no-stop, --force, and --cwd.`,
            );
          }
        }
        if (flagBool(flags, 'stop') && flagBool(flags, 'no-stop')) {
          throw new Error('Pass only one of --stop and --no-stop.');
        }
        const actionRaw = (positional[0] ?? 'list').toLowerCase();
        if (actionRaw !== 'list' && actionRaw !== 'status' && actionRaw !== 'install' && actionRaw !== 'uninstall') {
          throw new Error(
            `Unknown adapters action "${positional[0]}". Use list, status, install, or uninstall.`,
          );
        }
        if (positional.length > 2) {
          throw new Error('adapters accepts one agent name: claude-code, codex, grok, or cursor.');
        }
        const stop = flagBool(flags, 'no-stop') ? false : flagBool(flags, 'stop') ? true : undefined;
        return cmdAdapters(cwd, {
          action: actionRaw,
          adapter: positional[1],
          json: flagBool(flags, 'json'),
          dryRun: flagBool(flags, 'dry-run'),
          stop,
          force: flagBool(flags, 'force'),
        });
      }
      case 'capture': {
        if (flagBool(flags, 'link')) {
          throw new Error('--link is only valid on wrap. Pass --session on capture.');
        }
        const noDiffStat = flagBool(flags, 'no-diff-stat');
        const json = flagBool(flags, 'json');
        const failOn = resolveFailOn(cwd, flags, true);
        const link = resolveCliLink(cwd, flags, false);
        const message = flagString(flags, 'message', 'm');
        const result = cmdCapture(cwd, {
          since: flagString(flags, 'since'),
          base: flagString(flags, 'base'),
          commits: flagNumber(flags, 'commits'),
          message,
          agent: link.agent,
          id: link.id,
          session: link.session,
          parent: link.parent,
          host: link.host,
          out: flagString(flags, 'out', 'o'),
          full: flagBool(flags, 'full'),
          json,
          emitGate: json,
          diffStat: noDiffStat ? false : undefined,
          topRisks: flagNumber(flags, 'top-risks'),
          failOn,
          uncommitted: flagBool(flags, 'uncommitted'),
          redact: resolveRedact(cwd, flags),
          sign: resolveSign(cwd, flags),
          autoPrune: resolveAutoPrune(cwd, flags),
          transcript: flagPath(flags, 'transcript'),
          adapter: flagPath(flags, 'adapter'),
        });
        return result.failedOn ? 2 : 0;
      }
      case 'wrap': {
        const failOn = resolveFailOn(cwd, flags, true);
        const link = resolveCliLink(cwd, flags, flagBool(flags, 'link'));
        const message = flagString(flags, 'message', 'm');
        const result = cmdWrap(cwd, {
          agent: link.agent,
          id: link.id,
          session: link.session,
          parent: link.parent,
          host: link.host,
          propagate: link.propagate,
          command: positional,
          message,
          failOn,
          base: flagString(flags, 'base'),
          redact: resolveRedact(cwd, flags),
          json: flagBool(flags, 'json'),
          full: flagBool(flags, 'full'),
          uncommitted: flagBool(flags, 'uncommitted'),
          sign: resolveSign(cwd, flags),
          autoPrune: resolveAutoPrune(cwd, flags),
          transcript: flagPath(flags, 'transcript'),
          adapter: flagPath(flags, 'adapter'),
        });
        if (result.failedOn) return 2;
        return result.verified ? 0 : 2;
      }
      case 'share': {
        const failOn = resolveFailOn(cwd, flags, true);
        const result = cmdShare(cwd, positional[0], {
          out: flagString(flags, 'out', 'o'),
          md: flagMd(flags),
          redact: resolveShareRedact(flags),
          failOn,
          json: flagBool(flags, 'json'),
          package: flagBool(flags, 'package', 'pack'),
          includeHost: flagBool(flags, 'include-host'),
        });
        return result.exitCode;
      }
      case 'attest': {
        assertKnownAttestFlags(flags);
        const predicate = resolveAttestPredicate(flags);
        const json = flagBool(flags, 'json');
        const verifyFlag = flags.verify;
        const sub = positional[0] === 'verify';
        if (sub || verifyFlag !== undefined) {
          if (sub && verifyFlag !== undefined) {
            throw new Error('Pass either `attest verify <file>` or `attest --verify <file>`.');
          }
          if (flags.session !== undefined) {
            throw new Error('--session writes an attestation. It is not a verify flag.');
          }
          if (flags['no-sign'] !== undefined) {
            throw new Error('--no-sign writes an unsigned attestation. It is not a verify flag.');
          }
          if (flags.predicate !== undefined || flags.slsa !== undefined) {
            throw new Error('--predicate and --slsa choose what to write. They are not verify flags.');
          }
          if (flags.out !== undefined || flags.o !== undefined) {
            throw new Error('--out writes an attestation. It is not a verify flag.');
          }
          let file = '';
          if (sub) {
            if (positional.length !== 2) {
              throw new Error('Usage: agent-receipt attest verify <file.intoto.jsonl>');
            }
            file = positional[1];
          } else if (typeof verifyFlag === 'string') {
            if (positional.length) {
              throw new Error('Usage: agent-receipt attest --verify <file.intoto.jsonl>');
            }
            file = verifyFlag;
          } else {
            throw new Error('attest --verify requires a file');
          }
          return cmdAttestVerify(cwd, file, {
            json,
            trustedKeys: flagTrustedKeys(flags),
          });
        }
        if (flags['trusted-key'] !== undefined) {
          throw new Error('--trusted-key is for attest --verify.');
        }
        if (positional.length > 1) {
          throw new Error('attest accepts one receipt, one session package, or `last`.');
        }
        if (flags.session !== undefined && positional.length) {
          throw new Error('--session does not take a path. Usage: agent-receipt attest --session <id>');
        }
        return cmdAttest(cwd, positional[0], {
          out: flagString(flags, 'out', 'o'),
          json,
          predicate,
          session: flagString(flags, 'session'),
          noSign: flagBool(flags, 'no-sign'),
        });
      }
      case 'export': {
        const fmt = (flagString(flags, 'format') || 'html').toLowerCase();
        if (fmt === 'intoto' || fmt === 'in-toto' || fmt === 'dsse') {
          assertKnownAttestFlags(flags, ['format', 'redact']);
          const predicate = resolveAttestPredicate(flags);
          if (flags['trusted-key'] !== undefined || flags.verify !== undefined) {
            throw new Error('export --format intoto writes an attestation. Use `attest --verify` to check one.');
          }
          if (positional.length > 1) {
            throw new Error('export --format intoto accepts one receipt, one session package, or `last`.');
          }
          if (flags.session !== undefined && positional.length) {
            throw new Error('--session does not take a path.');
          }
          return cmdAttest(cwd, positional[0], {
            out: flagString(flags, 'out', 'o'),
            json: flagBool(flags, 'json'),
            predicate,
            session: flagString(flags, 'session'),
            noSign: flagBool(flags, 'no-sign'),
          });
        }
        cmdExport(cwd, positional[0], {
          out: flagString(flags, 'out', 'o'),
          redact: flagBool(flags, 'redact'),
          includeHost: flagBool(flags, 'include-host'),
          format: (fmt as 'html' | 'markdown' | 'md' | undefined) || 'html',
        });
        return 0;
      }
      case 'html':
        cmdHtml(cwd, positional[0], {
          out: flagString(flags, 'out', 'o'),
          redact: flagBool(flags, 'redact'),
          includeHost: flagBool(flags, 'include-host'),
        });
        return 0;
      case 'show':
        cmdShow(cwd, positional[0]);
        return 0;
      case 'last':
        cmdLast(cwd, {
          pathOnly: flagBool(flags, 'path'),
          json: flagBool(flags, 'json'),
        });
        return 0;
      case 'history':
      case 'ls':
        assertKnownHistoryFlags(flags);
        return cmdHistory(cwd, {
          limit: flagNumber(flags, 'limit'),
          json: flagBool(flags, 'json'),
          agent: flagHistoryAgent(flags),
          uncommitted: flagHistoryUncommitted(flags),
          failed: flagHistoryFailed(flags),
        });
      case 'watch': {
        if (flagBool(flags, 'link')) {
          throw new Error('--link is only valid on wrap. Pass --session on watch.');
        }
        const failOn = resolveFailOn(cwd, flags, true);
        const link = resolveCliLink(cwd, flags, false);
        const message = flagString(flags, 'message', 'm');
        return await cmdWatch(cwd, {
          interval: flagNumber(flags, 'interval'),
          once: flagBool(flags, 'once'),
          agent: link.agent,
          session: link.session,
          parent: link.parent,
          host: link.host,
          message,
          failOn,
          json: flagBool(flags, 'json'),
          commitsOnly: flagBool(flags, 'commits-only'),
          redact: resolveRedact(cwd, flags),
          sign: resolveSign(cwd, flags),
          autoPrune: resolveAutoPrune(cwd, flags),
        });
      }
      case 'verify': {
        const explicitFail = flags['fail-on'] !== undefined;
        const failOn = explicitFail ? parseFailOn(flags['fail-on']) : undefined;
        const packageMode = flagBool(flags, 'package', 'pack');
        const pathArg = positional[0];
        const auto = !packageMode && Boolean(pathArg) && sharePackageAutoDetected(cwd, pathArg);
        if (packageMode || auto) {
          if (!pathArg) {
            throw new Error(
              'verify --package requires a share package directory or manifest.json.',
            );
          }
          const result = cmdVerifyPackage(cwd, pathArg, {
            json: flagBool(flags, 'json'),
            failOn,
            requireSig: flagBool(flags, 'require-sig', 'require-signature'),
            trustedKeys: flagTrustedKeys(flags),
          });
          return result.exitCode;
        }
        const result = cmdVerify(cwd, pathArg, {
          json: flagBool(flags, 'json'),
          failOn,
          requireSig: flagBool(flags, 'require-sig', 'require-signature'),
          trustedKeys: flagTrustedKeys(flags),
        });
        return result.exitCode;
      }
      case 'import': {
        const pathArg = positional[0];
        if (!pathArg) {
          throw new Error('import requires a share package directory or manifest.json.');
        }
        for (const key of Object.keys(flags)) {
          if (
            key !== 'cwd' &&
            key !== 'json' &&
            key !== 'dry-run' &&
            key !== 'require-sig' &&
            key !== 'require-signature' &&
            key !== 'trusted-key' &&
            key !== 'fail-on'
          ) {
            throw new Error(
              `Unknown flag: --${key}. import accepts --dry-run, --json, --require-sig, --trusted-key, --fail-on, and --cwd.`,
            );
          }
        }
        const explicitFail = flags['fail-on'] !== undefined;
        const failOn = explicitFail ? parseFailOn(flags['fail-on']) : undefined;
        const result = cmdImport(cwd, pathArg, {
          json: flagBool(flags, 'json'),
          dryRun: flagBool(flags, 'dry-run'),
          failOn,
          requireSig: flagBool(flags, 'require-sig', 'require-signature'),
          trustedKeys: flagTrustedKeys(flags),
        });
        return result.exitCode;
      }
      case 'keygen': {
        assertKnownKeygenFlags(flags);
        const result = cmdKeygen(cwd, {
          force: flagBool(flags, 'force'),
          json: flagBool(flags, 'json'),
        });
        return result.exitCode;
      }
      case 'sign': {
        assertKnownSignFlags(flags);
        const result = cmdSign(cwd, positional[0], {
          json: flagBool(flags, 'json'),
        });
        return result.exitCode;
      }
      case 'report': {
        const sub = positional[0];
        if (sub === 'verify') {
          for (const key of Object.keys(flags)) {
            if (
              key !== 'cwd' &&
              key !== 'json' &&
              key !== 'receipts' &&
              key !== 'require-sig' &&
              key !== 'require-signature' &&
              key !== 'trusted-key'
            ) {
              throw new Error(
                `Unknown flag: --${key}. report verify accepts --receipts <dir>, --require-sig, --trusted-key <fp>, --json, and --cwd.`,
              );
            }
          }
          if (positional.length < 2) {
            throw new Error(
              'report verify requires an HTML file. Usage: agent-receipt report verify <file.html> [more.html ...]',
            );
          }
          const receipts = flags.receipts;
          if (receipts !== undefined && (typeof receipts !== 'string' || !receipts.trim())) {
            throw new Error('--receipts requires a directory');
          }
          return cmdReportVerify(cwd, positional.slice(1), {
            json: flagBool(flags, 'json'),
            receiptsDir: typeof receipts === 'string' ? receipts : undefined,
            requireSig: flagBool(flags, 'require-sig', 'require-signature'),
            trustedKeys: flagTrustedKeys(flags),
          });
        }
        for (const key of Object.keys(flags)) {
          if (
            key !== 'cwd' &&
            key !== 'json' &&
            key !== 'out' &&
            key !== 'o' &&
            key !== 'session' &&
            key !== 'include-host' &&
            key !== 'no-redact' &&
            key !== 'trusted-key'
          ) {
            throw new Error(
              `Unknown flag: --${key}. report accepts --session <id>, --out <path>, --include-host, --no-redact, --trusted-key <fp>, --json, and --cwd.`,
            );
          }
        }
        if (positional.length > 1) {
          throw new Error(
            'report accepts one receipt, last, or a *.session directory. Usage: agent-receipt report <receipt|last> [--out <path>]',
          );
        }
        const sessionFlag = flags.session;
        if (sessionFlag === true) throw new Error('--session requires an id');
        const out = flagProveOut(flags);
        return cmdReport(cwd, positional[0], {
          json: flagBool(flags, 'json'),
          out,
          session: typeof sessionFlag === 'string' ? sessionFlag : undefined,
          includeHost: flagBool(flags, 'include-host'),
          noRedact: flagBool(flags, 'no-redact'),
          trustedKeys: flagTrustedKeys(flags),
        });
      }
      case 'prove': {
        assertKnownProveFlags(flags);
        const explicitFail = flags['fail-on'] !== undefined;
        const failOn = explicitFail ? parseFailOn(flags['fail-on']) : undefined;
        const page = flagBool(flags, 'page', 'one-pager');
        const html = flagBool(flags, 'html');
        const out = flagProveOut(flags);
        if (out && !page && !html) {
          throw new Error('prove --out requires --page (or --one-pager) or --html.');
        }
        const result = cmdProve(cwd, positional[0], {
          json: flagBool(flags, 'json'),
          failOn,
          trustedKeys: flagTrustedKeys(flags),
          page,
          html,
          out,
        });
        return result.exitCode;
      }
      case 'trust': {
        for (const key of Object.keys(flags)) {
          if (!TRUST_FLAGS.has(key)) {
            throw new Error(`Unknown flag: --${key}. trust accepts --json, --self, and --cwd.`);
          }
        }
        const result = cmdTrust(cwd, positional[0], positional[1], {
          json: flagBool(flags, 'json'),
          self: flagBool(flags, 'self'),
        });
        return result.exitCode;
      }
      case 'session': {
        const sub = positional[0];
        if (sub === 'export' || sub === 'pack') {
          for (const key of Object.keys(flags)) {
            if (
              key !== 'cwd' &&
              key !== 'json' &&
              key !== 'out' &&
              key !== 'include-host' &&
              key !== 'resign' &&
              key !== 'max-receipt-bytes' &&
              key !== 'max-sidecar-bytes' &&
              key !== 'max-manifest-bytes'
            ) {
              throw new Error(
                `Unknown flag: --${key}. session export accepts --out <dir>, --include-host, --resign, --max-receipt-bytes, --max-sidecar-bytes, --max-manifest-bytes, --json, and --cwd.`,
              );
            }
          }
          if (positional.length > 2) {
            throw new Error(
              'session export accepts one id. Usage: agent-receipt session export <id> [--out <dir>] [--include-host] [--resign] [--json]',
            );
          }
          const out = flags.out;
          if (out !== undefined && (typeof out !== 'string' || !out.trim())) {
            throw new Error('--out requires a directory path');
          }
          const result = cmdSessionExport(cwd, positional[1], {
            json: flagBool(flags, 'json'),
            out: typeof out === 'string' ? out : undefined,
            includeHost: flagBool(flags, 'include-host'),
            resign: flagBool(flags, 'resign'),
            maxReceiptBytes: flagByteCap(flags, 'max-receipt-bytes'),
            maxSidecarBytes: flagByteCap(flags, 'max-sidecar-bytes'),
            maxManifestBytes: flagByteCap(flags, 'max-manifest-bytes'),
          });
          return result.exitCode;
        }
        if (sub === 'import' || sub === 'merge') {
          for (const key of Object.keys(flags)) {
            if (
              key !== 'cwd' &&
              key !== 'json' &&
              key !== 'dry-run' &&
              key !== 'require-sig' &&
              key !== 'require-signature' &&
              key !== 'trusted-key' &&
              key !== 'max-receipt-bytes' &&
              key !== 'max-sidecar-bytes' &&
              key !== 'max-manifest-bytes'
            ) {
              throw new Error(
                `Unknown flag: --${key}. session import accepts --dry-run, --json, --require-sig, --trusted-key, --max-receipt-bytes, --max-sidecar-bytes, --max-manifest-bytes, and --cwd.`,
              );
            }
          }
          if (positional.length > 2) {
            throw new Error(
              'session import accepts one package directory. Usage: agent-receipt session import <packageDir> [--dry-run] [--json] [--require-sig]',
            );
          }
          const result = cmdSessionImport(cwd, positional[1], {
            json: flagBool(flags, 'json'),
            dryRun: flagBool(flags, 'dry-run'),
            requireSig: flagBool(flags, 'require-sig', 'require-signature'),
            trustedKeys: flagTrustedKeys(flags),
            maxReceiptBytes: flagByteCap(flags, 'max-receipt-bytes'),
            maxSidecarBytes: flagByteCap(flags, 'max-sidecar-bytes'),
            maxManifestBytes: flagByteCap(flags, 'max-manifest-bytes'),
          });
          return result.exitCode;
        }
        for (const key of Object.keys(flags)) {
          if (key !== 'cwd' && key !== 'json') {
            throw new Error(
              `Unknown flag: --${key}. session accepts --json and --cwd. ` +
                'session export|pack and session import|merge are separate subcommands.',
            );
          }
        }
        if (positional.length > 1) {
          throw new Error('session accepts one id. Usage: agent-receipt session <id> [--json]');
        }
        return cmdSession(cwd, positional[0], { json: flagBool(flags, 'json') });
      }
      case 'doctor':
        return cmdDoctor(cwd, {
          strict: flagBool(flags, 'strict'),
          json: flagBool(flags, 'json'),
        });
      case 'audit':
      case 'log':
        assertKnownAuditFlags(flags);
        return cmdAudit(cwd, {
          json: flagBool(flags, 'json'),
          verify: flagBool(flags, 'verify'),
          limit: flagNumber(flags, 'limit'),
          event: flagAuditEvent(flags),
          agent: flagAuditAgent(flags),
          failed: flagAuditFailed(flags),
        });
      case 'prune':
      case 'retain': {
        const report = cmdPrune(cwd, {
          dryRun: flagBool(flags, 'dry-run'),
          maxCount: flagPositiveInt(flags, 'max-count'),
          maxAgeDays: flagPositiveInt(flags, 'max-age-days'),
          json: flagBool(flags, 'json'),
          force: flagBool(flags, 'force'),
        });
        return report.exitCode;
      }
      case 'compare':
      case 'diff':
        return cmdCompare(cwd, positional[0], positional[1]);
      case 'install-hooks':
        if (flagBool(flags, 'uninstall')) {
          cmdUninstallHooks(cwd, { prePush: flagBool(flags, 'pre-push') });
        } else {
          cmdInstallHooks(cwd, {
            prePush: flagBool(flags, 'pre-push'),
            force: flagBool(flags, 'force'),
          });
        }
        return 0;
      case 'uninstall-hooks':
        cmdUninstallHooks(cwd, { prePush: flagBool(flags, 'pre-push') });
        return 0;
      case undefined:
      case '':
        console.error(color.red('Missing command.') + ' Run `agent-receipt help` for usage.');
        return 1;
      default:
        console.error(color.red(`Unknown command: ${command}`));
        console.error('Run `agent-receipt help` for usage.');
        return 1;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const exportFmt = typeof flags.format === 'string' ? flags.format.toLowerCase() : '';
    const attestExport =
      command === 'export' &&
      (exportFmt === 'intoto' || exportFmt === 'in-toto' || exportFmt === 'dsse');
    if ((command === 'attest' || attestExport) && flagBool(flags, 'json')) {
      const verifying =
        command === 'attest' &&
        (flags.verify !== undefined || positional[0] === 'verify');
      printAttestError(msg, verifying ? 'attest-verify' : 'attest');
    } else if (command === 'prove' && flagBool(flags, 'json')) {
      printProveError(msg);
    } else if (command === 'keygen' && flagBool(flags, 'json')) {
      printKeygenError(msg);
    } else if (command === 'sign' && flagBool(flags, 'json')) {
      printSignError(msg);
    } else if (command && JSON_GATE_COMMANDS.has(command) && flagBool(flags, 'json')) {
      printGate(errorGate(command, msg));
    } else {
      console.error(color.red('Error:') + ` ${msg}`);
    }
    return 1;
  }
}

export { globalHelp as HELP };
