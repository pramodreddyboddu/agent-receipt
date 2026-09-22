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
import { cmdLast } from './commands/last.js';
import { cmdInstallHooks, cmdUninstallHooks } from './commands/hooks.js';
import { cmdDoctor } from './commands/doctor.js';
import { cmdCompare } from './commands/compare.js';
import { cmdHistory } from './commands/history.js';
import { cmdWatch } from './commands/watch.js';
import { cmdWrap } from './commands/wrap.js';
import { cmdExport, cmdHtml } from './commands/export.js';
import { cmdShare } from './commands/share.js';
import { cmdAudit } from './commands/audit.js';
import { cmdPrune } from './commands/prune.js';

const JSON_GATE_COMMANDS = new Set(['capture', 'wrap', 'share', 'verify']);

/**
 * `--fail-on` on the CLI wins. Otherwise capture/wrap/watch/share honor
 * config `failOn`. verify does not (integrity-only unless the flag is passed).
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

/** share redacts unless `--no-redact` (share-safety from 1.0.3). */
function resolveShareRedact(flags: Record<string, string | boolean>): boolean {
  if (flagBool(flags, 'no-redact')) return false;
  return true;
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
        });
        return 0;
      case 'capture': {
        const noDiffStat = flagBool(flags, 'no-diff-stat');
        const json = flagBool(flags, 'json');
        const failOn = resolveFailOn(cwd, flags, true);
        const result = cmdCapture(cwd, {
          since: flagString(flags, 'since'),
          base: flagString(flags, 'base'),
          commits: flagNumber(flags, 'commits'),
          message: flagString(flags, 'message', 'm'),
          agent: flagString(flags, 'agent', 'a'),
          session: flagString(flags, 'session'),
          out: flagString(flags, 'out', 'o'),
          full: flagBool(flags, 'full'),
          json,
          emitGate: json,
          diffStat: noDiffStat ? false : undefined,
          topRisks: flagNumber(flags, 'top-risks'),
          failOn,
          uncommitted: flagBool(flags, 'uncommitted'),
          redact: resolveRedact(cwd, flags),
        });
        return result.failedOn ? 2 : 0;
      }
      case 'wrap': {
        const failOn = resolveFailOn(cwd, flags, true);
        const result = cmdWrap(cwd, {
          agent: flagString(flags, 'agent', 'a'),
          message: flagString(flags, 'message', 'm'),
          failOn,
          base: flagString(flags, 'base'),
          redact: resolveRedact(cwd, flags),
          json: flagBool(flags, 'json'),
          full: flagBool(flags, 'full'),
          uncommitted: flagBool(flags, 'uncommitted'),
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
        });
        return result.exitCode;
      }
      case 'export': {
        const fmt = flagString(flags, 'format');
        cmdExport(cwd, positional[0], {
          out: flagString(flags, 'out', 'o'),
          redact: flagBool(flags, 'redact'),
          format: (fmt as 'html' | 'markdown' | 'md' | undefined) || 'html',
        });
        return 0;
      }
      case 'html':
        cmdHtml(cwd, positional[0], {
          out: flagString(flags, 'out', 'o'),
          redact: flagBool(flags, 'redact'),
        });
        return 0;
      case 'show':
        cmdShow(cwd, positional[0]);
        return 0;
      case 'last':
        cmdLast(cwd, { pathOnly: flagBool(flags, 'path') });
        return 0;
      case 'history':
      case 'ls':
        return cmdHistory(cwd, {
          limit: flagNumber(flags, 'limit'),
          json: flagBool(flags, 'json'),
        });
      case 'watch': {
        const failOn = resolveFailOn(cwd, flags, true);
        return await cmdWatch(cwd, {
          interval: flagNumber(flags, 'interval'),
          once: flagBool(flags, 'once'),
          agent: flagString(flags, 'agent', 'a'),
          message: flagString(flags, 'message', 'm'),
          failOn,
          json: flagBool(flags, 'json'),
          commitsOnly: flagBool(flags, 'commits-only'),
          redact: resolveRedact(cwd, flags),
        });
      }
      case 'verify': {
        const explicitFail = flags['fail-on'] !== undefined;
        const failOn = explicitFail ? parseFailOn(flags['fail-on']) : undefined;
        const result = cmdVerify(cwd, positional[0], {
          json: flagBool(flags, 'json'),
          failOn,
        });
        return result.exitCode;
      }
      case 'doctor':
        return cmdDoctor(cwd, { strict: flagBool(flags, 'strict') });
      case 'audit':
      case 'log':
        return cmdAudit(cwd, {
          json: flagBool(flags, 'json'),
          verify: flagBool(flags, 'verify'),
          limit: flagNumber(flags, 'limit'),
        });
      case 'prune':
      case 'retain':
        cmdPrune(cwd, {
          dryRun: flagBool(flags, 'dry-run'),
          maxCount: flagPositiveInt(flags, 'max-count'),
          maxAgeDays: flagPositiveInt(flags, 'max-age-days'),
          json: flagBool(flags, 'json'),
        });
        return 0;
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
    if (command && JSON_GATE_COMMANDS.has(command) && flagBool(flags, 'json')) {
      printGate(errorGate(command, msg));
    } else {
      console.error(color.red('Error:') + ` ${msg}`);
    }
    return 1;
  }
}

export { globalHelp as HELP };
