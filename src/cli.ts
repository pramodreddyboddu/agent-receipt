import { resolve } from 'node:path';
import { parseArgs, flagString, flagBool, flagNumber } from './lib/args.js';
import { VERSION } from './lib/version.js';
import { color } from './lib/color.js';
import { helpFor, globalHelp } from './lib/help.js';
import { parseFailOn } from './lib/risk.js';
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
        cmdInit(cwd, { cursor: flagBool(flags, 'cursor') });
        return 0;
      case 'capture': {
        const noDiffStat = flagBool(flags, 'no-diff-stat');
        const failOn = parseFailOn(
          flags['fail-on'] === undefined ? undefined : flags['fail-on'],
        );
        const result = cmdCapture(cwd, {
          since: flagString(flags, 'since'),
          commits: flagNumber(flags, 'commits'),
          message: flagString(flags, 'message', 'm'),
          agent: flagString(flags, 'agent', 'a'),
          session: flagString(flags, 'session'),
          out: flagString(flags, 'out', 'o'),
          full: flagBool(flags, 'full'),
          json: flagBool(flags, 'json'),
          diffStat: noDiffStat ? false : undefined,
          topRisks: flagNumber(flags, 'top-risks'),
          failOn,
        });
        return result.failedOn ? 2 : 0;
      }
      case 'show':
        cmdShow(cwd, positional[0]);
        return 0;
      case 'last':
        cmdLast(cwd, { pathOnly: flagBool(flags, 'path') });
        return 0;
      case 'history':
      case 'ls':
        return cmdHistory(cwd, { limit: flagNumber(flags, 'limit') });
      case 'watch': {
        const failOn = parseFailOn(
          flags['fail-on'] === undefined ? undefined : flags['fail-on'],
        );
        return await cmdWatch(cwd, {
          interval: flagNumber(flags, 'interval'),
          once: flagBool(flags, 'once'),
          agent: flagString(flags, 'agent', 'a'),
          message: flagString(flags, 'message', 'm'),
          failOn,
          json: flagBool(flags, 'json'),
        });
      }
      case 'verify': {
        const ok = cmdVerify(cwd, positional[0]);
        return ok ? 0 : 2;
      }
      case 'doctor':
        return cmdDoctor(cwd);
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
    console.error(color.red('Error:') + ` ${msg}`);
    return 1;
  }
}

export { globalHelp as HELP };
