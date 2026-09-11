import { resolve } from 'node:path';
import { parseArgs, flagString, flagBool, flagNumber } from './lib/args.js';
import { VERSION } from './lib/version.js';
import { color } from './lib/color.js';
import { cmdInit } from './commands/init.js';
import { cmdCapture } from './commands/capture.js';
import { cmdShow } from './commands/show.js';
import { cmdVerify } from './commands/verify.js';
import { cmdLast } from './commands/last.js';
import { cmdInstallHooks, cmdUninstallHooks } from './commands/hooks.js';

const HELP = `agent-receipt ${VERSION} — tamper-evident git snapshot receipts for agent sessions

Usage:
  agent-receipt <command> [options]

Commands:
  init                   Write .agent-receipt.yml + setup notes
  capture                Capture a git snapshot receipt (Markdown)
  show [path]            Pretty-print last / given receipt (full body)
  last                   Path + glance of the most recent receipt
  verify [path]          Hash-check tamper-evident integrity
  install-hooks          Install opt-in post-commit capture hook
  uninstall-hooks        Remove managed hook sections
  help                   Show this help
  version                Show version

Global options:
  --cwd <path>           Run as if started in this directory

capture options:
  --since <ref>          Diff range start (e.g. main, HEAD~5, abc123)
  --commits <N>          Last N commits (default: config or 1)
  --message <text>       Human/agent session message
  --agent <name>         Agent label (default: config or "agent")
  --session <id>         Session / run id label
  --out <path>           Output Markdown path
  --full                 Include full diffs (no truncation)
  --json                 Also write companion .json

last options:
  --path                 Print only the absolute path (scripting)

install-hooks options:
  --pre-push             Also install a pre-push capture hook

Examples:
  agent-receipt init
  agent-receipt capture --agent cursor --message "ship v0.2"
  agent-receipt capture --since main --full --json --session s-42
  agent-receipt last
  agent-receipt last --path
  agent-receipt show
  agent-receipt verify
  agent-receipt install-hooks
  agent-receipt install-hooks --pre-push
  agent-receipt uninstall-hooks

Docs: https://github.com/pramodreddyboddu/agent-receipt
Agent tips: docs/agents.md · examples/ (Cursor, Claude Code, Aider)
`;

export function run(argv: string[] = process.argv): number {
  const { command, positional, flags } = parseArgs(argv);
  const cwdFlag = flagString(flags, 'cwd');
  const cwd = cwdFlag ? resolve(cwdFlag) : process.cwd();

  if (flagBool(flags, 'help', 'h') || command === 'help') {
    console.log(HELP);
    return 0;
  }
  if (flagBool(flags, 'version', 'V') || command === 'version') {
    console.log(`agent-receipt ${VERSION}`);
    return 0;
  }

  try {
    switch (command) {
      case 'init':
        cmdInit(cwd);
        return 0;
      case 'capture':
        cmdCapture(cwd, {
          since: flagString(flags, 'since'),
          commits: flagNumber(flags, 'commits'),
          message: flagString(flags, 'message', 'm'),
          agent: flagString(flags, 'agent', 'a'),
          session: flagString(flags, 'session'),
          out: flagString(flags, 'out', 'o'),
          full: flagBool(flags, 'full'),
          json: flagBool(flags, 'json'),
        });
        return 0;
      case 'show':
        cmdShow(cwd, positional[0]);
        return 0;
      case 'last':
        cmdLast(cwd, { pathOnly: flagBool(flags, 'path') });
        return 0;
      case 'verify': {
        const ok = cmdVerify(cwd, positional[0]);
        return ok ? 0 : 2;
      }
      case 'install-hooks':
        cmdInstallHooks(cwd, {
          prePush: flagBool(flags, 'pre-push'),
          force: flagBool(flags, 'force'),
        });
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

export { HELP };
