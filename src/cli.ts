import { parseArgs, flagString, flagBool, flagNumber } from './lib/args.js';
import { cmdInit } from './commands/init.js';
import { cmdCapture } from './commands/capture.js';
import { cmdShow } from './commands/show.js';
import { cmdVerify } from './commands/verify.js';

const HELP = `agent-receipt — tamper-evident git snapshot receipts for agent sessions

Usage:
  agent-receipt <command> [options]

Commands:
  init                 Write .agent-receipt.yml + setup notes
  capture              Capture a git snapshot receipt (Markdown)
  show [path]          Pretty-print last/default receipt
  verify [path]        Hash-check tamper-evident integrity
  help                 Show this help
  version              Show version

capture options:
  --since <ref>        Diff range start (e.g. main, HEAD~5, abc123)
  --commits <N>        Last N commits (default: config or 1)
  --message <text>     Human/agent session message
  --agent <name>       Agent label (default: config or "agent")
  --out <path>         Output Markdown path
  --full               Include full diffs (no truncation)
  --json               Also write companion .json

Examples:
  agent-receipt init
  agent-receipt capture --agent cursor --message "ship v0.1"
  agent-receipt capture --since main --full --json
  agent-receipt show
  agent-receipt verify .agent-receipt/receipts/receipt-....md
`;

export function run(argv: string[] = process.argv): number {
  const { command, positional, flags } = parseArgs(argv);
  const cwd = process.cwd();

  if (flagBool(flags, 'help', 'h') || command === 'help') {
    console.log(HELP);
    return 0;
  }
  if (flagBool(flags, 'version', 'V') || command === 'version') {
    console.log('agent-receipt 0.1.0');
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
          out: flagString(flags, 'out', 'o'),
          full: flagBool(flags, 'full'),
          json: flagBool(flags, 'json'),
        });
        return 0;
      case 'show':
        cmdShow(cwd, positional[0]);
        return 0;
      case 'verify': {
        const ok = cmdVerify(cwd, positional[0]);
        return ok ? 0 : 2;
      }
      default:
        console.error(`Unknown command: ${command}`);
        console.error('Run `agent-receipt help` for usage.');
        return 1;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    return 1;
  }
}

export { HELP };
