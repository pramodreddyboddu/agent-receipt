import { VERSION } from './version.js';

const TOPICS: Record<string, string> = {
  init: `agent-receipt init — write config + setup notes

Usage:
  agent-receipt init [--cwd <path>]

Creates:
  .agent-receipt.yml          config (outDir, agent, ignore globs, …)
  .agent-receipt/SETUP.md     short next-steps

Examples:
  agent-receipt init
  agent-receipt init --cwd ~/code/my-app
`,

  capture: `agent-receipt capture — snapshot a git range into a Markdown receipt

Usage:
  agent-receipt capture [options]

Options:
  --since <ref>          Diff range start (e.g. main, HEAD~5, abc123)
  --commits <N>          Last N commits (default: config or 1)
  --message <text>       Human/agent session message
  --agent <name>         Agent label (default: config or "agent")
  --session <id>         Session / run id label
  --out <path>           Output Markdown path
  --full                 Include full diffs (no truncation)
  --json                 Also write companion .json
  --diff-stat            Include diff-stat overview (default: on)
  --no-diff-stat         Omit the diff-stat overview
  --top-risks <N>        Max risk rows in findings table (default: 20)
  --cwd <path>           Run as if started in this directory

Examples:
  agent-receipt capture --agent cursor --message "ship auth"
  agent-receipt capture --since main --full --json --session s-42
  agent-receipt capture --commits 3 --no-diff-stat
`,

  show: `agent-receipt show — print a receipt body

Usage:
  agent-receipt show [path]

If path is omitted, shows the newest receipt under configured outDir.

Examples:
  agent-receipt show
  agent-receipt show .agent-receipt/receipts/receipt-….md
`,

  last: `agent-receipt last — path + glance of the newest receipt

Usage:
  agent-receipt last [--path]

Options:
  --path                 Print only the absolute path (scripting)

Examples:
  agent-receipt last
  agent-receipt last --path | xargs agent-receipt verify
`,

  verify: `agent-receipt verify — hash-check tamper-evident integrity

Usage:
  agent-receipt verify [path]

Recomputes SHA-256 over the Markdown body (everything except the Integrity
section / hash marker) and compares it to the embedded marker.
Exit 0 = OK, exit 2 = mismatch / missing hash.

Examples:
  agent-receipt verify
  agent-receipt verify receipt.md
`,

  doctor: `agent-receipt doctor — environment health check

Usage:
  agent-receipt doctor [--cwd <path>]

Checks:
  node          Node.js >= 20
  git           git on PATH
  repo          inside a git work tree
  config        .agent-receipt.yml present + valid
  hooks         managed post-commit hook installed?
  outDir        receipt directory writable

Exit 0 if no FAIL checks; exit 1 otherwise. WARN items are non-fatal.

Examples:
  agent-receipt doctor
  agent-receipt doctor --cwd ~/code/my-app
`,

  compare: `agent-receipt compare — what changed between two receipts

Usage:
  agent-receipt compare [a] [b]
  agent-receipt diff [a] [b]          # alias

With no args: newest vs previous under outDir.
With one arg: that receipt vs previous.
With two args: compare those two paths.

Shows session deltas, summary metrics, file set diff, and risk set diff.

Examples:
  agent-receipt compare
  agent-receipt compare older.md newer.md
  agent-receipt diff
`,

  diff: `See: agent-receipt help compare`,

  'install-hooks': `agent-receipt install-hooks — opt-in auto-capture on commit

Usage:
  agent-receipt install-hooks [--pre-push] [--force] [--uninstall]

Options:
  --pre-push             Also install a pre-push capture hook
  --force                Refresh managed section
  --uninstall            Same as uninstall-hooks (compat)

Hooks embed this package's bin (node + absolute path) when installable locally/globally.
Fallback order at runtime: AGENT_RECEIPT_BIN → embedded bin path → npx (last resort).
Failure inside the hook is non-blocking (\`|| true\`).

Examples:
  agent-receipt install-hooks
  agent-receipt install-hooks --pre-push
  AGENT_RECEIPT_BIN=$(pwd)/bin/agent-receipt.js agent-receipt install-hooks
`,

  'uninstall-hooks': `agent-receipt uninstall-hooks — remove managed hook sections

Usage:
  agent-receipt uninstall-hooks [--pre-push]

Only strips the marked agent-receipt block; custom hook lines are preserved.

Examples:
  agent-receipt uninstall-hooks
  agent-receipt uninstall-hooks --pre-push
`,

  help: `agent-receipt help — show usage

Usage:
  agent-receipt help
  agent-receipt help <command>

Examples:
  agent-receipt help
  agent-receipt help capture
  agent-receipt help doctor
`,

  version: `agent-receipt version — print version

Usage:
  agent-receipt version
  agent-receipt --version
`,
};

export function globalHelp(): string {
  return `agent-receipt ${VERSION} — tamper-evident git snapshot receipts for agent sessions

Usage:
  agent-receipt <command> [options]

Commands:
  init                   Write .agent-receipt.yml + setup notes
  capture                Capture a git snapshot receipt (Markdown)
  show [path]            Pretty-print last / given receipt (full body)
  last                   Path + glance of the most recent receipt
  verify [path]          Hash-check tamper-evident integrity
  doctor                 Environment health check (git, hooks, config, node)
  compare [a] [b]        Diff two receipts (default: last vs previous)
  diff [a] [b]           Alias for compare
  install-hooks          Install opt-in post-commit capture hook
  uninstall-hooks        Remove managed hook sections
  help [command]         Show this help, or detailed help for a command
  version                Show version

Global options:
  --cwd <path>           Run as if started in this directory
  -h, --help             Show help
  -V, --version          Show version

Quickstart (≈ 5 minutes):
  npm i -g github:pramodreddyboddu/agent-receipt
  cd your-repo && agent-receipt init && agent-receipt install-hooks
  # …make a commit…
  agent-receipt last && agent-receipt verify && agent-receipt doctor

Examples:
  agent-receipt init
  agent-receipt capture --agent cursor --message "ship v0.3"
  agent-receipt capture --since main --full --json --session s-42
  agent-receipt last
  agent-receipt last --path
  agent-receipt show
  agent-receipt verify
  agent-receipt doctor
  agent-receipt compare
  agent-receipt install-hooks
  agent-receipt install-hooks --pre-push
  agent-receipt uninstall-hooks
  agent-receipt help doctor

Docs: https://github.com/pramodreddyboddu/agent-receipt
Agent tips: docs/agents.md · examples/ (Cursor, Claude Code, Aider)
Schema: docs/receipt.schema.json · Release: docs/RELEASE.md
`;
}

export function helpFor(topic?: string): string {
  if (!topic) return globalHelp();
  const key = topic.toLowerCase();
  const body = TOPICS[key];
  if (!body) {
    return (
      `Unknown help topic: ${topic}\n\n` +
      `Known topics: ${Object.keys(TOPICS).sort().join(', ')}\n\n` +
      globalHelp()
    );
  }
  return body.trimEnd() + '\n';
}

export { TOPICS };
