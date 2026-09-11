import { VERSION } from './version.js';

const TOPICS: Record<string, string> = {
  init: `agent-receipt init — write config + setup notes

Usage:
  agent-receipt init [--cursor] [--cwd <path>]

Options:
  --cursor               Drop .cursor/rules/agent-receipt.mdc (agent runs capture)

Creates:
  .agent-receipt.yml          config (outDir, agent, ignore globs, …)
  .agent-receipt/SETUP.md     short next-steps
  .cursor/rules/…             only with --cursor

Examples:
  agent-receipt init
  agent-receipt init --cursor
  agent-receipt init --cwd ~/code/my-app
`,

  capture: `agent-receipt capture — snapshot a git range into a Markdown receipt

Usage:
  agent-receipt capture [options]

Options:
  --base <ref>           Changes vs a base branch/ref (e.g. main); shows commits ahead
  --since <ref>          Diff range start (e.g. main, HEAD~5, abc123)
  --commits <N>          Last N commits (default: config or 1)
  --uncommitted          Snapshot dirty working tree (staged+unstaged+untracked)
  --message <text>       Human/agent session message
  --agent <name>         Agent label (default: config or "agent")
  --session <id>         Session / run id label
  --out <path>           Output Markdown path
  --full                 Include full diffs (no truncation)
  --json                 Also write companion .json
  --diff-stat            Include diff-stat overview (default: on)
  --no-diff-stat         Omit the diff-stat overview
  --top-risks <N>        Max risk rows in findings table (default: 20)
  --redact               Mask high/secret findings for safer sharing (re-hashed)
  --fail-on [high|medium|low]
                         Exit 2 after writing if max severity meets threshold.
                         Bare --fail-on means high. For hooks/CI scripts.
  --cwd <path>           Run as if started in this directory

Each capture updates .agent-receipt/index.json (stable receipt index).

Examples:
  agent-receipt capture --agent cursor --message "ship auth"
  agent-receipt capture --base main --agent cursor --message "PR branch"
  agent-receipt capture --uncommitted --agent cursor --message "wip"
  agent-receipt capture --since main --full --json --session s-42
  agent-receipt capture --commits 3 --no-diff-stat
  agent-receipt capture --redact --out share.md
  agent-receipt capture --fail-on high
`,

  wrap: `agent-receipt wrap — one-shot end-of-session capture + TL;DR + verify

Usage:
  agent-receipt wrap [options]

If the working tree is dirty (and --base is not set), captures with --uncommitted;
otherwise captures commits (optionally vs --base). Explicit --base always uses a
commit range even if the tree is dirty. Prints TL;DR + path, then verifies.

Options:
  --agent <name>         Agent label (default: wrap)
  --message <text>       Session message (default: "session wrap")
  --base <ref>           When clean, capture vs this base branch/ref
  --uncommitted          Require dirty-tree capture (error if clean)
  --redact               Mask high/secret findings in the written receipt
  --fail-on [high|medium|low]
                         Exit 2 after writing if max severity meets threshold
  --json                 Also write companion .json
  --full                 Include full diffs
  --cwd <path>           Run as if started in this directory

Exit codes: 0 OK, 2 fail-on threshold or verify failure, 1 error.

Examples:
  agent-receipt wrap --agent cursor --message "done with auth"
  agent-receipt wrap --agent cursor --base main
  agent-receipt wrap --fail-on high
`,

  export: `agent-receipt export — write a shareable HTML (or Markdown) receipt

Usage:
  agent-receipt export [path] [--out <file>] [--redact] [--format html|markdown]

If path is omitted, exports the newest receipt under outDir.
Default format is self-contained HTML (no external CSS/JS) — open in a browser
or share as a single file.

Options:
  --out <path>           Output path (default: sibling .html next to the receipt)
  --redact               Mask high/secret findings before writing
  --format <html|markdown|md>
                         Output format (default: html)
  --cwd <path>           Run as if started in this directory

Examples:
  agent-receipt export
  agent-receipt export --out share.html --redact
  agent-receipt export receipt.md --format markdown --redact --out safe.md
`,

  html: `agent-receipt html — alias for export as self-contained HTML

Usage:
  agent-receipt html [path] [--out <file>] [--redact]

Examples:
  agent-receipt html
  agent-receipt html --out session.html --redact
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

  history: `agent-receipt history — list recent receipts

Usage:
  agent-receipt history [--limit <N>] [--json]
  agent-receipt ls [--limit <N>] [--json]   # alias

Shows newest-first: time, agent, risk counts, short summary.
Uncommitted (dirty-tree) receipts get a visible [uncommitted] badge.
'--json' prints a JSON array (prefers .agent-receipt/index.json).

Options:
  --limit <N>            Max rows (default: 20)
  --json                 Machine-readable JSON array

Examples:
  agent-receipt history
  agent-receipt history --json --limit 5
  agent-receipt ls --limit 5
`,

  ls: `See: agent-receipt help history`,

  watch: `agent-receipt watch — poll git and auto-capture on commits or dirty tree

Usage:
  agent-receipt watch [--interval <sec>] [--once] [--commits-only] [--agent <name>] [--message <text>] [--fail-on …]

Defaults: poll every 5 seconds; watch **commits + dirty tree** until Ctrl+C.
Dirty-tree captures are labeled **uncommitted**.
--commits-only: restore v0.4 HEAD-only behavior.
--once: wait for the next change, capture once, exit (Cursor / agent “run after session”).

Options:
  --interval <sec>       Poll interval (default: 5, min 1, max 3600)
  --once                 Capture after the next change, then exit
  --commits-only         Only watch HEAD commits (ignore dirty tree)
  --agent <name>         Agent label (default: watch)
  --message <text>       Session message
  --fail-on [high|medium|low]
                         After capture, exit 2 when --once if threshold met
  --json                 Also write companion .json on each capture
  --cwd <path>           Run as if started in this directory

When HEAD moves A → B, capture uses --since A so all commits in the interval are included.
When the working tree changes (and HEAD did not), capture uses --uncommitted.

Cursor / agent wrap-up:
  agent-receipt watch --once --interval 2 --agent cursor --message "session wrap-up"

Long session (leave a terminal running):
  agent-receipt watch --interval 5 --agent cursor

Examples:
  agent-receipt watch
  agent-receipt watch --once --agent cursor
  agent-receipt watch --commits-only --once
  agent-receipt watch --interval 10 --fail-on high
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

For CI that should fail on secrets, run capture with --fail-on high in the job
(not in the git hook — hooks stay non-blocking).

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
  agent-receipt help watch
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
  wrap                   End-of-session: capture + TL;DR + verify
  export [path]          Write self-contained HTML (or Markdown) receipt
  html [path]            Alias for export as HTML
  show [path]            Pretty-print last / given receipt (full body)
  last                   Path + glance of the most recent receipt
  history                List recent receipts (time, agent, risk, summary)
  ls                     Alias for history
  watch                  Poll git; auto-capture on commits or dirty tree
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

Quickstart (≈ 60 seconds):
  npm i -g github:pramodreddyboddu/agent-receipt
  cd your-repo && agent-receipt init --cursor && agent-receipt install-hooks
  agent-receipt capture --agent cursor --message "first receipt"
  agent-receipt history && agent-receipt last && agent-receipt verify

Examples:
  agent-receipt init --cursor
  agent-receipt wrap --agent cursor --message "session done"
  agent-receipt capture --agent cursor --message "ship v0.6"
  agent-receipt capture --base main --message "PR vs main"
  agent-receipt capture --uncommitted --message "wip"
  agent-receipt capture --redact --out share.md
  agent-receipt export --redact --out share.html
  agent-receipt html
  agent-receipt capture --fail-on high
  agent-receipt history --json
  agent-receipt watch --once --agent cursor
  agent-receipt watch --commits-only --once
  agent-receipt watch --interval 5
  agent-receipt last
  agent-receipt verify
  agent-receipt doctor
  agent-receipt compare
  agent-receipt install-hooks
  agent-receipt help wrap

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
