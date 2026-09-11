# agent-receipt

**Tamper-evident git snapshot receipts for AI / agent coding sessions.**

Agents change your repo faster than you can review. `agent-receipt` writes a
one-screen, hash-checked snapshot of what just happened — files, diffs, and
high-signal risk hints — so you can glance a session, list recent ones, and
catch `.env` / AWS keys / private keys before they ship.

This is **tamper-evident**, not a signature. Nobody can quietly edit a receipt
without `verify` failing. It is not cryptographic signing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why this exists

A coding agent can touch twenty files, bump a lockfile, and accidentally stage
`.env` in the time it takes you to refill coffee. Git history tells you *what
landed*. It does not give you a **session-shaped** artifact: who (agent), why
(message), what to review, and a checksum you can re-check later.

`agent-receipt` is that artifact. Use it when:

- You want a **TL;DR + “what to review”** at the top of a Markdown file
- You want **history** of recent agent sessions, not only `git log`
- You want **hooks / `watch`** so capture is not a forgotten extra step
- You want CI to **fail on high-severity** findings (`--fail-on high`)

## 60-second best path

Requires **Node.js ≥ 20** and `git` on `PATH`.

```bash
# Install from GitHub (works before npm publish)
npm i -g github:pramodreddyboddu/agent-receipt

cd your-git-repo
agent-receipt init --cursor     # config + Cursor rule that actually runs capture
agent-receipt install-hooks     # optional: auto-capture on every commit
agent-receipt doctor

# After an agent session (or let the Cursor rule / hook do it):
agent-receipt capture --agent cursor --message "what changed"

agent-receipt history           # time, agent, risk, summary (+ [uncommitted] badge)
agent-receipt last              # glance the newest
agent-receipt verify            # integrity
```

Wait for the **next** commit, capture once, exit — the Cursor / agent
“run after session” path:

```bash
agent-receipt watch --once --interval 2 --agent cursor --message "session wrap-up"
```

Leave a terminal running during a long session (commits **and** dirty tree):

```bash
agent-receipt watch --interval 5 --agent cursor
# HEAD-only (v0.4): agent-receipt watch --commits-only --interval 5
```

Example receipt: [`examples/sample-receipt.md`](examples/sample-receipt.md).

### Alternative installs

```bash
# one-shot without global install
npx github:pramodreddyboddu/agent-receipt doctor

# after npm publish
npm install -g agent-receipt
npm install -D agent-receipt
```

## Commands

| Command | Purpose |
|---------|---------|
| `init [--cursor]` | Write `.agent-receipt.yml` + notes; `--cursor` drops the Cursor rule |
| `capture` | Git snapshot → Markdown receipt (+ optional JSON) |
| `show [path]` | Pretty-print last / given receipt (full body) |
| `last` | Path + glance of the most recent receipt |
| `history` / `ls` | List recent receipts (`--json`; `[uncommitted]` badge; index at `.agent-receipt/index.json`) |
| `watch` | Poll git; auto-capture on commits **or dirty tree** (`--once`, `--commits-only`) |
| `verify [path]` | Hash-check tamper-evident integrity |
| `doctor` | Health check: git, repo, hooks, config, Node |
| `compare [a] [b]` | Diff two receipts (default: last vs previous) |
| `diff [a] [b]` | Alias for `compare` |
| `install-hooks` | Opt-in post-commit auto-capture (`--pre-push` optional) |
| `uninstall-hooks` | Remove managed hook sections |
| `help [cmd]` | Global help, or man-page style help for a command |

```bash
agent-receipt help watch
agent-receipt help capture
agent-receipt history
agent-receipt history --json --limit 5
agent-receipt ls --limit 5
```

### `capture` flags

| Flag | Description |
|------|-------------|
| `--since <ref>` | Diff from ref (e.g. `main`, `HEAD~5`) |
| `--commits <N>` | Last N commits (default: config / 1) |
| `--uncommitted` | Snapshot dirty working tree (labeled **uncommitted**) |
| `--message <text>` | Session message |
| `--agent <name>` | Agent label |
| `--session <id>` | Session / run id label |
| `--out <path>` | Output Markdown path |
| `--full` | Full diffs (no truncation) |
| `--json` | Also write companion `.json` |
| `--diff-stat` / `--no-diff-stat` | Diff-stat overview (default on) |
| `--top-risks <N>` | Max risk rows in findings table (default 20) |
| `--fail-on [high\|medium\|low]` | Exit 2 after writing if max severity meets threshold. Bare `--fail-on` = high. For CI scripts. |
| `--cwd <path>` | Run as if started in this directory (global) |

### `watch` flags

| Flag | Description |
|------|-------------|
| `--interval <sec>` | Poll interval (default **5**, min 1, max 3600) |
| `--once` | Wait for the next change (commit **or** dirty tree), capture, exit |
| `--commits-only` | Restore v0.4 behavior: only watch HEAD commits |
| `--agent` / `--message` | Passed through to capture |
| `--fail-on …` | With `--once`, exit 2 when the threshold is met |

By default watch detects **dirty trees** (staged / unstaged / untracked) as well
as new commits. Dirty captures are labeled **uncommitted** on the receipt.

```bash
# Try dirty watch (edit a file, wait one poll):
agent-receipt watch --once --interval 2 --agent cursor --message "dirty wrap-up"

# Old HEAD-only behavior:
agent-receipt watch --commits-only --once --interval 2
```

When HEAD moves `A → B`, watch captures `--since A` so every commit in the
interval is in the receipt. When only the working tree changes, it captures
with `--uncommitted`.

## What a receipt includes

- **TL;DR** — one-line: agent, time, branch, HEAD, files, +/−, risk
- **What to review** — ranked high/medium findings + notable files
- **Summary** rollup — files, line totals, risk counts / max severity
- **Notable changes** — package / lockfile / CI workflow highlights
- **Diff stat** — compact git-style overview
- Timestamp, branch, HEAD, optional agent / message / session
- Commit list for the range
- Files changed with insertions / deletions / binary flag
- Per-file diff summary (`--full` for complete diffs)
- **Risk findings** table, severity-sorted: `.env` commits, AWS keys in diffs,
  private key blocks, high-entropy tokens, secret-looking paths, lockfile / CI deletions, …
- Optional **uncommitted** snapshot (dirty working tree)
- SHA-256 integrity footer (tamper-evident)
- Stable index at `.agent-receipt/index.json` (updated on every capture)

Noise paths (`node_modules/**`, `dist/**`, `coverage/**` by default) are
excluded from risk / summary / file tables via config `ignore` globs.

See [`examples/sample-receipt.md`](examples/sample-receipt.md),
[`docs/agents.md`](docs/agents.md), [`docs/receipt.schema.json`](docs/receipt.schema.json),
and short recipes under [`examples/`](examples/).

## Cursor / agent wrap-up

`init --cursor` writes [`.cursor/rules/agent-receipt.mdc`](examples/.cursor/rules/agent-receipt.mdc)
with `alwaysApply: true`. The rule tells the agent to **run** capture (not
merely remind you) at session end.

Copy from examples if you already ran `init` without `--cursor`:

```bash
mkdir -p .cursor/rules
cp path/to/agent-receipt/examples/.cursor/rules/agent-receipt.mdc .cursor/rules/
```

**Run after session** (next commit → one receipt → exit):

```bash
agent-receipt watch --once --interval 2 --agent cursor --message "session wrap-up"
```

## Git hooks (local / global install)

`install-hooks` embeds **this package's** `bin/agent-receipt.js` (via `node` +
absolute path) so auto-capture works after `npm i -g` / local install **without**
npm publish. At hook runtime the order is:

1. `AGENT_RECEIPT_BIN` — absolute path to the CLI (optional override)
2. Embedded absolute bin from install time
3. `npx --yes agent-receipt` — last resort only

Hooks stay **non-blocking**. For CI that should fail on secrets:

```bash
agent-receipt capture --fail-on high
```

See [`examples/hooks.md`](examples/hooks.md).

## Config (`.agent-receipt.yml`)

```yaml
outDir: .agent-receipt/receipts
defaultAgent: agent
defaultCommits: 1
fullDiffs: false

# Path globs excluded from risk / summary / file tables
ignore:
  - node_modules/**
  - dist/**
  - coverage/**
  # optional lockfile noise:
  # - "*.lock"
  # - package-lock.json

# Suppress specific risk findings (code, code:pathGlob, or *:pathGlob)
riskAllowlist:
  # - package-json-change
  # - "lockfile-change:*.lock"
  # - "*:docs/**"
```

### Risk allowlist

`riskAllowlist` entries suppress matching findings after analysis:

| Entry | Meaning |
|-------|---------|
| `package-json-change` | Ignore that rule everywhere |
| `lockfile-change:*.lock` | Ignore that rule only on matching paths |
| `*:docs/**` | Ignore **all** risk codes under `docs/` |

```bash
# Example: ignore noisy package.json bumps, still catch secrets
cat >> .agent-receipt.yml <<'YAML'
riskAllowlist:
  - package-json-change
  - "lockfile-change:package-lock.json"
YAML
agent-receipt capture --commits 1
```

## Integrity model

The Markdown body (everything except the Integrity section / hash marker) is
hashed with SHA-256. `verify` recomputes the hash and compares it to the embedded
marker. Any edit to the body fails verification.

This is **tamper-evident**, not cryptographic signing. For signatures, wrap the
receipt with your own signing flow (e.g. `minisign`, GPG).

## Development

```bash
git clone https://github.com/pramodreddyboddu/agent-receipt.git
cd agent-receipt
npm install
npm test
node bin/agent-receipt.js help
```

Release playbook (no auto-publish): [`docs/RELEASE.md`](docs/RELEASE.md).

## License

MIT © Pramod Reddy Boddu
