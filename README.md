# agent-receipt

**Tamper-evident git snapshot receipts for AI / agent coding sessions.**

Capture what an agent changed (branch, HEAD, files, diffs, risk hints) into a
Markdown receipt with an embedded SHA-256 integrity footer. Verify later that
nobody edited the receipt.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 30-second path (discover → trust)

```bash
# Install from GitHub (works before npm publish)
npm i -g github:pramodreddyboddu/agent-receipt

# Or from a local checkout
# npm i -g /path/to/agent-receipt

cd your-git-repo
agent-receipt init
agent-receipt install-hooks
agent-receipt doctor

# …make a normal commit (hook auto-captures) OR capture manually:
agent-receipt capture --agent cursor --message "first receipt"

agent-receipt last
agent-receipt verify
```

Example of what you get: [`examples/sample-receipt.md`](examples/sample-receipt.md).

Requires **Node.js ≥ 20** and `git` on `PATH`.

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
| `init` | Write `.agent-receipt.yml` + short setup notes |
| `capture` | Git snapshot → Markdown receipt (+ optional JSON) |
| `show [path]` | Pretty-print last / given receipt (full body) |
| `last` | Path + glance of the most recent receipt |
| `verify [path]` | Hash-check tamper-evident integrity |
| `doctor` | Health check: git, repo, hooks, config, Node |
| `compare [a] [b]` | Diff two receipts (default: last vs previous) |
| `diff [a] [b]` | Alias for `compare` |
| `install-hooks` | Opt-in post-commit auto-capture (`--pre-push` optional) |
| `uninstall-hooks` | Remove managed hook sections |
| `help [cmd]` | Global help, or man-page style help for a command |

```bash
agent-receipt help doctor
agent-receipt help capture
agent-receipt compare
```

### `capture` flags

| Flag | Description |
|------|-------------|
| `--since <ref>` | Diff from ref (e.g. `main`, `HEAD~5`) |
| `--commits <N>` | Last N commits (default: config / 1) |
| `--message <text>` | Session message |
| `--agent <name>` | Agent label |
| `--session <id>` | Session / run id label |
| `--out <path>` | Output Markdown path |
| `--full` | Full diffs (no truncation) |
| `--json` | Also write companion `.json` |
| `--diff-stat` / `--no-diff-stat` | Diff-stat overview (default on) |
| `--top-risks <N>` | Max risk rows in findings table (default 20) |
| `--cwd <path>` | Run as if started in this directory (global) |

## What a receipt includes

- **Summary rollup** — files, line +/- totals, risk counts / max severity
- **Notable changes** — package / lockfile / CI workflow highlights
- **Diff stat** — compact git-style overview
- Timestamp, branch, HEAD, optional agent / message / session
- Commit list for the range
- Files changed with insertions / deletions / binary flag
- Per-file diff summary (`--full` for complete diffs)
- **Risk findings** table: secret-looking paths, auth paths, dependency
  manifests, large diffs, binaries, lockfile / CI deletions, broad change sets
- SHA-256 integrity footer (tamper-evident)

Noise paths (`node_modules/**`, `dist/**`, `coverage/**` by default) are
excluded from risk / summary / file tables via config `ignore` globs.

See [`examples/sample-receipt.md`](examples/sample-receipt.md),
[`docs/agents.md`](docs/agents.md), [`docs/receipt.schema.json`](docs/receipt.schema.json),
and short recipes under [`examples/`](examples/).


## Git hooks (local / global install)

`install-hooks` embeds **this package's** `bin/agent-receipt.js` (via `node` +
absolute path) so auto-capture works after `npm i -g` / local install **without**
npm publish. At hook runtime the order is:

1. `AGENT_RECEIPT_BIN` — absolute path to the CLI (optional override)
2. Embedded absolute bin from install time
3. `npx --yes agent-receipt` — last resort only

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
