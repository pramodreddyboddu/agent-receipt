# agent-receipt

**Tamper-evident git snapshot receipts for AI / agent coding sessions.**

Capture what an agent changed (branch, HEAD, files, diffs, risk hints) into a
Markdown receipt with an embedded SHA-256 integrity footer. Verify later that
nobody edited the receipt.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 30-second quickstart

```bash
# from any git repo
npx agent-receipt init
npx agent-receipt capture --agent cursor --message "refactor auth helpers"
npx agent-receipt show
npx agent-receipt verify
```

Or install globally / locally:

```bash
npm install -g agent-receipt
agent-receipt help
```

## Commands

| Command | Purpose |
|---------|---------|
| `init` | Write `.agent-receipt.yml` + short setup notes |
| `capture` | Git snapshot → Markdown receipt (+ optional JSON) |
| `show [path]` | Pretty-print last / given receipt |
| `verify [path]` | Hash-check tamper-evident integrity |

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
| `--cwd <path>` | Run as if started in this directory (global) |

## What a receipt includes

- Timestamp, branch, HEAD, optional agent / message
- Commit list for the range
- Files changed with insertions / deletions / binary flag
- Per-file diff summary (`--full` for complete diffs)
- Risk hints: secret-looking paths, large binaries, lockfile / CI deletions
- SHA-256 integrity footer (tamper-evident)

See [`examples/sample-receipt.md`](examples/sample-receipt.md).

## Config (`.agent-receipt.yml`)

```yaml
outDir: .agent-receipt/receipts
defaultAgent: agent
defaultCommits: 1
fullDiffs: false
```

## Outside a git repo

`capture` exits non-zero with a clear error if the working directory is not a
git repository. Point `--cwd` at a repo when invoking from elsewhere.

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

Requires Node.js ≥ 20 and `git` on `PATH`.

## License

MIT © Pramod Reddy Boddu
