# agent-receipt

**One-shot, tamper-evident git receipts for AI coding agent sessions.**

Agents change your repo faster than you can review. `agent-receipt` writes a
one-screen, hash-checked snapshot of what just happened — files, diffs, and
high-signal risk hints — so you can glance a session, list recent ones, and
catch `.env` / AWS keys / private keys before they ship.

This is **tamper-evident**, not a signature. Nobody can quietly edit a receipt
without `verify` failing. It is not cryptographic signing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
<!-- Optional after public + npm: -->
<!-- [![npm version](https://img.shields.io/npm/v/@pramodreddyboddu/agent-receipt.svg)](https://www.npmjs.com/package/@pramodreddyboddu/agent-receipt) -->
<!-- [![CI](https://github.com/pramodreddyboddu/agent-receipt/actions/workflows/ci.yml/badge.svg)](https://github.com/pramodreddyboddu/agent-receipt/actions/workflows/ci.yml) -->

## Install

Requires **Node.js ≥ 20** and `git` on `PATH`.

```bash
# Once the package is public on npm:
npm i -g @pramodreddyboddu/agent-receipt

# Or from GitHub (works before / without npm publish):
npm install -g github:pramodreddyboddu/agent-receipt

# One-shot without a global install:
npx github:pramodreddyboddu/agent-receipt doctor
```

Dev dependency in a repo:

```bash
npm install -D @pramodreddyboddu/agent-receipt
# or: npm install -D github:pramodreddyboddu/agent-receipt
```

## Hero path: `wrap` at session end

```bash
cd your-git-repo
agent-receipt init --cursor     # config + Cursor rule that actually runs capture
agent-receipt install-hooks     # optional: auto-capture on every commit
agent-receipt doctor

# End of an agent session — one shot (dirty → --uncommitted, then verify):
agent-receipt wrap --agent cursor --message "what changed"
```

That prints **TL;DR** + receipt path and runs `verify`. Example:

```text
TL;DR  cursor · 2026-09-11T… · main @ a1b2c3d4e5f6 · 4 files · +42/−7 · risk none
Wrote  .agent-receipt/receipts/….md
verify OK
```

Or capture vs `main` on a PR branch and share HTML:

```bash
agent-receipt capture --base main --agent cursor --message "PR work"
agent-receipt export --redact --out share.html
```

```bash
agent-receipt history           # time, agent, risk, summary (+ [uncommitted] badge)
agent-receipt last              # glance the newest
agent-receipt verify            # integrity
agent-receipt --version
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
- You want a **one-shot wrap** at session end, **`share`** for redacted HTML, or an export you can attach
- You want a **CI gate** (`--json`, stable exit 2 on `--fail-on`), a local **audit** log (capture, watch, wrap, share, export, and prune deletes), opt-in **`prune`** for old receipts, and a team rollout note ([`docs/business.md`](docs/business.md))

## Commands

| Command | Purpose |
|---------|---------|
| `init [--cursor] [--grok]` | Write `.agent-receipt.yml` + notes; `--cursor` / `--grok` drop agent rules |
| `capture` | Git snapshot → Markdown receipt (+ optional JSON) |
| `wrap` | End of session: capture (+ `--uncommitted` if dirty) → TL;DR + path → verify |
| `share [path]` | One shot: redact → HTML (+ optional Markdown) → verify → paths + TL;DR |
| `export` / `html` | Self-contained HTML receipt (or export last); `--out`, `--redact` |
| `show [path]` | Pretty-print last / given receipt (full body) |
| `last` | Path + glance of the most recent receipt |
| `history` / `ls` | List recent receipts (`--json`; `[uncommitted]` badge; index at `.agent-receipt/index.json`) |
| `watch` | Poll git; auto-capture on commits **or dirty tree** (`--once`, `--commits-only`) |
| `verify [path]` | Hash-check tamper-evident integrity |
| `audit` / `log` | Local log of capture, watch, wrap, share, export, and prune deletes (`.agent-receipt/audit.jsonl`, experimental hash chain). `--event` filters the listing |
| `prune` / `retain` | Delete old receipts under `outDir` when `maxCount` / `maxAgeDays` is set (`--dry-run` does not delete or audit; off by default) |
| `doctor` | Health check plus a prod checklist (policy, audit, retention, hooks, redact, git clean, Cursor/Grok). `--json` for scripts. `--strict` fails only under receipt-dir pressure |
| `compare [a] [b]` | Diff two receipts (default: last vs previous) |
| `diff [a] [b]` | Alias for `compare` |
| `install-hooks` | Opt-in post-commit auto-capture (`--pre-push` optional) |
| `uninstall-hooks` | Remove managed hook sections |
| `help [cmd]` | Global help, or man-page style help for a command |

```bash
agent-receipt help wrap
agent-receipt help share
agent-receipt wrap --agent cursor --message "done"
agent-receipt share --out share.html --md share.md
agent-receipt history
agent-receipt prune --dry-run
agent-receipt doctor --strict
agent-receipt doctor --json
agent-receipt audit --event wrap --limit 20
agent-receipt history --json --limit 5
agent-receipt ls --limit 5
agent-receipt html --redact --out share.html
```

### `capture` flags

| Flag | Description |
|------|-------------|
| `--base <ref>` | Changes vs a base branch/ref (e.g. `main`); receipt shows **commits ahead** + file stats |
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
| `--redact` | Mask high/secret findings for safer sharing (re-hashed) |
| `--fail-on [high\|medium\|low]` | Exit 2 after writing if max severity meets threshold. Bare `--fail-on` = high. For CI scripts. |
| `--cwd <path>` | Run as if started in this directory (global) |


### `wrap` (end of session)

One shot for the end of an agent session:

1. If the tree is **dirty** and `--base` is not set → `capture --uncommitted`
2. Else → `capture` (with `--base <ref>` when provided)
3. Print **TL;DR** + receipt path
4. `verify`

```bash
agent-receipt wrap --agent cursor --message "session done"
agent-receipt wrap --agent cursor --base main --fail-on high
```

Flags: `--agent`, `--message`, `--fail-on`, `--base`, `--redact`, `--no-redact`, `--uncommitted`, `--json`, `--full`.

`--json` prints one CI gate object on stdout (exit codes unchanged: 0 pass, 2 policy or verify failure, 1 usage error) and still writes the companion receipt `.json`. Config `failOn` / `redact` apply when the flags are omitted. See [`docs/business.md`](docs/business.md).

### `share` (redacted HTML in one shot)

```bash
agent-receipt share
agent-receipt share --out share.html --md share.md
agent-receipt share receipt.md --fail-on high --json
```

Verifies the source first (a tampered receipt is not rewritten), applies
**`--redact` by default** (1.0.3 share-safety: `DATABASE_URL` / credential URLs,
nested receipt bodies), writes HTML and optional Markdown, verifies the
published body, and prints TL;DR plus paths. `--no-redact` opts out.
`--md` refuses to overwrite the source receipt.

### `export` / `html` (shareable receipt)

Write a **self-contained HTML** file (or Markdown) people can open in a browser
or attach to a PR / chat. Defaults to the newest receipt; pass a path to export
a specific one.

```bash
agent-receipt export                         # → sibling .html next to last receipt
agent-receipt html --out session.html
agent-receipt export --redact --out share.html
agent-receipt export receipt.md --format markdown --redact --out safe.md
```

### `--base` vs last N commits

On a feature branch, summarize everything since `main` (commits ahead + files):

```bash
agent-receipt capture --base main --agent cursor --message "PR vs main"
# Range label looks like: "5 commits ahead of main"
```

`--since main` still works for the same diff range with a classic `main..HEAD` label.

### `--redact` (safer sharing)

Masks high-signal secrets (AWS keys, GitHub/Slack tokens, private key blocks,
secret assignment values) and high/secret risk detail in Markdown/HTML, then
**re-hashes** so `verify` still passes on the redacted artifact.

```bash
agent-receipt capture --redact --out share.md
agent-receipt wrap --redact --agent cursor
agent-receipt html --redact --out share.html
```

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
- Optional **`--base`** range (“N commits ahead of main”)
- Optional **redacted** sharing mode (`--redact`)
- SHA-256 integrity footer (tamper-evident)
- Optional **HTML export** (`export` / `html`) for open/share
- Stable index at `.agent-receipt/index.json` (updated on every capture)

Noise paths (`node_modules/**`, `dist/**`, `coverage/**` by default) are
excluded from risk / summary / file tables via config `ignore` globs.

See [`examples/sample-receipt.md`](examples/sample-receipt.md),
[`docs/agents.md`](docs/agents.md), [`docs/receipt.schema.json`](docs/receipt.schema.json),
short recipes under [`examples/`](examples/), and
[`docs/business.md`](docs/business.md) for team rollout.

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

## Grok Build CLI

`init --grok` writes a project rule Grok loads every session
(`.grok/rules/agent-receipt.md`) and a **SessionEnd** hook that wraps only when
the working tree is dirty, with `--redact`. Project hooks run after
`grok --trust` or `/hooks-trust`.

After a Grok session — dirty tree is captured as **uncommitted** automatically;
`--redact` keeps the 1.0.3 share-safety masks:

```bash
agent-receipt wrap --agent grok --redact --message "what changed"
```

Require a dirty snapshot (errors if the tree is clean):

```bash
agent-receipt wrap --agent grok --redact --uncommitted --message "uncommitted grok work"
```

In this repo: `scripts/grok-wrap.sh "what changed"` or `npm run wrap:grok -- "what changed"`.

Full recipe: [`docs/grok-cli.md`](docs/grok-cli.md). The SessionEnd hook drains
stdin with a byte cap and a short timeout so an open pipe (no EOF) cannot hang
the session.

Team install, CI gates, audit log, retention, and what not to put in receipts:
[`docs/business.md`](docs/business.md). Org defaults:
[`examples/org-policy.yml`](examples/org-policy.yml). PR gate example:
[`examples/github/pr-gate.yml`](examples/github/pr-gate.yml).

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

**Trailing appends after `## Integrity` are ignored by design** — they are not
part of the canonical body, so `verify` still passes if only the footer area is
extended. Prefer editing the body (which will fail verify) or re-capturing when
you need a new sealed artifact.

This is **tamper-evident**, not cryptographic signing. For signatures, wrap the
receipt with your own signing flow (e.g. `minisign`, GPG).

Heuristic risk scanning has limits — see [`SECURITY.md`](SECURITY.md).

`--redact` also masks credential URLs (e.g. `DATABASE_URL` / `postgres://user:pass@…`)
and omits nested prior-receipt / index diff bodies so truncated secrets are not
re-embedded when those artifacts appear in the change set.

## Development

```bash
git clone https://github.com/pramodreddyboddu/agent-receipt.git
cd agent-receipt
npm install
npm test
npm run pack:check
node bin/agent-receipt.js help
node bin/agent-receipt.js --version
```

Release playbook (no auto-publish): [`docs/RELEASE.md`](docs/RELEASE.md).

## License

MIT © Pramod Reddy Boddu
