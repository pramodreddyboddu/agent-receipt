# agent-receipt

**One-shot, tamper-evident git receipts for AI coding agent sessions.**

Agents change your repo faster than you can review. `agent-receipt` writes a
one-screen, hash-checked snapshot of what just happened — files, diffs, and
high-signal risk hints — so you can glance a session, list recent ones, and
catch `.env` / AWS keys / private keys before they ship.

This is **tamper-evident**. Nobody can quietly edit a receipt without `verify`
failing. `verify` stays a hash check. `keygen` and `sign` add a thin local
Ed25519 attest of that hash (`foo.sig.json` beside the receipt). It is not a
CA and not PKI. The private key stays under `.agent-receipt/keys/`.

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

## GitHub Action

Gate a pull request with one `uses:` line. The action runs a pinned
`agent-receipt` (`1.0.36` by default, never `latest`) and posts a sticky
summary comment.

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
  - uses: pramodreddyboddu/agent-receipt@v1
    with:
      fail-on: high
      comment: on
```

Policy, signed verify, and keyless `attest-verify` (`id-token: write` plus
`pull-requests: write`) are in [`docs/github-action.md`](docs/github-action.md).
Print the same summary locally with `agent-receipt pr-comment --dry-run`.
Pass `policy-pack: builtin:baseline` (comma-separated) to evaluate packs in
that same job.

## Policy packs

Declarative rules for the controls orgs already ask for: secret files,
workflow edits, lockfiles, package installs, and a required signature.
Packs are YAML or JSON (`apiVersion: agent-receipt/policy/v1`). Built-ins
are `builtin:baseline`, `builtin:supply-chain`, `builtin:ci-protect`, and
`builtin:strict`. `extends` composes them. Deny hits fail the gate (exit 2).
Warn hits are reported only. A missing or invalid pack fails closed.

```bash
agent-receipt policy list
agent-receipt policy show builtin:strict
agent-receipt policy lint policies/baseline.yml
agent-receipt wrap --policy-pack builtin:baseline --json
```

Per-repo defaults live in `.agent-receipt.yml` (`policyPacks`,
`policyExceptions` with `rule`, `path`, `reason`, and an optional `expires`
date). An expired exception does not suppress the hit. Full format:
[`docs/policy-packs.md`](docs/policy-packs.md). Schema:
[`docs/policy-pack.schema.json`](docs/policy-pack.schema.json).

## Local viewer

`agent-receipt view` serves the receipt store in a browser on `127.0.0.1`.
It is read-only, offline, and always redacted. There is no `--no-redact`.

```bash
agent-receipt view
agent-receipt view --port 0 --open
agent-receipt view --json
agent-receipt view --static ./viewer-dist
```

`--static` writes `index.html` and `data.json` with inline CSS and script
(no CDN). Open `index.html` from disk or upload the directory as a CI
artifact. A non-loopback `--host` is refused unless you also pass
`--allow-remote`.

Details: [`docs/viewer.md`](docs/viewer.md).

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
agent-receipt last --json       # one object: path, sha256, agent, failedOn
agent-receipt verify            # integrity (hash-only)
agent-receipt keygen             # local Ed25519 keypair (optional)
agent-receipt trust add --self   # allowlist that fingerprint (not a CA)
agent-receipt sign               # attest the receipt sha256
agent-receipt attest            # in-toto Statement in a DSSE envelope
agent-receipt attest --verify .agent-receipt/receipts/*.intoto.jsonl
agent-receipt prove             # hash + audit link + signature status
agent-receipt prove --page      # human one-pager beside the receipt (foo.prove.md)
agent-receipt prove --html      # offline HTML verification report (foo.prove.html)
agent-receipt report last       # signed one-page HTML report (sibling of outDir)
agent-receipt report verify .agent-receipt/*.report.html
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
| `init [--cursor] [--grok] [--claude] [--codex] [--org] [--retention] [--auto-prune]` | Write `.agent-receipt.yml` + notes. `--org` (alias `--policy`) sets `redact: true` and `failOn: high` without replacing local `ignore`. `--retention` sets `maxCount: 100` and `maxAgeDays: 30` the same way and does not turn `autoPrune` on. `--auto-prune` sets `autoPrune: true` without replacing ignore, redact, or the limits. `--cursor` / `--grok` / `--claude` / `--codex` install that agent's project hook |
| `adapters [list\|status\|install\|uninstall] [name]` | Native capture hooks for Claude Code, Cursor, Grok CLI, and Codex. Install merges and snapshots the previous bytes. Uninstall restores them when they are unchanged and strips only our hooks when they are not. `--dry-run` writes nothing. `--json` for scripts. `--no-stop` skips the extra Stop hook on Claude, Codex, and Cursor. `--force` restores the snapshot anyway |
| `capture` | Git snapshot → Markdown receipt (+ optional JSON). `--transcript` records tool calls, including MCP, inside the hashed body. `--sign` writes `*.sig.json` when local keys exist |
| `wrap` | End of session: capture (+ `--uncommitted` if dirty) → TL;DR + path → verify. `--transcript` is the same as capture. `--sign` is opt-in |
| `share [path]` | One shot: redact → HTML (+ optional Markdown) → verify → paths + TL;DR. `--package` writes `foo.share/` with HTML, Markdown, optional `receipt.sig.json`, and `manifest.json`. Markdown sidecar is copied or re-signed; HTML stays unsigned |
| `export` / `html` | Self-contained HTML receipt (or Markdown); `--out`, `--redact`. Markdown uses the same sidecar handoff. HTML stays unsigned |
| `show [path]` | Pretty-print last / given receipt (full body) |
| `last` | Path + glance of the most recent receipt. `--json` prints one object (`path`, `sha256`, agent, `failedOn`, `uncommitted`, TL;DR). `--json` wins over `--path` |
| `history` / `ls` | List recent receipts (`--agent`, `--uncommitted`, `--failed`, `--json`, `--limit`; `[uncommitted]` and `[failed]` badges; index at `.agent-receipt/index.json` stores `failedOn`) |
| `watch` | Poll git; auto-capture on commits **or dirty tree** (`--once`, `--commits-only`) |
| `keygen [--force]` | Create a local Ed25519 keypair under `.agent-receipt/keys/` (PKCS8 private, SPKI public). Idempotent; `--force` rotates. No network |
| `sign [path]` | Hash-check a receipt, then write `foo.sig.json` over the sha256 hex. Missing keys exit 1. Hash failure exits 2 and writes nothing. Capture and wrap sign only with `--sign` |
| `attest [path\|last]` | in-toto Statement v1 inside a DSSE envelope (`.intoto.jsonl`). Subjects are the receipt and changed files. `--slsa` writes SLSA Provenance v1. `--verify` checks the signature, subject digests, and the hash-chain head. `export --format intoto` is the same writer |
| `trust` | Known-keys allowlist: `list`, `show`, `add <fp>`, `add --self`, `rm <fp>` on `.agent-receipt/trusted-keys.txt`. `trust show` is read-only and reports whether the local key is listed. Not a CA |
| `verify [path]` | Hash-check tamper-evident integrity. Default stays hash-only (unsigned receipts still pass). `--package` checks a `share --package` directory (manifest, file hashes, receipt, optional signatures). `--require-sig` requires a valid `*.sig.json` and, when a trust store is configured, a known fingerprint. `--json` includes `trailingIgnored` (boolean) |
| `pr-comment` | Run `gate`, `verify`, or `attest-verify`, then print or post a redacted Markdown summary. `--dry-run` does not call GitHub. `--comment-mode update` keeps one sticky pull request comment. `--policy-pack` adds a Policy packs section |
| `policy [list\|show\|lint\|test]` | Declarative policy packs. `builtin:<name>` or a file. Lint exits 1 on a schema error. Test exits 2 on a deny hit. `--json` for each |
| `import <dir>` | Verify a share package, then copy `receipt.md` (and `receipt.sig.json` when present) into the local receipt store. `--dry-run` writes nothing. Not a local capture |
| `prove [path]` | Prove-this-run: same hash as `verify`, plus trailing content, risk, an audit-log link, and signature status when a sidecar is present. `--json` adds `signature` (`trusted` is null when the allowlist is inactive). `--page` writes `foo.prove.md` (plain English; not itself signed). Config `failOn` is not applied |
| `report [path\|last]` | Signed one-page HTML report. `report --session <id>` or `report <path/to/*.session>` covers a tree. `report verify <file.html> [more.html ...]` re-renders the page from the signed payload and requires the same bytes. The worst exit code wins |
| `audit` / `log` | Local log of capture, watch, wrap, share, export, and prune deletes (`.agent-receipt/audit.jsonl`, experimental hash chain). `--event`, `--agent`, and `--failed` filter the listing |
| `prune` / `retain` | Delete old receipts under `outDir` when `maxCount` / `maxAgeDays` is set (`--dry-run` does not delete or audit; off by default). Trusted prune refuses the delete when the audit chain is broken (`--force` is break-glass). `autoPrune: true` or `--prune` runs that same path after capture, wrap, and watch (no `--force`; a broken chain warns and does not fail the capture) |
| `doctor` | Health check plus a prod checklist (policy, packs, audit, keys, trust, retention, autoPrune, hooks, redact, git clean, Cursor/Grok, adapters, viewer). `--json` for scripts. `--strict` fails unset org policy (`redact` + `failOn`), unset retention (`maxCount` / `maxAgeDays`), a broken audit chain, an invalid trust store, an invalid policy pack, and an expired policy exception. A missing trust store stays INFO. Unset packs stay INFO under `--strict`. The `adapters` and `viewer` rows stay INFO and do not fail `--strict`. Unset `autoPrune` stays INFO and does not fail `--strict`. Default doctor still pressure-gates unset retention. Missing signing keys stay INFO |
| `view` | Local read-only browser for receipts and session trees. Loopback by default. `--static <dir>` writes an offline `index.html` + `data.json` bundle. Always redacts |
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
agent-receipt history --agent cursor
agent-receipt history --uncommitted --json
agent-receipt history --failed
agent-receipt history --agent ci --failed --json
agent-receipt ls --agent ci --uncommitted --limit 5
agent-receipt prune --dry-run
agent-receipt prune --force
agent-receipt init --org
agent-receipt init --retention
agent-receipt doctor --strict
agent-receipt doctor --json
agent-receipt keygen
agent-receipt trust add --self
agent-receipt sign
agent-receipt prove --json
agent-receipt prove --page
agent-receipt prove --html
agent-receipt last --json
agent-receipt audit --event wrap --limit 20
agent-receipt audit --agent cursor --failed
agent-receipt log --agent ci --failed --json
agent-receipt history --json --limit 5
agent-receipt ls --limit 5
agent-receipt html --redact --out share.html
```

`history` / `ls` keep every receipt unless you pass a filter. `--agent <name>` is an exact, case-sensitive match on the receipt `agent` field (`agent: null` or a missing agent does not match). `--uncommitted` keeps dirty-tree snapshots (`uncommitted: true`). `--failed` keeps gate failures: the index `failedOn` boolean when that field is present (a stored `false` stays out even if risk is high), otherwise high severity only (`risk.high > 0`, `risk.maxSeverity` of `high`, or a high-severity row on a scan). Medium or low alone does not match. They combine with `--limit` and `--json` (still a JSON array; each row includes `failedOn`, and scan rows include `uncommitted`). New captures write `failedOn` on the index and on the companion `.json`. Filter order: load receipts, then `--agent`, then `--uncommitted`, then `--failed`, then `--limit` (newest N of the filtered set). No matches is exit 0 (`[]` with `--json`). An empty receipt store still errors. Unknown flags, a bare `--agent`, and `--failed` with a value exit 1.

### `capture` flags

| Flag | Description |
|------|-------------|
| `--base <ref>` | Changes vs a base branch/ref (e.g. `main`); receipt shows **commits ahead** + file stats |
| `--since <ref>` | Diff from ref (e.g. `main`, `HEAD~5`) |
| `--commits <N>` | Last N commits (default: config / 1) |
| `--uncommitted` | Snapshot dirty working tree (labeled **uncommitted**) |
| `--message <text>` | Session message |
| `--agent <name>` | Agent label (flag wins over `AGENT_RECEIPT_AGENT`) |
| `--session <id>` | Session id for related runs (`AGENT_RECEIPT_SESSION`) |
| `--parent <ref>` | Parent receipt id, sha256, or path (`AGENT_RECEIPT_PARENT`) |
| `--host <label>` | Host label. Omitted unless this flag or `AGENT_RECEIPT_HOST` |
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

Flags: `--agent`, `--message`, `--session`, `--parent`, `--host`, `--link`, `--fail-on`, `--base`, `--redact`, `--no-redact`, `--uncommitted`, `--json`, `--full`.

`--json` prints one CI gate object on stdout (exit codes unchanged: 0 pass, 2 policy or verify failure, 1 usage error) and still writes the companion receipt `.json`. Config `failOn` / `redact` apply when the flags are omitted. See [`docs/business.md`](docs/business.md).

## Linking multi-agent runs

`capture`, `wrap`, and `watch` can record a `session` id and a `parent` receipt reference in the hashed `## Session` header, plus an `agent` label. Link fields are read only when two checks both pass. The bytes from `# Agent Receipt` through the end of `## Session` must match the 1.0.28 writer, with fence awareness off in that region: the writer's TL;DR (the `> **TL;DR**` line, blank lines, and `> `-quoted message lines, including the bare `>` quote spacer), then `## What to review` in the writer's body shape, then `## Summary` in the writer's table shape, then `## Session` fields in writer order, then the heading the writer emits next (`## Notable changes`, `## Commits`, or `## Files changed`). A raw line, a fence (`` ``` `` or `~~~`, any info string), an extra heading, a CR-only or mixed line ending, or an out-of-order field fails that check. A file that is entirely CRLF still matches. The whole file is then scanned line by line with fences ignored (a fenced line still counts). There must be exactly one line equal to `# Agent Receipt`, exactly one equal to `## What to review`, and exactly one equal to `## Session`. If any count is not one, the receipt is pre-1.0.28: no link metadata. When the TL;DR contains a timestamp it must match the header Timestamp; a TL;DR with no timestamp skips that check. Receipts written by 1.0.27 or earlier quote only the first message line and leave the rest raw, then write their own header, so a message that pastes a 1.0.28 block has those headings more than once and is not linked. Only that receipt's author, or whoever signs it, can put that message in the hashed body. The rule makes every pre-1.0.28 receipt unlinkable. A branch or workspace path that contains a backtick is percent-encoded in the header so the link is kept. `wrap --link` (or `--session`, including `--session new`) exports `AGENT_RECEIPT_SESSION` and `AGENT_RECEIPT_PARENT` to the command after `--`, so a nested wrap links itself to this receipt. Flags win over those env vars. With no link flag and no link env, the receipt is unchanged.

`--agent` is free-form (spaces allowed; no newlines or control characters), matching 1.0.27 and config `defaultAgent`. `--session` still accepts 1.0.27 values such as `old sess/1` and stores them on one line. Generated ids are `s-` plus 16 hex. `--parent` is an `r-` id, a sha256, or a path to a receipt file. `--message` may span lines; each line is quoted or indented so it cannot form a header field.

`agent-receipt session <id>` prints the local parent/child tree. `--json` is the machine-readable form. Exit 1 when any receipt in the session fails verify or a local parent fails verify. A parent that is not in this `outDir` is flagged `orphan`. A loop inside the session is flagged `cycle`. A parent in another local session is `warnings=cross-session-parent`. None of those warnings change the exit code by themselves.

`host` stays off unless you pass `--host` or set `AGENT_RECEIPT_HOST`. `share` keeps session, parent, and agent, and masks host unless `--include-host`. `prove` shows session, parent, and whether a local parent verifies. It does not show host, and a missing parent does not change the prove exit code.

```bash
agent-receipt wrap --link --session new --agent parent -- node agent-receipt wrap --agent child
agent-receipt session s-0123456789abcdef
agent-receipt session s-0123456789abcdef --json
```

Receipts written with `--out` outside `outDir` are not listed. Auto-prune can delete a parent later; the child then shows as an orphan.

## Cross-host session merge

`session export <id>` (alias `session pack`) packs that local tree into a directory beside `outDir`: `.agent-receipt/receipts` becomes `.agent-receipt/<id>.session/`. `--out <dir>` names the directory. The package holds each receipt as `receipts/<basename>.md`, a sidecar when one was copied or re-signed, `session-manifest.json`, and `session-manifest.sig.json` when local keys load. Unless `--include-host`, export uses the same redaction function as `share`: secrets are masked, a nested receipt or index diff body is replaced with `[REDACTED — nested receipt/index body omitted]`, and the header Host line becomes `[REDACTED]`. `--include-host` keeps the original bytes, including Host and secrets. A sidecar signed by another key is copied when the bytes do not change. When redaction must change those bytes, export exits 2 and writes nothing unless `--resign`, which warns on stderr and records `originalFingerprint` and `resignedBy` in the manifest. `originalFingerprint` is the manifest signer's claim about the source sidecar (or null when the source was unsigned). It is not a second signature over the pre-export bytes. `session-manifest.sig.json` covers that claim when the sidecar verifies. An unsigned source whose bytes change is not silently treated as the exporter's own signature: export warns on stderr and sets `signedBy` to the exporter fingerprint, with `originalFingerprint` and `resignedBy` null. A same-key rewrite leaves `signedBy` null. Orphans and cycles are included and named in the manifest `warnings`. An empty session or a receipt that fails verify writes nothing. Receipts, sidecars, and the manifest are refused above 32 MiB, 256 KiB, and 8 MiB unless `--max-receipt-bytes`, `--max-sidecar-bytes`, or `--max-manifest-bytes` raises the cap. The size is taken from `stat` before the file is read.

`session import <dir>` (alias `session merge`) checks the manifest, the file hashes, each receipt, and any signatures, then copies the receipts into your `outDir`. The same id and the same sha256 is skipped. A different sha256 for the same id, or the same filename compared case-insensitively, refuses the import and does not overwrite. A symlink destination (including a dangling link, a symlinked sidecar, or a symlink `outDir`) exits 2 and writes nothing. An existing file, including a stray `.sig.json`, is a conflict unless it is byte-identical. An unreadable destination is a conflict. Files are staged inside `outDir` and published without replacing a name that already exists. On a real import, stale `.import-staging-*` directories that contain the marker file `.agent-receipt-import-staging` and are older than this run are removed first. A directory without that marker is left alone. `--dry-run` does not delete them. `--dry-run` and `--json` report the plan, including `originalFingerprint`, `resignedBy`, and `signedBy`. The human summary and a later `session <id>` print those claims. `--require-sig` requires receipt sidecars and a manifest signature. After import, `session <id>` lists the merged tree. Import does not append the audit log and does not add an index row. `last`, `history`, and `prune` ignore `*.session/` directories. `prune` checks every target, including the `.sig.json`, before it unlinks anything, and refuses a symlink sidecar.

```bash
agent-receipt session export s-0123456789abcdef
agent-receipt session import .agent-receipt/s-0123456789abcdef.session --dry-run
agent-receipt session s-0123456789abcdef
```

Schema: [`docs/session-package.schema.json`](docs/session-package.schema.json). This is not a CA.

### `share` (redacted HTML in one shot)

```bash
agent-receipt share
agent-receipt share --out share.html --md share.md
agent-receipt share --package
agent-receipt share receipt.md --fail-on high --json
```

Verifies the source first (a tampered receipt is not rewritten), applies
**`--redact` by default** (1.0.3 share-safety: `DATABASE_URL` / credential URLs,
nested receipt bodies), writes HTML and optional Markdown, verifies the
published body, and prints TL;DR plus paths. `--no-redact` opts out.
`--md` refuses to overwrite the source receipt. `--package` (alias `--pack`)
writes `foo.share/` with `receipt.html`, `receipt.md`, optional
`receipt.sig.json`, and `manifest.json`. Open the HTML, then
`verify --package` the directory (or `verify` the Markdown). The HTML body
stays unsigned. `import` copies the proved Markdown into your receipt store.

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
[`docs/gate.schema.json`](docs/gate.schema.json),
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

The same installers are `agent-receipt adapters install grok` (and `claude-code`, `cursor`, `codex`). `adapters install --dry-run` writes nothing. Uninstall restores the pre-install bytes. Pass a transcript when you wrap by hand:

```bash
agent-receipt wrap --agent grok --redact --transcript session.jsonl --message "what changed"
```

Full recipe: [`docs/grok-cli.md`](docs/grok-cli.md). The SessionEnd hook drains
stdin with a byte cap and a short timeout so an open pipe (no EOF) cannot hang
the session.

Team install, CI gates, audit log, retention, and what not to put in receipts:
[`docs/business.md`](docs/business.md). Org defaults:
[`examples/org-policy.yml`](examples/org-policy.yml). Drop-in PR gate:
[`examples/github/action.yml`](examples/github/action.yml) (copy to
`.github/actions/agent-receipt/`; `install` pin
`github:pramodreddyboddu/agent-receipt#v1.0.36`, optional `prove`, optional
`sign`, optional `require-sig`, optional `trusted-keys`) and
[`examples/github/pr-gate.yml`](examples/github/pr-gate.yml) (prove after a
green gate, optional temp keygen + `trust add --self` when `trusted-keys`
is empty, `verify --require-sig`, upload `receipt-gate.json`).
Signed CI recipe (not a CA): [`docs/ci-signed-gate.md`](docs/ci-signed-gate.md).
Gate JSON:
[`docs/gate.schema.json`](docs/gate.schema.json). `init --retention` sets
`maxCount: 100` and `maxAgeDays: 30` and does not turn `autoPrune` on.
`autoPrune: true` (or `init --auto-prune`, or `--prune` for one run) plus
those limits deletes older receipts after a successful capture, wrap, or
watch. That path is the same trusted prune and does not pass `--force`.
A broken audit chain skips the delete and does not fail the capture.
`--no-prune` turns it off for one run. Not a daemon. Trusted prune refuses
a broken audit chain unless you pass `prune --force` on the manual command.

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

A symlinked `.agent-receipt` parent is followed. Receipts, keys, and the trust store are written in the real directory. `prune` still refuses a symlink receipt or a symlink sidecar and does not delete the rest of that batch.

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

`verify --json` includes `trailingIgnored` (boolean). `wrap --json` and
`share --json` set that field when they verified a body. `capture --json`
leaves it null.

`prove` is the prove-this-run report: the same hash check, plus trailing
content, risk, TL;DR, agent, stored `failedOn` / `uncommitted`, whether
`.agent-receipt/audit.jsonl` links this receipt, and signature status.
Exit 0 when the hash matches, the log is missing or intact, and any sidecar
is valid or absent. Exit 2 when the body was edited, the audit chain is
broken, a present `.sig.json` does not verify, or you passed `--fail-on`
and it tripped. A missing sidecar does not fail prove. Config `failOn`
does not apply. `prove --json` prints one object, including `signature`.
`prove --page` writes a one-page Markdown summary next to the receipt
(`foo.md` → `foo.prove.md`) with the verdict, hash, audit link, and
signature status. `--json --page` adds `pagePath`. The page is not signed.

`prove --html` (v1.0.27) writes one self-contained, offline HTML
verification report (`foo.md` → `foo.prove.html`, same `--out` rules) with a
PASS / FAIL banner, the hash check, audit chain, Ed25519 signature and trust
status, and a receipt summary. Redaction is always on (same secret rules as
`share`), everything is HTML-escaped, URLs are defanged, and the file has
inline CSS only: no scripts, links, images, fonts, or network, plus a
`default-src 'none'` CSP. It is written on FAIL too; exit codes do not
change. `--json --html` adds `htmlPath`. `--page --html` writes both (then
`--out` must be a directory). The HTML report is not itself signed.

`report` (v1.0.30) writes a signed one-page HTML report a reviewer can open offline. `report last` and `report <receipt>` cover one receipt. `report --session <id>` and `report <path/to/*.session>` cover a tree, including the parent/child/agent lines and any `originalFingerprint`, `resignedBy`, or `signedBy` claim. The default file sits beside `outDir` (`.agent-receipt/<stem>.report.html`). The page has a VERIFIED / FAILED / UNSIGNED / UNTRUSTED banner, the summary, commands, files, risk flags, what to review, commits, range, and the exact commands to re-verify. Redaction matches `share` unless you pass `--include-host` or `--no-redact`, which add a loud UNREDACTED marker. Passing a file that is already a report exits 1 (`input is already a report; use report verify`). That is a `*.report.html` name, or any file that contains the report payload block, including a report renamed to `.md`. The page is `render(payload, signature)`. The Ed25519 signature covers the canonical JSON payload, which holds every string the page shows (verdict, banner, pills, agent, fingerprints, trust, signature status, title, UNREDACTED state, and the narrative). The signature block is inserted after signing. `report verify` checks that signature, re-renders the HTML, and requires the same bytes. A single missing trailing newline is ignored. Any other difference exits 2 with `page content does not match signed payload`. Exit 0 only when the signature is valid, the page matches, and the verdict is VERIFIED, or, without `--require-sig`, when an honestly UNSIGNED page matches (printed UNSIGNED). Verdict FAILED or UNTRUSTED exits 2. A non-zero exit never prints VERIFIED. A failing unsigned page prints `FAILED (unsigned)`, not UNSIGNED. Several files take the worst exit code. A detached `<report>.html.sig.json` is written when keys load. Missing keys leave the report unsigned and exit 0. The payload `renderVersion` selects the HTML renderer (`2` is this page and includes tool calls when the receipt has them; `1` stays). An unknown renderVersion exits 2. Every same-id file, and every file whose raw or embedded hash is recorded, must pass integrity and the recorded signature. A file whose raw sha256 equals the recorded sha256 or redactedSha256 matches, so an imported redacted copy verifies. When the payload records a fingerprint or originalFingerprint, that byte match requires a valid sidecar with the matching fingerprint, with or without `--require-sig`. When the payload is unsigned, a valid stray sidecar is ignored. An invalid sidecar exits 2. A local-store report does not accept a redact-then-hash stand-in, so an edit that redaction would hide still exits 2 (`receipt <id> at <path> fails integrity`, `signature mismatch`, or `differs from the signed payload`). A session-package report may match the redacted form, and a non-null originalFingerprint then requires that sidecar, so `report <package>.session` still verifies in the exporter's repo and a stripped re-hashed original does not. A package report records `originalSha256` (the pre-redaction hash) when this store still has that file, so deleting the original while the index or audit log lists it exits 2. A newest prune audit event is payload-only, including when this log has no capture, wrap, or watch event for that receipt. The reason is `receipt absent; audit.jsonl (unsigned) records a prune`. audit.jsonl is not signed, and anyone with write access can extend it, so that reason does not call the prune legitimate. A missing capture, wrap, or watch event for that receipt is not tampering: the prune is payload-only (exit 0) with that same reason. Exit 2 only when one of those events exists in this log and the prune is timestamped more than 5 seconds before it. Clock skew of up to 5 seconds stays payload-only. `source: retention` does not silence the unsigned-prune warning unless `maxCount`, `maxAgeDays`, or `autoPrune` is set; the warning then adds `(retention source claimed but no retention config found)`. A present `audit.jsonl` in the store being searched with a broken hash chain exits 2, and a chain-only failure is counted in `failed`. `--receipts` does not consult an unrelated audit.jsonl in the current directory. The candidate walk has a depth of 4 for `report last`, `report verify`, and `report --session`. A file at depth 5 or deeper is not a candidate. Share HTML shows bidi controls as `\uXXXX`, the same as the report. A symlink exits 2. `.MD` counts as a candidate. `--receipts` searches only that directory, and a referenced receipt missing there exits 2. Without `--receipts`, a missing receipt that the store index or audit log still lists exits 2. Otherwise the headline is `VERIFIED (payload only; N receipts not checked)` and `--json` uses `VERIFIED_PAYLOAD_ONLY`. `--require-sig` enforces the trust allowlist when one is configured. With no trust store it accepts any valid self-signed page and prints a one-line note; use `agent-receipt trust add --self` to pin keys. Bidi controls in rendered fields, including agent names, are shown as `\uXXXX`.

A clone with `core.autocrlf=true` rewrites a genuine report to CRLF and `report verify` exits 2 with `page has CRLF line endings — was it checked out with core.autocrlf? add *.report.html -text to .gitattributes`. A lone CR is `page has CR line endings`. A leading UTF-8 BOM exits 2. The check does not normalize those bytes. Add `*.report.html -text` and `.agent-receipt/** -text` to `.gitattributes` so Git leaves the report and the audit log alone. `report verify`, `audit --verify`, and `doctor` strip one trailing CR from each `audit.jsonl` line before the hash chain, so a checkout that still converts the log to CRLF verifies. Exactly one trailing CR is stripped. Two trailing CRs still fail the chain. If the chain still fails and the failing line itself ends in CR, the error names CRLF and `core.autocrlf`.

`verify --require-sig` (alias `--require-signature`) opts in to that sidecar.
The hash check still runs first. After it matches, a missing sidecar exits 2
(`signature required: signature absent`) and a bad sidecar exits 2 with the
signature reason. Default `verify` stays hash-only. There is no CA.

When a fingerprint trust store is configured, `--require-sig` also requires
the sidecar fingerprint to be on that allowlist. The store is
`.agent-receipt/trusted-keys.txt` (one lowercase 64-hex fingerprint per
line) unioned with `trustedFingerprints` in `.agent-receipt.yml`, plus
`--trusted-key` for one invocation. Empty or missing both means the
allowlist is inactive and any cryptographically valid sidecar still passes.
A listed store that does not include the fingerprint exits 2. Invalid lines
fail closed. `trust list` / `trust add` / `trust add --self` / `trust rm`
edit the file. `trust add --self` lists the local keygen fingerprint.
`trust show` reports that allowlist and whether the local key is listed.
It is read-only (it does not create keys and it does not edit the file).
This is a known-keys allowlist, not a certificate authority.

`keygen` writes a local Ed25519 keypair (Node `crypto` only) under
`.agent-receipt/keys/`. `sign` attests the receipt sha256 hex into
`foo.sig.json`, embedding the SPKI public key so a peer can check it
without that directory. The private key never leaves `.agent-receipt/keys/`
and is never written into a receipt or sidecar. Capture, wrap, and watch
sign when you pass `--sign` or when config `sign: true` (CLI `--no-sign`
overrides; missing keys leave the receipt unsigned and do not exit 2).
`init --org` does not set `sign`. `share` and Markdown `export` copy a valid sidecar when the published
sha256 matches the source. When redact rewrites the body, they re-sign the
published Markdown if local keys exist, and otherwise leave it unsigned
(no stale sidecar) with a short `keygen` / `sign` tip. HTML stays unsigned.
Peers verify and sign the Markdown. `share --package` puts that HTML and
the Markdown (plus optional `receipt.sig.json` and `manifest.json`) in one
`foo.share/` directory so a peer can open the page and still verify the proof.

`attest` (v1.0.32) writes that same local key over an in-toto Statement v1
wrapped in a DSSE envelope (`.intoto.jsonl`). The signature covers the DSSE
PAE bytes, not the receipt sha256 hex. Subjects are the receipt file and
changed files, each hashed as raw bytes. The predicate carries the run
(or SLSA Provenance v1 with `--slsa`) and the receipt hash-chain head.
Narrative fields are redacted first. A secret in a subject filename is
redacted too. Missing keys write an unsigned envelope and warn. The private
key is never included. `attest --verify` checks the signature, the subject
digests on disk, and the hash-chain head. An empty trust store accepts any
cryptographically valid signature. This is not a CA.
`export --format intoto` is the same writer and does not append the audit log.

`attest --keyless` (v1.0.33) signs one statement with an ephemeral P-256 key
and an OIDC token (a file, `SIGSTORE_ID_TOKEN`, or GitHub Actions
`id-token: write`). Fulcio issues a short-lived certificate. Rekor records
the entry. The bundle is `<stem>.sigstore.json`. The private key and the
token are never stored. Verify the bundle with `--certificate-identity` and
`--certificate-oidc-issuer`. See [`docs/keyless.md`](docs/keyless.md).
`sign --keyless` is not a command.

Thin local Ed25519 attest landed in 1.0.16. `verify --require-sig` and the
portable sidecar handoff landed in 1.0.17. A thin known-keys allowlist
landed in 1.0.18. A signed CI drop-in (`sign`, require-sig, trust examples)
landed in v1.0.19. `trust add --self` landed in v1.0.20. `prove --page`
landed in v1.0.21. Config `sign: true` and `--no-sign` landed in v1.0.22.
`trust show` landed in v1.0.23. `share --package` landed in v1.0.24
(HTML + signed Markdown in one directory; the HTML body stays unsigned).
`verify --package` and `import` landed in v1.0.25 (peer check of that
directory, then a copy of the proved Markdown). Auto-prune landed in v1.0.26
(`autoPrune: true` after capture, wrap, and watch when a retention limit is
set; a broken chain skips the delete). `prove --html` landed in v1.0.27
(offline, redacted HTML verification report; not itself signed). Thin
multi-agent receipt linking landed in v1.0.28 (session, parent, `wrap --link`,
`session`). Cross-host session merge landed in v1.0.29 (`session export`,
`session import`, optional `session-manifest.sig.json`). The signed one-page
HTML report landed in v1.0.30 (`report`, `report verify`). Native capture
adapters for Claude Code, Cursor, Grok CLI, and Codex, plus MCP tool-call
capture, landed in v1.0.31 (`adapters`, `capture --transcript`). in-toto
Statement v1 and SLSA Provenance v1 export landed in v1.0.32 (`attest`,
`export --format intoto`, DSSE). Sigstore keyless signing landed in v1.0.33
(`attest --keyless`, a Sigstore bundle, offline identity verify). Full PKI/CA, minisign,
GPG, default auto-sign on capture without that config, and a long-running
prune daemon are still deferred.

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
