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
agent-receipt prove             # hash + audit link + signature status
agent-receipt prove --page      # human one-pager beside the receipt (foo.prove.md)
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
| `init [--cursor] [--grok] [--org] [--retention] [--auto-prune]` | Write `.agent-receipt.yml` + notes. `--org` (alias `--policy`) sets `redact: true` and `failOn: high` without replacing local `ignore`. `--retention` sets `maxCount: 100` and `maxAgeDays: 30` the same way and does not turn `autoPrune` on. `--auto-prune` sets `autoPrune: true` without replacing ignore, redact, or the limits. `--cursor` / `--grok` drop agent rules |
| `capture` | Git snapshot → Markdown receipt (+ optional JSON). `--sign` writes `*.sig.json` when local keys exist |
| `wrap` | End of session: capture (+ `--uncommitted` if dirty) → TL;DR + path → verify. `--sign` is opt-in, same as capture |
| `share [path]` | One shot: redact → HTML (+ optional Markdown) → verify → paths + TL;DR. `--package` writes `foo.share/` with HTML, Markdown, optional `receipt.sig.json`, and `manifest.json`. Markdown sidecar is copied or re-signed; HTML stays unsigned |
| `export` / `html` | Self-contained HTML receipt (or Markdown); `--out`, `--redact`. Markdown uses the same sidecar handoff. HTML stays unsigned |
| `show [path]` | Pretty-print last / given receipt (full body) |
| `last` | Path + glance of the most recent receipt. `--json` prints one object (`path`, `sha256`, agent, `failedOn`, `uncommitted`, TL;DR). `--json` wins over `--path` |
| `history` / `ls` | List recent receipts (`--agent`, `--uncommitted`, `--failed`, `--json`, `--limit`; `[uncommitted]` and `[failed]` badges; index at `.agent-receipt/index.json` stores `failedOn`) |
| `watch` | Poll git; auto-capture on commits **or dirty tree** (`--once`, `--commits-only`) |
| `keygen [--force]` | Create a local Ed25519 keypair under `.agent-receipt/keys/` (PKCS8 private, SPKI public). Idempotent; `--force` rotates. No network |
| `sign [path]` | Hash-check a receipt, then write `foo.sig.json` over the sha256 hex. Missing keys exit 1. Hash failure exits 2 and writes nothing. Capture and wrap sign only with `--sign` |
| `trust` | Known-keys allowlist: `list`, `show`, `add <fp>`, `add --self`, `rm <fp>` on `.agent-receipt/trusted-keys.txt`. `trust show` is read-only and reports whether the local key is listed. Not a CA |
| `verify [path]` | Hash-check tamper-evident integrity. Default stays hash-only (unsigned receipts still pass). `--package` checks a `share --package` directory (manifest, file hashes, receipt, optional signatures). `--require-sig` requires a valid `*.sig.json` and, when a trust store is configured, a known fingerprint. `--json` includes `trailingIgnored` (boolean) |
| `import <dir>` | Verify a share package, then copy `receipt.md` (and `receipt.sig.json` when present) into the local receipt store. `--dry-run` writes nothing. Not a local capture |
| `prove [path]` | Prove-this-run: same hash as `verify`, plus trailing content, risk, an audit-log link, and signature status when a sidecar is present. `--json` adds `signature` (`trusted` is null when the allowlist is inactive). `--page` writes `foo.prove.md` (plain English; not itself signed). Config `failOn` is not applied |
| `audit` / `log` | Local log of capture, watch, wrap, share, export, and prune deletes (`.agent-receipt/audit.jsonl`, experimental hash chain). `--event`, `--agent`, and `--failed` filter the listing |
| `prune` / `retain` | Delete old receipts under `outDir` when `maxCount` / `maxAgeDays` is set (`--dry-run` does not delete or audit; off by default). Trusted prune refuses the delete when the audit chain is broken (`--force` is break-glass). `autoPrune: true` or `--prune` runs that same path after capture, wrap, and watch (no `--force`; a broken chain warns and does not fail the capture) |
| `doctor` | Health check plus a prod checklist (policy, audit, keys, trust, retention, autoPrune, hooks, redact, git clean, Cursor/Grok). `--json` for scripts. `--strict` fails unset org policy (`redact` + `failOn`), unset retention (`maxCount` / `maxAgeDays`), a broken audit chain, and an invalid trust store. A missing trust store stays INFO. Unset `autoPrune` stays INFO and does not fail `--strict`. Default doctor still pressure-gates unset retention. Missing signing keys stay INFO |
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

Full recipe: [`docs/grok-cli.md`](docs/grok-cli.md). The SessionEnd hook drains
stdin with a byte cap and a short timeout so an open pipe (no EOF) cannot hang
the session.

Team install, CI gates, audit log, retention, and what not to put in receipts:
[`docs/business.md`](docs/business.md). Org defaults:
[`examples/org-policy.yml`](examples/org-policy.yml). Drop-in PR gate:
[`examples/github/action.yml`](examples/github/action.yml) (copy to
`.github/actions/agent-receipt/`; `install` pin
`github:pramodreddyboddu/agent-receipt#v1.0.26`, optional `prove`, optional
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
set; a broken chain skips the delete). Full PKI/CA, minisign, GPG,
default auto-sign on capture without that config, a signed one-pager,
`prove --html`, and a long-running prune daemon are still deferred.

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
