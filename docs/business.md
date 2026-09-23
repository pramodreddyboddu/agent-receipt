# Business / production rollout

`agent-receipt` 1.0.22 for teams: install once, capture every session, fail CI
on high-severity findings, share only redacted HTML, and keep a local
audit log of capture, watch, wrap, share, export, and prune deletes. No SSO and no hosted service — see
[Enterprise (SSO-free)](#enterprise-sso-free).

This is **tamper-evident**, not access control and not a secret scanner.
Redaction is a heuristic mask (see [SECURITY.md](../SECURITY.md)). Treat a
green gate as a tripwire, not a clearance to ship credentials.

## Install

Requires **Node.js ≥ 20** and `git` on `PATH`.

```bash
npm i -g @pramodreddyboddu/agent-receipt
# or, before / without npm publish:
npm i -g github:pramodreddyboddu/agent-receipt

cd your-git-repo
agent-receipt init
agent-receipt doctor
```

Dev dependency:

```bash
npm install -D @pramodreddyboddu/agent-receipt
npx agent-receipt doctor
```

## Hooks

Local auto-capture stays **non-blocking** (a hook must not block `git commit`):

```bash
agent-receipt install-hooks            # post-commit
agent-receipt install-hooks --pre-push # also pre-push
```

Grok Build: `agent-receipt init --grok` installs a SessionEnd hook that wraps
a **dirty** tree with `--redact`. Trust it once (`grok --trust` or
`/hooks-trust`). The hook **does not wait for stdin EOF** — see
[Stdin contract](#sessionend-stdin-contract).

Cursor: `agent-receipt init --cursor` drops a rule that tells the agent to run
capture itself.

`agent-receipt doctor` prints a short **Prod ready** checklist: config, hooks,
whether `redact` is the default, policy, audit, retention, git clean, Cursor
init, Grok init. Only `FAIL` rows change the exit code (exit 1). Warnings are
non-fatal. `doctor --strict` is optional and still does not replace CI
`--fail-on` — see [Org policy](#org-policy).

`doctor --json` prints that same checklist as **one JSON object** on stdout
(`ok`, `command`, `version`, `exitCode`, `strict`, `checks`). `ok` is true
only when `exitCode` is 0. Each check is `{ id, status, detail }` with
status `pass`, `fail`, `warn`, or `info`. `--json` does not change the exit
code. It is a checklist for scripts, not the CI risk gate (`wrap --json`).

A broken `.agent-receipt/audit.jsonl` chain is WARN on default `doctor` and
does not change the exit code. `doctor --strict` promotes that row to FAIL
(exit 1) even when `outDir` is small. Unset org policy (`redact` + `failOn`)
is also FAIL under `--strict` on a small or empty `outDir`. Unset retention
fails `--strict` on any `outDir`. Default `doctor` still leaves that row
INFO/WARN until the directory is under pressure.

## Org policy

`agent-receipt init --org` (alias `--policy`) writes these two keys. On an
existing `.agent-receipt.yml` it merges: `ignore`, `riskAllowlist`, `outDir`,
and retention keys stay. Copying
[`examples/org-policy.yml`](../examples/org-policy.yml) is still fine when
you want the commented example as a starting file:

```yaml
redact: true    # capture / wrap / watch / share, unless --no-redact
failOn: high    # those commands exit 2 at high (or medium / low)
# sign: true    # after keygen; capture / wrap / watch. CLI --no-sign overrides.
```

- CLI `--fail-on` overrides config. Bare `--fail-on` means `high`.
- CLI `--redact` / `--no-redact` override config `redact`.
- **`sign: true`** signs `capture`, `wrap`, and `watch` after a successful write when a local Ed25519 keypair loads. `--sign` forces it on. `--no-sign` forces it off. Absent or `sign: false` leaves signing opt-in. Missing keys print a tip and leave the receipt unsigned. That does not exit 2. `init --org` does **not** set `sign` (a laptop may not have keys yet). Add the line after `keygen` and `trust add --self`. `share`, `export`, `prove`, and `verify` do not read this key. The CI composite input `sign: true` stays fail-closed and is independent of config. Not a CA.
- **`share` redacts unless `--no-redact`**, even when config `redact` is false.
- **`verify` ignores config `failOn`.** It stays an integrity check unless you
  pass `--fail-on`. Existing hooks that only run `verify` keep exit 0 on a
  valid receipt that happens to contain risk hints.

## CI gate

Run the gate in the job, not in the git hook. Hooks stay non-blocking; CI is
allowed to fail the build.

```yaml
- name: Agent receipt gate
  run: |
    agent-receipt wrap --base origin/${{ github.base_ref }} --json > "$RUNNER_TEMP/receipt-gate.json"
```

With `examples/org-policy.yml` installed you can omit `--fail-on` (config
supplies it). Pass `--fail-on high` anyway if the job should not depend on the
file being present.

Redirecting stdout does **not** hide the exit code:

| Exit | Meaning |
|------|---------|
| 0 | Gate passed. |
| 2 | `--fail-on` matched **and/or** `verify` failed. capture / wrap / share still write the artifact when they got that far. |
| 1 | Usage or runtime error (not a git repo, bad `--fail-on`, missing receipt). Not a policy failure. |

Stable rules:

- Both a policy hit and a verify failure are exit **2**. The JSON object says which (`failedOn`, `verified`). There is no third policy code.
- Invalid `--fail-on` (anything other than `high`, `medium`, `low`, or bare) is exit **1**.
- `--json` does not change exit codes.
- `watch --json` still writes the companion receipt file and keeps human stdout. Use `capture`, `wrap`, `share`, or `verify` for the gate object.

### `--json` gate object

`capture --json`, `wrap --json`, `share --json`, and `verify --json` print
**one JSON object** on stdout (no pretty-print, no log lines mixed in).
Progress stays on stderr. `capture` / `wrap` also still write the companion
receipt `.json` next to the Markdown (`docs/receipt.schema.json`) — that file
is the artifact, not the gate. The gate object itself is
[`docs/gate.schema.json`](gate.schema.json).

```json
{
  "ok": true,
  "command": "wrap",
  "version": "1.0.22",
  "exitCode": 0,
  "verified": true,
  "failedOn": false,
  "failOn": "high",
  "redacted": true,
  "uncommitted": false,
  "path": "/repo/.agent-receipt/receipts/receipt-….md",
  "jsonPath": "/repo/.agent-receipt/receipts/receipt-….json",
  "htmlPath": null,
  "markdownPath": null,
  "tldr": "wrap · … · risk none",
  "sha256": "…",
  "risk": { "high": 0, "medium": 0, "low": 0, "total": 0, "maxSeverity": null },
  "ignored": 0,
  "trailingIgnored": false,
  "reason": null
}
```

`ok` is true only when `exitCode` is 0. `verified` is `null` for `capture`
(it does not run verify). `trailingIgnored` is a boolean when the command
hashed a body (`verify`, and `wrap` / `share` after they verify). It is
`null` for `capture` and for usage errors. `verify --json` always includes
the boolean. `share` sets `htmlPath` / `markdownPath`. On exit 1 the same
shape is printed with `reason` set and the path fields null.

```bash
jq -e '.ok == true and .exitCode == 0' "$RUNNER_TEMP/receipt-gate.json"
```

You do not need `jq` for pass/fail — the process exit code is the gate.

## Share

```bash
agent-receipt share                          # newest receipt → sibling .html
agent-receipt share --out share.html --md share.md
agent-receipt share receipt.md --fail-on high --json
```

`share` is one shot: verify the **source** (a tampered receipt is not
rewritten), apply `--redact`, write self-contained HTML, optionally write
Markdown (`--md`), verify the published body, print TL;DR and paths.

It reuses `export` / `html` / `verify` / `redact`. Share-safety from 1.0.3
stays on: credential URLs (`DATABASE_URL`, `postgres://user:pass@…`), API keys,
and nested `.agent-receipt` diff bodies. Redaction re-hashes so `verify`
passes on the shared file. It does **not** prove the source was secret-free
before masking, and it will miss novel secret shapes.

Do not point `--out` or `--md` at the source receipt; share refuses to
overwrite it.

## Enterprise (SSO-free)

Nothing here phones home. A rollout is a config file, a CI job, and a
decision about what stays in `.agent-receipt/`. There is no SSO, no org
admin console, and no Cloud Agents product.

### Org policy

Run `agent-receipt init --org` (alias `--policy`), or copy
[`examples/org-policy.yml`](../examples/org-policy.yml) onto
`.agent-receipt.yml` and keep your local `ignore` / `riskAllowlist` lines.
That turns `redact` on for capture / wrap / watch and sets `failOn: high`.
`init --org` does the same two keys on an existing file without replacing
`ignore`. `share` already redacts unless `--no-redact`, even without this file.

`doctor` lists this as **policy**. INFO means it is not applied yet. Only
real **FAIL** rows change the exit code — the default checklist does not
block a laptop that has not adopted the file. CI should still pass `--fail-on`
so a missing config cannot silently weaken the job. `--fail-on` scans the
receipt risk summary. `doctor` does not.

`doctor --strict` is a separate prod gate, not a secret scan. It always
fails a broken audit chain (the audit row becomes `fail`, exit 1). It also
fails unset org policy (`redact: true` and `failOn`) on any `outDir`,
including a small or empty one. `doctor --json` reports that policy check
as `fail`. Unset retention (`maxCount` / `maxAgeDays`) also fails `--strict`
on any `outDir`, including a small or empty one. Set it with
`agent-receipt init --retention`. A limit that is set but would still delete
files stays a warning until you run `prune`. Default `doctor` still only
warns on a broken chain, leaves unset policy as INFO, and pressure-gates
unset retention (100 receipts or 20 MB).

```bash
agent-receipt init --org
agent-receipt doctor --json
agent-receipt doctor --strict --json
```

`checks` follows the human Environment then Prod ready order. Human output
stays the default when `--json` is omitted.

### CI gate

Hooks stay non-blocking. The failing check belongs in the PR job.

Copy one of:

| Example | What to do with it |
|---------|--------------------|
| [`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml) | Copy to `.github/workflows/agent-receipt-gate.yml`. `pull_request` runs `wrap --fail-on --json` (or `share`). Also callable as a reusable workflow. After a green gate it runs `prove --json` (`prove` defaults to true) and uploads `receipt-gate.json` plus the receipt Markdown (`actions/upload-artifact@v4`, name `agent-receipt-gate`). |
| [`examples/github/action.yml`](../examples/github/action.yml) | Composite action. Copy the directory to `.github/actions/agent-receipt/`. Optional `install` (`npm install -g`, pin `github:pramodreddyboddu/agent-receipt#v1.0.22`), `prove`, `sign` (default false; fails closed without keys and names `keygen`), `require-sig` (default false), and `trusted-keys` (file path or comma-separated fingerprints, installed before wrap). Outputs `ok`, `exit-code`, `sha256`, `path`, `gate-json`. |

### Drop-in

Copy the composite action and call it after checkout. `install: true` installs
from GitHub when you do not already have the CLI. `prove: true` runs
`prove --json` after a green wrap or share and fails the step unless `ok` is
true, `verified` is true, and `exitCode` is 0. The step prints that prove JSON.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: actions/setup-node@v4
  with:
    node-version: 20
- uses: ./.github/actions/agent-receipt
  with:
    install: true
    from: github:pramodreddyboddu/agent-receipt#v1.0.22
    prove: true
    fail-on: high
    base: origin/main
```

### Signed CI gate

Not a CA. Run `keygen` (or restore `.agent-receipt/keys`) before a job that
sets the action input `sign: true`. CLI `wrap --sign`, and config
`sign: true`, with missing keys only print a tip. `--no-sign` overrides
config for that run. The action input fails the step and does not read
config `sign`.

```bash
agent-receipt keygen
agent-receipt trust add --self
agent-receipt wrap --sign --fail-on high --json
agent-receipt prove --json
agent-receipt prove --page
agent-receipt verify --require-sig
```

`prove` reports `signature.ok`. With the allowlist, `signature.trusted` is
true and `verify --require-sig` exits 0. `trust add --self` writes the local
keygen fingerprint into `.agent-receipt/trusted-keys.txt`. It does not create
keys and it is not a CA. [`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml)
temp-`keygen`s when `require-sig` is true. If `trusted-keys` is empty, that
job runs `trust add --self`. A non-empty list is installed as given. Full
recipe: [`ci-signed-gate.md`](ci-signed-gate.md).

Or copy [`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml) to
`.github/workflows/agent-receipt-gate.yml`. That job always passes `--fail-on`
(a missing config cannot weaken the gate), proves after a green gate, and
uploads the gate JSON and the receipt. A missing receipt file after a green
gate does not fail the job. The gate object is documented in
[`docs/gate.schema.json`](gate.schema.json), next to
[`docs/receipt.schema.json`](receipt.schema.json). The optional Ed25519
sidecar is [`docs/signature.schema.json`](signature.schema.json).

Exit codes are unchanged: 0 pass, 2 policy and/or verify failure, 1 usage
error. The step prints the gate JSON from `$RUNNER_TEMP/receipt-gate.json`
before exiting. You do not need `jq`. The examples pass `--fail-on` so a
missing config cannot silently weaken the job. After a successful wrap or
share, `trailingIgnored` is a boolean when that field is set (`null` on
capture). The job still fails when `exitCode !== 0` or `ok !== true`.

This repo’s own [docs mirror](github-actions-ci.yml) runs a temp-repo
`wrap --json` + `prove --json` + `last --json` + `share --json` smoke, then
proves `doctor --strict` fails unset org policy and unset retention, and
passes after `init --org` plus `init --retention`,
plus `doctor --json`, `audit --event wrap`, `audit --agent ci --failed`,
`history --agent ci` / `history --uncommitted`, and `history --failed`. The live
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) does not include
that smoke yet: the checkout token cannot push workflow files. See
[Workflow scope](#workflow-scope).

### Share defaults

`agent-receipt share` redacts unless `--no-redact`. That is the handoff
for a person outside the repo (HTML, optional `--md`). Do not pass
`--no-redact` on artifacts that leave the trusted boundary. Redaction is
still a heuristic — read the HTML once. It masks common cloud tokens
(GitHub `ghp_` / `gho_` / `ghs_` / `ghu_` / `ghr_`, GitLab `glpat-`, npm,
Google `AIza` / `ya29.`, AWS `AKIA` / `ASIA`, Stripe, SendGrid, Slack,
Azure `AccountKey`, OpenAI `sk-` / `sk-proj-`, Anthropic `sk-ant-`,
Hugging Face `hf_`, Groq `gsk_`, xAI `xai-`, and `Authorization: Bearer`)
and still misses novel shapes.

### Audit log (experimental)

`capture`, `watch`, `wrap`, `share`, and `export` / `html` each append
one line to `.agent-receipt/audit.jsonl`. `prune` / `retain` append one
`prune` line per receipt they delete. `--dry-run` does not append, and
neither does a run that deletes nothing. Trusted prune does not append
when the chain is broken: it exits 1 and deletes nothing unless `--force`.

```bash
agent-receipt audit            # newest last, human
agent-receipt audit --json     # array, oldest first
agent-receipt audit --event wrap
agent-receipt audit --agent cursor
agent-receipt audit --agent ci --failed
agent-receipt audit --event wrap --agent ci --limit 20 --json
agent-receipt log --event prune
agent-receipt log --failed
agent-receipt audit --verify   # exit 0 intact, exit 2 if a line was edited
agent-receipt log --verify     # alias
```

`--event` keeps one of `capture`, `watch`, `wrap`, `share`, `export`, or
`prune` (the `event` field already written on each line). `--agent <name>`
keeps events whose `agent` field equals that name (exact string,
case-sensitive). An event with `agent: null` does not match any `--agent`
filter. `--failed` keeps events where `failedOn` is true or `exitCode` is
not 0.

Filter order: load the log, then `--event` (if set), then `--agent` (if
set), then `--failed` (if set), then `--limit` (newest N of what remains).
The human listing prints that slice oldest → newest (newest last). `--json`
prints the same slice as a JSON array, oldest first. No matches is exit 0
and an empty listing (`[]` with `--json`), not an error. An unknown
`--event` name exits 1. An unknown flag exits 1.

`audit --verify` ignores `--event`, `--agent`, `--failed`, and `--limit`
and checks the whole file. A short stderr note says so when a listing
filter is also passed.

Each line has `ts`, `event`, `path`, `sha256`, `agent`, `redacted`,
`verified`, `failedOn`, `exitCode`, and `prev`. `prev` is the SHA-256 of
the previous line, or `null` on the first. That is a local hash chain so
a quiet edit shows up in `--verify`. It is **not** a signature, not a
key, and not proof of who ran the command. `experimental` is set on
every line on purpose.

The log does not store diff bodies or `--message` (those are the usual
places a secret lands). It does store paths and the receipt hash. Treat
it as internal.

`wrap` writes one `wrap` line (the inner capture is not a second event).
`share` writes one `share` line (the inner export is not a second event).
`watch` writes one `watch` line per capture it makes. `prune` writes one
`prune` line per deleted receipt (the sibling `.json` is not a second
line). Index rows that were already missing are not events.

`doctor` reports **audit**: INFO if the file is not there yet, PASS when
the chain matches, WARN if it does not. WARN does not fail default `doctor`.
`doctor --strict` turns that broken chain into FAIL and exits 1. Unset org
policy also fails under `--strict` with no pressure gate. Unset retention
fails under `--strict` on any `outDir`. Default `doctor` still pressure-gates
that row.

Editing a line in place breaks the chain on purpose. To rotate, move the
file aside and let the next command start a new one (`prev: null`).
`prune` does not delete or rewrite `audit.jsonl`.

### Prove this run

`prove` is the one-screen check that a receipt still matches its hash and
that the local audit log still links it. It also reports a local Ed25519
sidecar when `sign` wrote one. Default `verify` stays hash-only.
`verify --require-sig` requires a valid sidecar. When a known-keys
allowlist is configured, the sidecar fingerprint must be listed. This is
not a CA. The private key never leaves `.agent-receipt/keys/`.

```bash
agent-receipt keygen
agent-receipt sign
agent-receipt prove
agent-receipt prove --json
agent-receipt prove receipt.md --fail-on high
agent-receipt last --json
```

`keygen` writes `ed25519.private` (PKCS8 PEM, mode 0600) and
`ed25519.public` (SPKI PEM) under `.agent-receipt/keys/`. The key
fingerprint is the lowercase hex SHA-256 of the DER SPKI bytes. Re-running
without `--force` leaves the pair unchanged. `sign` hash-checks the receipt
first (exit 2, no sidecar, when the hash fails), then signs the sha256 hex
string as UTF-8 bytes. `foo.md` gets `foo.sig.json` with `alg`, `version`,
`sha256`, `fingerprint`, `signature`, and `publicKey`. Capture, wrap, and
watch call `sign` when you pass `--sign` or when config `sign: true`
(missing keys leave the receipt unsigned; `--no-sign` overrides;
`init --org` does not set `sign`). `share` and Markdown `export` copy a valid sidecar when
the published sha256 matches, and re-sign the published Markdown when the
body was rewritten and local keys exist. A rewritten file with no keys is
left unsigned (no stale sidecar). HTML is unsigned. Peers verify and sign
the Markdown. `verify --require-sig` is how a peer requires that sidecar.

`prove --json` is one object: `ok`, `command` (`prove`), `version`,
`exitCode`, `verified`, `trailingIgnored`, `failedOn`, `failOn`, `redacted`,
`uncommitted`, `path`, `sha256`, `tldr`, `agent`, `risk`, `audit`
(`present`, `chainOk`, `events`, `matched`, `reason`), `signature`
(`present`, `ok`, `alg`, `fingerprint`, `reason`, `trusted`), and `reason`.
`trusted` is true when the known-keys allowlist lists the fingerprint,
false when an active allowlist rejects it, and null when the allowlist is
inactive.
`ok` is true only when `exitCode` is 0.

`prove --page` (alias `--one-pager`) writes that same report as a
shareable Markdown one-pager. `foo.md` becomes `foo.prove.md` in the same
directory. A receipt that is not named `.md` gets `<name>.prove.md`.
`--out <path>` overrides the destination: an existing directory, or a path
ending in `/`, receives `<stem>.prove.md` inside it; any other path is the
file. Human stdout keeps PROVED or FAILED and prints one `page:` line.
`--json --page` adds `pagePath`. Without `--page`, nothing is written.
A failed prove (exit 2) still writes the page, with verdict FAILED.
The page is not itself signed, not a CA, and not access control. It does
not append the audit log. `last`, `history`, and `prune` ignore
`*.prove.md` so the page is not the next receipt. HTML export of the
one-pager stays deferred.

`signature.ok` is null when no sidecar is present, and that alone does not
change the exit. A sidecar that verifies against the current receipt sha256
is `ok: true`. A present sidecar that is invalid, mismatched, or malformed
is `ok: false` and the exit is 2. Peers use the embedded `publicKey`; they
do not need the local keys directory.

Exit 0 when the hash matches, the audit log is absent or intact, and the
signature is absent or valid. Exit 2 when the body fails verify, the chain
is broken, a present signature fails, or explicit `--fail-on` trips. Exit 1
when the receipt is missing or a flag is bad. Config `failOn` does not
apply — pass `--fail-on` if this invocation should also enforce risk.

`last --json` is a different object (`command: "last"`): path, sha256, agent,
message, timestamp, failedOn, uncommitted, and TL;DR. It prefers the index
row for agent, failedOn, uncommitted, and sha256. No receipt exits 1. With
`--path` and `--json` together, `--json` wins.

### Retention for `.agent-receipt/`

| Path | Contains | Guidance |
|------|----------|----------|
| `receipts/*.md` and sibling `.json` | Diffs, maybe secrets before redaction | Prefer local or a CI artifact with a short retention (14–30 days is a reasonable team default). Do not commit a receipt that captured a live secret — rotate the credential. |
| `index.json` | Paths, agent, message, risk counts, sha256, and `failedOn` on rows captured from 1.0.12 (gate result; older rows omit it). No diff body. | Messages are stored in the clear. `prune` drops rows for receipts it deletes, and rows under outDir whose files are already gone. |
| `audit.jsonl` | capture / watch / wrap / share / export / prune metadata and hashes. No diff, no message. | Safer to keep longer than receipt bodies (90 days is a reasonable default). Still not a public artifact. `prune` appends to it and does not delete or rewrite earlier lines. |
| `share` HTML / `--md` | Redacted receipt | The file you attach. Glance it first. HTML written outside outDir is not pruned. |

Deletion is **opt-in**. Until you set a limit, `prune` exits 0 and deletes
nothing. Capture, wrap, and watch never delete old receipts.

```yaml
# .agent-receipt.yml — both optional; set either or both
maxCount: 100      # keep the newest 100 receipts
maxAgeDays: 30     # delete receipts strictly older than 30 days
```

```bash
agent-receipt prune --dry-run                  # plan only
agent-receipt prune                            # apply config
agent-receipt prune --max-count 50 --dry-run   # flags override config for this run
agent-receipt retain --max-age-days 14         # alias of prune
```

Rules:

- A receipt is a `*.md` file **directly** under `outDir` that is listed in
  the index, named `receipt-*.md`, or has an `agent-receipt-sha256` footer.
  `SETUP.md` is not a receipt. Nested directories are not walked.
- Newest is the index timestamp when the row exists, otherwise file mtime.
- With both limits, a file is kept only when it is among the newest
  `maxCount` **and** not strictly older than `maxAgeDays`. A receipt
  exactly `maxAgeDays` old is kept.
- The sibling `<name>.json` next to a deleted receipt is deleted with it.
  `index.json`, `audit.jsonl`, and symlinks are not deleted.
- `outDir` must be a directory **inside** the repo and not the repo root.
- If `index.json` is not valid JSON, `prune` exits 1 and deletes nothing.
- The index is rewritten with a temp file and rename. If that write fails
  after files were removed, run `prune` again — it drops rows whose files
  are already gone.
- `--dry-run` does not delete, does not rewrite the index, and does not append `audit.jsonl`.
- An applied delete appends one `prune` audit line per receipt (no diff, no `--message`). `prune --json` repeats those identity fields on each `deleted` row and sets `audited` to the number of lines written (`0` on dry-run).
- **Trusted prune.** When `.agent-receipt/audit.jsonl` exists, `prune` runs `verifyAuditChain` before it deletes anything. A broken chain exits 1, deletes nothing, and appends no audit line. Dry-run exits 1 as well: the JSON may still list candidates in `deleted`, with `ok: false`, `chainOk: false`, `auditPresent: true`, and a `reason`. It does not claim those deletes will proceed. A missing audit log is fine. `prune --force` is break-glass and deletes even when the chain is broken. `agent-receipt init --retention` sets `maxCount: 100` and `maxAgeDays: 30` without replacing `ignore` or `redact`. Retention must not paper over a broken audit chain. `doctor --strict` fails unset retention on any `outDir`. Default `doctor` still pressure-gates that row.
- `maxCount` and `maxAgeDays` must be integers `>= 1`. `0` is rejected so
  a typo cannot wipe the directory.
- `doctor` **retention**: INFO when opt-in is off and the directory is
  small; WARN when 100 or more receipts **or** 20 MB or more sit in
  `outDir` with no limit, or when a configured limit would delete
  something; FAIL when the keys are invalid or `outDir` is unsafe to
  prune. WARN does not fail default `doctor`. With `--strict`, unset
  `maxCount` / `maxAgeDays` is FAIL on any `outDir`, including a small or
  empty one (`agent-receipt init --retention`). A set limit that would
  still delete stays WARN. Default `doctor` still warns only at 100
  receipts or 20 MB when the limit is unset.

This package gitignores `.agent-receipt/` in its own repo. Your repo
chooses. A local-only choice:

```gitignore
.agent-receipt/
```

Commit receipts only when they are the review artifact you meant to keep,
and prefer `share` output over a raw capture when the audience is wider
than the people who can already read the git history.

### History

`history` and `ls` list receipts newest first. They use
`.agent-receipt/index.json` when it has rows, and otherwise scan `outDir`.

```bash
agent-receipt history --agent cursor
agent-receipt history --uncommitted --json
agent-receipt history --failed
agent-receipt history --agent ci --failed --json
agent-receipt ls --agent ci --uncommitted --limit 5
```

`--agent <name>` keeps receipts whose `agent` field equals that name (exact
string, case-sensitive). `agent: null` or a missing agent does not match.
`--uncommitted` keeps receipts where `uncommitted` is true.
`--failed` keeps receipts that failed the gate. From 1.0.12 the index stores
`failedOn` (`true` when fail-on tripped, `false` when it did not). That
boolean wins: a stored `false` stays out of `--failed` even if the risk
summary is high. Older rows omit the field and match when `risk.high > 0`
or `risk.maxSeverity` is `high`. A scan (no index) matches a high-severity
risk row. Medium or low alone does not match. The companion receipt `.json`
carries the same `failedOn` boolean when capture writes it.

Filter order: load receipts, then `--agent` (if set), then `--uncommitted`
(if set), then `--failed` (if set), then `--limit` (newest N of what remains).
`--json` is that same slice, still a JSON array. Each row includes `failedOn`.
Scan rows also include `uncommitted`. No matches is exit 0 and an empty
listing (`[]` with `--json`). An empty receipt store still errors, same as
`history` with no flags. Unknown flags exit 1. `--agent` requires a name.
`--failed` takes no value. Matching rows show a `[failed]` badge.

### Deferred

A signed CI drop-in landed in 1.0.19 (`sign` on the composite action and
`pr-gate.yml`, auto-trust of the temp fingerprint when `require-sig` is set
and `trusted-keys` is empty, and [`ci-signed-gate.md`](ci-signed-gate.md)).
`trust add --self` landed in 1.0.20: it loads the local keygen fingerprint
into `.agent-receipt/trusted-keys.txt`. The pr-gate auto-trust path uses that
command. It is not a CA. Config `sign: true` and CLI `--no-sign` landed in
1.0.22: capture, wrap, and watch sign after a successful write when local
keys exist. Missing keys tip and leave the receipt unsigned (not exit 2).
`init --org` does not set `sign`. share, export, prove, and verify do not
read the key. The CI composite input `sign: true` stays fail-closed.
`prove --page` landed in 1.0.21: a plain-English one-pager (`foo.prove.md`)
a human can open without the full receipt. The page is not signed.
A thin known-keys allowlist landed in 1.0.18 (`.agent-receipt/trusted-keys.txt`,
config `trustedFingerprints`, `verify --require-sig` and `prove` when the
store is non-empty, `doctor` trust row, `trust list|add|rm`, and opt-in
`capture --sign` / `wrap --sign`). Empty or missing means the allowlist is
inactive. It is not a CA. `verify --require-sig` and the portable Markdown
sidecar handoff landed in 1.0.17. Share and export copy a valid sidecar when
the published sha256 matches, and re-sign a rewritten Markdown file when
local keys exist. `doctor --strict` fails unset retention on any `outDir`.
Default `doctor` stays pressure-gated. A missing trust store does not fail
`doctor` or `doctor --strict`. Thin local Ed25519 attest landed in 1.0.16
(`keygen`, `sign`, prove `signature`, `docs/signature.schema.json`). It
signs the receipt sha256 with a key that stays under `.agent-receipt/keys/`.
Full PKI/CA is still deferred. Minisign, GPG/OpenPGP, default auto-sign
on capture without config (signing stays opt-in via config `sign: true` or
`--sign`), `trust show`, an HTML/share signed package (and a signed
one-pager), unsigned HTML prove export (`--html`), a background deleter,
and multi-agent receipt linking are still deferred. Config `sign: true` /
`--no-sign` landed in 1.0.22. The prove-for-humans
one-pager landed in 1.0.21. Drop-in CI/PR
gate polish landed in 1.0.15 (composite action with `install` / `prove` /
step outputs, `pr-gate.yml` prove + artifact upload, and
`docs/gate.schema.json`). Trusted retention landed as `init --retention`
(`maxCount: 100`, `maxAgeDays: 30`) and trusted prune (a broken audit chain
refuses the delete, including dry-run, unless `prune --force`). Fail-closed
org policy landed in 1.0.14 (`doctor --strict` always fails unset `redact` +
`failOn`, including a small `outDir`; `init --org` / `init --policy` sets
those keys). Prove-this-run UX landed in 1.0.13 (`prove`, audit link,
`last --json`, `trailingIgnored` on the gate). Also deferred: SSO / IdP,
Cloud Agents, a background job that deletes receipts by itself, live GitHub
Actions workflow sync (the checkout token has no `workflow` scope), and npm
Trusted Publishing (this cut does not publish). `prune` stays manual.
Missing signing keys do not fail `doctor` or `doctor --strict`. CI `--fail-on` is still the enforcement point for risk. A broken audit chain still fails `--strict`.
`doctor --json`, `audit --event`, `audit --agent`, `audit --failed`,
`history --agent`, `history --uncommitted`, `history --failed`, and `prove`
are checklist and listing tools; they do not sign the audit log.

### Workflow scope

Pushing `.github/workflows/*` needs the GitHub OAuth **`workflow`** scope
in addition to `repo`. Confirm with `gh auth status` (look for `workflow`
under Token scopes). The token used for the 1.0.6 through 1.0.22 cuts had
`gist`, `read:org`, and `repo` only — no `workflow` — so the live workflow
file was left unchanged and
[`docs/github-actions-ci.yml`](github-actions-ci.yml) is the copy to install:

```bash
gh auth refresh -h github.com -s workflow
cp docs/github-actions-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: share --json smoke"
git push
```

Fine-grained personal access tokens need repository **Actions: Read and write**
(and Contents: Read and write). GitHub Apps need the **Workflows** permission.
Do not force-push. Do not commit a PAT.

## SessionEnd stdin contract

Grok (and anything else that execs `.grok/hooks/agent-receipt-wrap.sh` or
`scripts/grok-wrap.sh`) may write a JSON event on stdin and **leave the pipe
open**. The scripts must not block waiting for EOF.

- A terminal stdin is not read and is not redirected.
- Otherwise **`node` is preferred** when it is on `PATH`. It drains until
  `HOOK_STDIN_MAX` bytes (default 65536, capped at 1 MiB), EOF, or
  `HOOK_STDIN_WAIT_SEC` (default `0.4`). After the first chunk it stops on
  ~30ms of quiet, so a short payload returns even when the writer never
  closes the pipe. Several chunks are consumed, not only the first `read`.
- If `node` is missing, GNU `timeout` + `dd` does one `read(2)` (`count=1`
  is not a full block). That path runs only when `timeout` accepts the wait
  value. BusyBox `timeout` rejects decimals such as `0.4` and is skipped —
  a failing `timeout` must not look like a successful drain.
- After that bounded drain, stdin is redirected from `/dev/null`. A host
  blocked on a full write gets `EPIPE` instead of stalling for the rest of
  wrap. Oversized payloads (above `HOOK_STDIN_MAX`) can see that `EPIPE`;
  that is intentional. The scripts do not `cat` until EOF.
- The payload is discarded. Whether to wrap comes from `git status`, not from
  the JSON. A clean tree exits 0 without wrapping.

## What not to put in receipts

Receipts store diffs. If a secret was in the change, it is in the receipt
until you redact — and redaction can miss it.

Do not:

- Commit or attach `.env`, private keys, cloud credentials, session tokens,
  customer data, or connection strings and then share the raw Markdown.
- Paste an unredacted receipt into a ticket, chat, or PR comment. Use
  `agent-receipt share` (HTML) and read it once before sending.
- Commit receipts that captured a secret diff, even after you think you
  deleted the file from git. Rotate the credential.
- Treat `risk none` or exit 0 as “no secrets.” The scanner is a heuristic.
- Rely on nested receipts as an archive. With `--redact`, prior
  `.agent-receipt` diff bodies are omitted so old secrets are not copied
  forward; without it, they are just more text.
- Put production data in `--message`. The message is stored in the clear and
  shown in `history`.

Keep receipts in `.agent-receipt/receipts/` and decide explicitly whether that
directory is committed, CI-artifact-only, or local. Prefer artifacts for
anything that might have touched secrets, and prefer `share` output over the
raw capture when a person outside the repo will read it.
