# Business / production rollout

`agent-receipt` 1.0.34 for teams: install once, capture every session, fail CI
on high-severity findings, share a redacted HTML + Markdown package (or HTML
alone), verify that package with `verify --package`, hand a reviewer a signed
one-page HTML report (`report` / `report verify`), and keep a local
audit log of capture, watch, wrap, share, export, and prune deletes. When
`autoPrune: true` and a retention limit is set, capture, wrap, and watch
delete old receipts with the same trusted prune (a broken audit chain skips
the delete and does not fail the capture). No SSO and no hosted service — see
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
  "version": "1.0.34",
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
agent-receipt share --package                 # foo.md → foo.share/
agent-receipt share receipt.md --fail-on high --json
```

`share` is one shot: verify the **source** (a tampered receipt is not
rewritten), apply `--redact`, write self-contained HTML, optionally write
Markdown (`--md`), verify the published body, print TL;DR and paths.

`share --package` (alias `--pack`) writes that handoff as a directory so a
peer can open the HTML and still verify the Markdown. `foo.md` becomes
`foo.share/` next to the receipt. `--out` overrides the directory when it
names an existing directory or ends with `/`. Inside it:

| File | Role |
|------|------|
| `receipt.html` | Redacted HTML. The HTML body stays unsigned. |
| `receipt.md` | Redacted Markdown. Package implies `--md`. |
| `receipt.sig.json` | Copied or re-signed with the same sidecar rules as `share --md`. Omitted when a rewrite has no local keys (no stale sidecar). |
| `manifest.json` | Small index: kind `agent-receipt-share`, CLI version, receipt sha256, `redacted`, per-file byte hashes, `fingerprint`, `signed`. See [`share-package.schema.json`](share-package.schema.json). |
| `manifest.sig.json` | Optional. Same Ed25519 sidecar as `sign`, over the sha256 hex of the manifest bytes. Written when local keys load. Missing keys omit it and do not exit 2. |

Peers open `receipt.html`, then run `verify --package` (alias `--pack`) on
the directory, or pass `manifest.json`. A directory whose manifest kind is
`agent-receipt-share` is detected without the flag. The check covers the
manifest, every file hash, `receipt.md`, and optional `receipt.sig.json` /
`manifest.sig.json`. HTML stays a byte hash. It is not signed. `import <dir>`
runs that check and, on success, copies `receipt.md` and the receipt sidecar
into the local outDir as `receipt-import-<sha12>.md`. It does not copy HTML
or the manifest, does not append the audit log, and does not add an index
row. `verify`, `prove`, or `verify --require-sig` on `receipt.md` still work.
`--json` on share adds `packagePath` and points `htmlPath` / `markdownPath` /
`sigPath` at those files. Package verify `--json` stays command `verify` and
adds `filesOk`, `manifestOk`, `manifestSig`, `signed`, and `fingerprint`.
Without `--package`, share is unchanged. `last`, `history`, and `prune` ignore
`*.share/` directories. This is not a CA.

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
| [`action.yml`](../action.yml) | Published composite action. `uses: pramodreddyboddu/agent-receipt@v1`. See [`docs/github-action.md`](github-action.md). |
| [`examples/github/action.yml`](../examples/github/action.yml) | Older copy-in composite. Copy the directory to `.github/actions/agent-receipt/`. Optional `install` (`npm install -g`, pin `github:pramodreddyboddu/agent-receipt#v1.0.34`), `prove`, `sign` (default false; fails closed without keys and names `keygen`), `require-sig` (default false), and `trusted-keys` (file path or comma-separated fingerprints, installed before wrap). Outputs `ok`, `exit-code`, `sha256`, `path`, `gate-json`. |

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
    from: github:pramodreddyboddu/agent-receipt#v1.0.34
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
agent-receipt trust show
agent-receipt wrap --sign --fail-on high --json
agent-receipt prove --json
agent-receipt prove --page
agent-receipt prove --html
agent-receipt verify --require-sig
```

`prove` reports `signature.ok`. With the allowlist, `signature.trusted` is
true and `verify --require-sig` exits 0. `trust add --self` writes the local
keygen fingerprint into `.agent-receipt/trusted-keys.txt`. It does not create
keys and it is not a CA. `trust show` (alias `trust status`) is read-only.
It reports whether the allowlist is active, the count, sources, fingerprints,
the local keygen fingerprint when keys load, and `localListed` (whether that
key is on the allowlist). Missing keys stay exit 0 (`localListed` is n/a).
When a local key exists and is not listed, the report names `trust add --self`.
It does not create keys, does not edit the allowlist, and does not edit config.
[`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml)
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
`*.prove.md` so the page is not the next receipt.

`prove --html` (1.0.27) renders the same report as one self-contained,
offline HTML verification report a reviewer can open in any browser:
`foo.md` becomes `foo.prove.html` (same `--out` rules as `--page`). It
opens with a PASS or FAIL banner (PASS means exit 0), then the hash check,
SHA-256, audit chain, Ed25519 signature and trust status, redaction, and a
receipt summary (agent, time, branch, HEAD, message, TL;DR, files, lines,
risk findings). Share-safe by default: every receipt-derived string goes
through the same secret redaction as `share`, secret-bearing risk details
are masked, text is HTML-escaped, and URLs are defanged. Inline CSS only;
no scripts, links, images, fonts, or network, and a `default-src 'none'`
CSP. A failed prove still writes the report with a FAIL banner and the
same exit code. `--json --html` adds `htmlPath`. `--page --html` writes
both (`--out` must then be a directory). The report is not itself signed,
not a CA, and does not append the audit log. `*.prove.html` is not a
receipt. Upload it as a CI artifact so reviewers can read the proof
without installing anything.

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
| `*.share/` | Portable handoff: `receipt.html`, `receipt.md`, optional `receipt.sig.json`, `manifest.json` | The directory you send. `last`, `history`, and `prune` ignore it. HTML inside it stays unsigned. |

Deletion is **opt-in**. Until you set a limit, `prune` exits 0 and deletes
nothing. Capture, wrap, and watch delete old receipts only when `autoPrune`
is true (or you pass `--prune`) **and** `maxCount` and/or `maxAgeDays` is
set. Both are required. `init --retention` sets the limits and does not
turn `autoPrune` on.

```yaml
# .agent-receipt.yml — limits optional; set either or both
maxCount: 100      # keep the newest 100 receipts
maxAgeDays: 30     # delete receipts strictly older than 30 days
autoPrune: true    # after capture / wrap / watch; still needs a limit above
```

```bash
agent-receipt init --retention              # limits only; autoPrune stays off
agent-receipt init --auto-prune             # autoPrune: true; limits unchanged
agent-receipt init --retention --auto-prune
agent-receipt wrap --no-prune               # this run does not delete
agent-receipt wrap --prune                  # this run deletes when a limit is set
```

`--no-prune` wins, then `--prune`, then config `autoPrune`. Auto-prune calls
the same trusted prune as `agent-receipt prune` and does not pass `--force`.
A broken audit chain deletes nothing, warns on stderr, and does not change
the capture, wrap, or watch exit code. The receipt just written stays.
Manual `prune` still exits 1 on a broken chain. If prune throws (invalid
retention, unsafe `outDir`, broken index), the capture warns and still
exits with the capture result. share, export, verify, prove, import, and
doctor do not auto-prune. This is not a daemon or cron.

capture and wrap `--json` add `autoPrune`, `pruned`, and `pruneReason` only
when the run attempted auto-prune. `pruneReason` is null when trusted prune
ran, or `failed-run` (fail-on or verify failure; nothing deleted),
`retention-off`, `chain-broken`, or `error`. The fields are omitted
when auto-prune was off. Human stdout prints `pruned: N receipt(s)` when
something was deleted, and a short skip line when the chain broke.

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
- **Trusted prune.** When `.agent-receipt/audit.jsonl` exists, `prune` runs `verifyAuditChain` before it deletes anything. A broken chain exits 1, deletes nothing, and appends no audit line. Dry-run exits 1 as well: the JSON may still list candidates in `deleted`, with `ok: false`, `chainOk: false`, `auditPresent: true`, and a `reason`. It does not claim those deletes will proceed. A missing audit log is fine. `prune --force` is break-glass and deletes even when the chain is broken. `agent-receipt init --retention` sets `maxCount: 100` and `maxAgeDays: 30` without replacing `ignore` or `redact`, and does not set `autoPrune`. `init --auto-prune` sets `autoPrune: true` without replacing those keys. Retention must not paper over a broken audit chain. `doctor --strict` fails unset retention on any `outDir`. Default `doctor` still pressure-gates that row. The `autoPrune` doctor row is INFO when unset, PASS when true with a limit, and WARN when true with no limit. That WARN does not fail `doctor` or `doctor --strict`. Unset `autoPrune` does not fail `--strict`.
- **Auto-prune.** After a successful capture, wrap, or watch write, `autoPrune: true` (or `--prune`) runs that trusted prune. It does not pass `--force`. A broken chain skips the delete and does not fail the capture. Applied deletes still append one `prune` audit line per receipt. Not a daemon.
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

### Linking multi-agent runs

A receipt can name the session it belongs to and the parent receipt that spawned it. `capture`, `wrap`, and `watch` take `--session`, `--parent`, and `--agent`. The same values fall back to `AGENT_RECEIPT_SESSION`, `AGENT_RECEIPT_PARENT`, and `AGENT_RECEIPT_AGENT` so a parent process can hand them to a child. Flags win. `wrap --link` (or `--session`, including `--session new`) writes the fields and exports the session and this receipt's id into the command after `--`. Nested wraps then share one session.

Those fields are inside the hashed `## Session` header. A receipt is 1.0.28+ only when two checks both pass. The bytes from the title line through the end of `## Session` must match the 1.0.28 writer grammar, parsed with fence awareness off. The grammar is the title `# Agent Receipt`, then only the writer's TL;DR lines (`> **TL;DR**`, blank lines, and `> `-quoted message lines), then `## What to review` with the writer's body (a blank line, either the nothing-flagged sentence or numbered review items, a blank line), then `## Summary` with the writer's metric table, then `## Session` with fields in writer order (Version, Timestamp, Branch, HEAD, optional Remote, Range, Snapshot only after an uncommitted Range, optional Id, Agent, Session, Parent, Host, and Message, then Workspace, then the optional redaction notice), then the heading the writer emits next (`## Notable changes`, `## Commits`, or `## Files changed`). A raw line, a fence (`` ``` `` or `~~~`, any info string), an extra heading, a CR-only or mixed line ending, or an out-of-order field in that region fails the grammar. Uniform CRLF is accepted; a bare CR line ending is not. The whole file is then scanned line by line with fences ignored: a line inside a fence still counts. There must be exactly one line equal to `# Agent Receipt`, exactly one equal to `## What to review`, and exactly one equal to `## Session`. If any count is not one, the receipt is pre-1.0.28 and parsers read no link metadata from it. There is no fallback `## Session`. When the TL;DR line contains a timestamp, it must match the header Timestamp. A TL;DR with no timestamp skips that check. The 1.0.28 writer emits one and it matches. A diff or message that contains `- **Session**:` lines does not create a link. Receipts written by 1.0.27 or earlier have no link metadata and verify, require a signature, and prove with the same exit codes as before. Those writers quote only the first message line and emit the rest raw, then write their own header, so a pasted 1.0.28 block (including a first line `# Agent Receipt`, or a blank line after the quoted line) leaves more than one of each heading. Only the author of that old receipt, or whoever signs it, can craft that body. The rule makes every pre-1.0.28 receipt unlinkable. The 1.0.28 writer quotes or indents message lines, commit continuations, diff lines, file names, and risk details that would otherwise be exactly those headings, so a real 1.0.28 receipt still has one of each and still links. A backtick in the branch or workspace path is percent-encoded (`%60`) so the grammar keeps the link. `--agent` is free-form, including spaces, same as 1.0.27 and config `defaultAgent`. `--session` still accepts 1.0.27 values (spaces and slashes) on one line. `--message` may span lines; the 1.0.28 writer quotes every line in the TL;DR and indents every header continuation so a message cannot put a raw heading in the header region. `--parent` must be an `r-` id, a sha256, or a receipt file. Changing the header breaks `verify`. On a 1.0.28+ receipt, a hash-valid id, parent, or host that fails the strict check is tampered (`verify` exits 2). Free-form agent and session text is not a verify-time tamper failure. `agent-receipt session <id>` lists the local tree and exits 1 when any receipt fails verify or a local parent fails verify. A cross-session parent is a warning. `prove` and `prove --html` show the session, the parent, and whether a local parent verifies. That does not change the prove exit code.

`host` is off unless `--host` or `AGENT_RECEIPT_HOST` is set. `share` keeps session, parent, and agent, and masks host unless `--include-host`. Receipts outside `outDir` are not indexed. Auto-prune can delete a parent; the child is then an orphan, which does not by itself fail `session`.

### Cross-host session merge

`session export <id>` (alias `session pack`) writes a portable directory for that local tree. The default path is the sibling of `outDir`: `.agent-receipt/receipts` becomes `.agent-receipt/<id>.session/`. `--out <dir>` names the directory. The package contains each receipt, a sidecar when one was copied or re-signed, `session-manifest.json`, and `session-manifest.sig.json` when local keys load. Unless `--include-host`, export calls the same function as `share`: secrets are masked, a nested receipt or index diff body is replaced with `[REDACTED — nested receipt/index body omitted]`, and the header Host line becomes `[REDACTED]`. `--include-host` keeps the original bytes. A sidecar from another key is kept when the bytes do not change. Redaction that would change those bytes exits 2 and writes nothing unless `--resign`. `--resign` warns on stderr and records `originalFingerprint` and `resignedBy`. Orphans and cycles are included and named in `warnings`. An empty session or a receipt that fails verify writes nothing. Reads are capped at 32 MiB (receipt), 256 KiB (sidecar), and 8 MiB (manifest) unless the matching `--max-*-bytes` flag raises the cap. `stat` runs before the read.

`session import <dir>` (alias `session merge`) verifies the manifest, the file hashes, each receipt, and any signatures, then copies the receipts into `outDir`. The same id and the same sha256 is skipped. A different sha256 for the same id, or the same filename compared case-insensitively, refuses the import and does not overwrite. A symlink at the destination or in a parent inside `outDir` exits 2 and writes nothing. A stray sidecar or an unreadable destination is a conflict. The copy is staged inside `outDir` and published only onto names that do not exist. A real import first removes stale `.import-staging-*` directories that contain the marker `.agent-receipt-import-staging` and are older than this run. Anything without that marker stays, including a symlink. `--dry-run` does not delete them. `--dry-run` and `--json` report the plan, including `originalFingerprint`, `resignedBy`, and `signedBy`. `originalFingerprint` is the manifest signer's claim, covered by `session-manifest.sig.json` when that sidecar verifies. It is not a second signature over the pre-export bytes. An unsigned source whose bytes changed is recorded as `signedBy` (the exporter key) with `originalFingerprint` null, and export warns on stderr. After import, `session <id>` and the human import summary show those claims. Import does not append the audit log and does not add an index row. `last`, `history`, and `prune` ignore `*.session/` directories. `prune` lstats every target before unlinking, and refuses a symlink sidecar without deleting the rest of the batch.

### Signed one-page report

`agent-receipt report last` (or a receipt path, `report --session <id>`, or a `*.session` directory) writes one offline HTML file beside `outDir`. A reviewer opens it with no network and no install. The banner is VERIFIED, FAILED, UNSIGNED, or UNTRUSTED. The page shows the summary, commands, files touched, risk flags, what to review, commits, range, and, for a session, the parent/child/agent tree plus signer fingerprints and trust. Range and Summary are clean text. Redaction matches `share` unless `--include-host` or `--no-redact` is set, which print an UNREDACTED marker. The whole rendered page is covered: the canonical payload holds every visible string, the Ed25519 signature covers that payload, and `report verify` re-renders the HTML and requires the same bytes (a single missing trailing newline is ignored). Any other difference exits 2 with `page content does not match signed payload`. A session report is FAILED, not VERIFIED, when the session root or any receipt in the tree fails verification. Exit 0 only for a valid signature, a matching page, and verdict VERIFIED, or for an honestly UNSIGNED page without `--require-sig` (printed UNSIGNED). FAILED, UNTRUSTED, a page mismatch, a bad signature, or a schema failure exits 2. A non-zero exit never prints VERIFIED. A failing unsigned page prints `FAILED (unsigned)`. `--receipts` must be a readable directory or verify exits 1. When it is set, only that directory is searched: a referenced receipt that is missing exits 2, and every same-id candidate must pass. A file whose raw sha256 equals the recorded sha256 or redactedSha256 matches. When the payload records a fingerprint or originalFingerprint, that match requires a valid sidecar. When the payload is unsigned, a valid stray sidecar is ignored. A session-package report may also match the redacted form, and a non-null originalFingerprint then requires that sidecar. A newest prune audit event is payload-only when this log has no capture, wrap, or watch event for that receipt. A missing capture is not tampering. When one of those events exists, the prune stays payload-only unless it is more than 5 seconds before that event. Clock skew of up to 5 seconds stays payload-only; more than 5 seconds exits 2. The reason is `receipt absent; audit.jsonl (unsigned) records a prune`. audit.jsonl is not signed, and anyone with write access can extend it. A present audit log in the store being searched with a broken hash chain exits 2. A symlink exits 2. Without `--receipts`, a missing receipt that the store index or audit log still lists exits 2. Otherwise the headline is `VERIFIED (payload only; N receipts not checked)`. `renderVersion` selects the HTML renderer. The candidate walk stops at depth 5. CRLF in the page exits 2 and names `core.autocrlf`; a lone CR is `page has CR line endings`. Add `*.report.html -text` and `.agent-receipt/** -text` to `.gitattributes`. Exactly one trailing CR on an audit line is stripped before the chain hash. Two trailing CRs still fail. The CRLF hint is added only when the failing line itself ends in CR. With no trust store, `--require-sig` accepts any valid self-signed page and prints a one-line note; use a trust allowlist. A detached `<report>.html.sig.json` is written when keys load, and the signature is also inside the file. Missing keys leave the report unsigned and exit 0. Schema: [`report-payload.schema.json`](report-payload.schema.json). This is not a CA.

Schema: [`session-package.schema.json`](session-package.schema.json). This is not a CA.

### Native adapters

`agent-receipt adapters` installs a project hook for Claude Code (`.claude/settings.json`), Cursor (`.cursor/hooks.json`), Grok CLI (`.grok/hooks/agent-receipt.json`), or Codex (`.codex/hooks.json`). `init --claude`, `init --codex`, `init --cursor`, and `init --grok` call the same installers. Install merges. It does not drop existing keys or other hooks. The first install snapshots the previous bytes under the git directory, keyed to the project root. Uninstall puts those bytes back when the file is unchanged since install, and strips only this adapter's hooks when it is not. `--force` restores the snapshot anyway. `--dry-run` writes nothing and, when an edit would be dropped, prints `would discard user changes`. `--no-stop` skips the extra Stop hook on Claude Code, Codex, and Cursor. Codex installs SessionEnd and Stop. Grok keeps SessionEnd.

`capture --transcript <file>` and `wrap --transcript <file>` record tool calls, including MCP tool calls, in a `## Tool calls` section inside the hashed receipt. Arguments are redacted key by key, then with the secret patterns, a high-entropy pass, and internal hosts, even when `--redact` is off. The companion JSON `toolCalls` object is not covered by the receipt hash or the Ed25519 sidecar. Trust the hashed section. A missing transcript warns and the receipt is still written. `doctor` reports adapters as INFO and does not fail `--strict`. A trusted key holder can re-sign an altered report narrative. Trust means trusting the signer. `report verify` checks the signature and the page bytes. It does not prove the narrative matches an earlier unsigned draft. This is not a CA.

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
`share --package` landed in 1.0.24: a portable directory with redacted HTML,
Markdown, an optional `receipt.sig.json`, `manifest.json`, and an optional
`manifest.sig.json`. The HTML body stays unsigned. `verify --package` and
`import` landed in 1.0.25: a peer checks that directory in one command and
can copy the proved Markdown into the local store. Import does not append
the audit log and does not pretend to be a local capture. Auto-prune landed
in 1.0.26: `autoPrune: true` (or `--prune` / `init --auto-prune`) runs trusted
prune after a successful capture, wrap, or watch when a retention limit is
set. It does not pass `--force`. A broken audit chain skips the delete and
does not fail the capture. `init --retention` does not turn it on. This is
not a long-running daemon or cron. `prove --html` landed in 1.0.27: an
offline, redacted, self-contained HTML verification report (not itself
signed). This is not a CA. Full PKI/CA is still deferred. Minisign, GPG/OpenPGP, default auto-sign
on capture without config (signing stays opt-in via config `sign: true` or
`--sign`). Thin local multi-agent receipt linking landed in 1.0.28 (`--session`, `--parent`, `--agent`, `--host`, `wrap --link`, `session`). Cross-host session merge landed in 1.0.29 (`session export`, `session import`, optional `session-manifest.sig.json`). The signed one-page HTML report landed in 1.0.30 (`report`, `report verify`). Native capture adapters and MCP tool-call capture landed in 1.0.31 (`adapters`, `capture --transcript`). in-toto Statement v1 and SLSA Provenance v1 export landed in 1.0.32 (`attest`, `export --format intoto`, a DSSE envelope). Sigstore keyless signing landed in 1.0.33 (`attest --keyless`). A long-running prune
daemon or cron is still deferred. `trust show` landed in
1.0.23: a read-only report of the allowlist and whether the local key is
listed. It is not a CA. Config `sign: true` /
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
Cloud Agents, a long-running prune daemon or cron (auto-prune after capture
is the landed first cut; it is not a background job), live GitHub
Actions workflow sync (the checkout token has no `workflow` scope), and npm
Trusted Publishing (this cut does not publish). Manual `prune` remains.
Auto-prune is opt-in (`autoPrune` plus a limit) and does not pass `--force`.
Missing signing keys do not fail `doctor` or `doctor --strict`. CI `--fail-on` is still the enforcement point for risk. A broken audit chain still fails `--strict`.
`doctor --json`, `audit --event`, `audit --agent`, `audit --failed`,
`history --agent`, `history --uncommitted`, `history --failed`, and `prove`
are checklist and listing tools; they do not sign the audit log.

### Workflow scope

Pushing `.github/workflows/*` needs the GitHub OAuth **`workflow`** scope
in addition to `repo`. Confirm with `gh auth status` (look for `workflow`
under Token scopes). The token used for the 1.0.6 through 1.0.34 cuts had
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
