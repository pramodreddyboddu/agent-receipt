# Business / production rollout

`agent-receipt` 1.0.9 for teams: install once, capture every session, fail CI
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

## Org policy

Copy [`examples/org-policy.yml`](../examples/org-policy.yml) onto
`.agent-receipt.yml` (keep your own `ignore` / `riskAllowlist` entries):

```yaml
redact: true    # capture / wrap / watch / share, unless --no-redact
failOn: high    # those commands exit 2 at high (or medium / low)
```

- CLI `--fail-on` overrides config. Bare `--fail-on` means `high`.
- CLI `--redact` / `--no-redact` override config `redact`.
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
is the artifact, not the gate.

```json
{
  "ok": true,
  "command": "wrap",
  "version": "1.0.9",
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
  "reason": null
}
```

`ok` is true only when `exitCode` is 0. `verified` is `null` for `capture`
(it does not run verify). `share` sets `htmlPath` / `markdownPath`. On exit 1
the same shape is printed with `reason` set and the path fields null.

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

Copy [`examples/org-policy.yml`](../examples/org-policy.yml) onto
`.agent-receipt.yml` and keep your local `ignore` / `riskAllowlist` lines.
That turns `redact` on for capture / wrap / watch and sets `failOn: high`.
`share` already redacts unless `--no-redact`, even without this file.

`doctor` lists this as **policy**. INFO means it is not applied yet. Only
real **FAIL** rows change the exit code — the default checklist does not
block a laptop that has not adopted the file. CI should still pass `--fail-on`
so a missing config cannot silently weaken the job. `--fail-on` scans the
receipt risk summary. `doctor` does not.

`doctor --strict` is a separate prod gate for **unset config**, not for
secrets. It exits 1 when org policy (`redact` + `failOn`) and/or retention
is unset **and** `outDir` is under pressure (100 receipts or 20 MB). A small
directory stays exit 0 with the same INFO/WARN rows. A limit that is set but
would still delete files stays a warning until you run `prune`.

```bash
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
| [`examples/github/pr-gate.yml`](../examples/github/pr-gate.yml) | Copy to `.github/workflows/agent-receipt-gate.yml`. `pull_request` runs `wrap --fail-on --json` (or `share`). Also callable as a reusable workflow. |
| [`examples/github/action.yml`](../examples/github/action.yml) | Composite action. Copy the directory to `.github/actions/agent-receipt/` and call it after `agent-receipt` is on `PATH` (devDependency or global install). |

Exit codes are unchanged: 0 pass, 2 policy and/or verify failure, 1 usage
error. The step prints the gate JSON from `$RUNNER_TEMP/receipt-gate.json`
before exiting. You do not need `jq`.

This repo’s own [docs mirror](github-actions-ci.yml) runs a temp-repo
`wrap --json` + `share --json` smoke, then `doctor --json` and
`audit --event wrap`. The live
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
neither does a run that deletes nothing.

```bash
agent-receipt audit            # newest last, human
agent-receipt audit --json     # array, oldest first
agent-receipt audit --event wrap
agent-receipt audit --event wrap --limit 20 --json
agent-receipt log --event prune
agent-receipt audit --verify   # exit 0 intact, exit 2 if a line was edited
agent-receipt log --verify     # alias
```

`--event` keeps one of `capture`, `watch`, `wrap`, `share`, `export`, or
`prune` (the `event` field already written on each line). It applies to the
listing only, including with `--limit` (newest N of that event) and `--json`
(still a JSON array, oldest first). An unknown name exits 1. `audit --verify`
ignores `--event` and checks the whole file.

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
the chain matches, WARN if it does not. WARN does not fail `doctor`.

Editing a line in place breaks the chain on purpose. To rotate, move the
file aside and let the next command start a new one (`prev: null`).
`prune` does not delete or rewrite `audit.jsonl`.

### Retention for `.agent-receipt/`

| Path | Contains | Guidance |
|------|----------|----------|
| `receipts/*.md` and sibling `.json` | Diffs, maybe secrets before redaction | Prefer local or a CI artifact with a short retention (14–30 days is a reasonable team default). Do not commit a receipt that captured a live secret — rotate the credential. |
| `index.json` | Paths, agent, message, risk counts, sha256. No diff body. | Messages are stored in the clear. `prune` drops rows for receipts it deletes, and rows under outDir whose files are already gone. |
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
- `maxCount` and `maxAgeDays` must be integers `>= 1`. `0` is rejected so
  a typo cannot wipe the directory.
- `doctor` **retention**: INFO when opt-in is off and the directory is
  small; WARN when 100 or more receipts **or** 20 MB or more sit in
  `outDir` with no limit, or when a configured limit would delete
  something; FAIL when the keys are invalid or `outDir` is unsafe to
  prune. WARN does not fail default `doctor`. With `--strict`, that WARN
  becomes FAIL when the limit is unset and the directory is already at
  100 receipts or 20 MB. A set limit that would still delete stays WARN.

This package gitignores `.agent-receipt/` in its own repo. Your repo
chooses. A local-only choice:

```gitignore
.agent-receipt/
```

Commit receipts only when they are the review artifact you meant to keep,
and prefer `share` output over a raw capture when the audience is wider
than the people who can already read the git history.

### Deferred

Not in 1.0.9: cryptographic signing, SSO / IdP, Cloud Agents, a background
job that deletes receipts by itself, live GitHub Actions workflow sync (the
checkout token has no `workflow` scope), and npm Trusted Publishing (this
cut does not publish). `prune` stays manual. `doctor --strict` only fails
unset policy or retention when the receipt directory is already large. CI
`--fail-on` is still the enforcement point for risk. `doctor --json` and
`audit --event` are checklist and listing tools; they do not sign the log.

### Workflow scope

Pushing `.github/workflows/*` needs the GitHub OAuth **`workflow`** scope
in addition to `repo`. Confirm with `gh auth status` (look for `workflow`
under Token scopes). The token used for the 1.0.6 through 1.0.9 cuts had
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
