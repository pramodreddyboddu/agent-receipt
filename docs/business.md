# Business / production rollout

`agent-receipt` 1.0.5 for teams: install once, capture every session, fail CI
on high-severity findings, and share only redacted HTML.

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
whether `redact` is the default, git clean, Cursor init, Grok init. Only `FAIL`
rows change the exit code (exit 1). Warnings are non-fatal.

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
  "version": "1.0.5",
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

## SessionEnd stdin contract

Grok (and anything else that execs `.grok/hooks/agent-receipt-wrap.sh` or
`scripts/grok-wrap.sh`) may write a JSON event on stdin and **leave the pipe
open**. The scripts must not block waiting for EOF.

- A terminal stdin is not read.
- Otherwise at most **one read** of `HOOK_STDIN_MAX` bytes (default 65536) is
  drained. `dd count=1` is one `read(2)`, not a full block, so a short payload
  returns even when the writer never closes the pipe.
- That read is capped by `HOOK_STDIN_WAIT_SEC` (default `0.4`) via GNU
  `timeout` when it is on `PATH`. Without `timeout`, `node` applies the same
  cap (and stops ~30ms after the first chunk).
- With neither `timeout` nor `node`, stdin is left unread. That still does
  not hang. The scripts do not `cat` until EOF.
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
