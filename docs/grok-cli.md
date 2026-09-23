# Grok Build CLI

Capture a tamper-evident receipt after a [Grok Build](https://x.ai/cli) session.
`wrap` is the one-shot: dirty tree → uncommitted snapshot, then TL;DR + `verify`.
`--redact` (share-safety from 1.0.3) stays on for anything you might paste or attach.

Requires **Node.js ≥ 20** and `git` on `PATH`.

## One-time setup

```bash
npm i -g @pramodreddyboddu/agent-receipt
# or, before/without npm publish:
npm i -g github:pramodreddyboddu/agent-receipt

cd your-git-repo
agent-receipt init --grok
```

`init --grok` writes:

| Path | Role |
|------|------|
| `.grok/rules/agent-receipt.md` | Project rule. Grok loads every `*.md` in `.grok/rules/` each session and is told to **run** `wrap`, not only suggest it. |
| `.grok/hooks/agent-receipt.json` | `SessionEnd` hook. |
| `.grok/hooks/agent-receipt-wrap.sh` | Runs `wrap --agent grok --redact --uncommitted` **only when the working tree is dirty**. Exit 0 if `agent-receipt` is missing or wrap fails (does not fail the Grok session). Does not wait for stdin EOF (see below). |

Grok does not run project hooks until you trust the repo:

```bash
grok --trust
# or in the TUI: /hooks-trust
```

Check discovery with `grok inspect` (rules) and `/hooks` (the SessionEnd command).

Copy from this package if you already ran `init` without `--grok`:

```bash
mkdir -p .grok/rules .grok/hooks
cp path/to/agent-receipt/examples/.grok/rules/agent-receipt.md .grok/rules/
cp path/to/agent-receipt/examples/.grok/hooks/agent-receipt.json .grok/hooks/
cp path/to/agent-receipt/examples/.grok/hooks/agent-receipt-wrap.sh .grok/hooks/
```

## After a Grok session

Recommended one-liner. If the tree is dirty, `wrap` captures it as **uncommitted**.
If it is clean, `wrap` captures the latest commit(s). `--redact` masks high/secret
findings and re-hashes so `verify` still passes.

```bash
agent-receipt wrap --agent grok --redact --message "what changed"
```

Require a dirty snapshot (errors when nothing is uncommitted — use this when you
know the session left a dirty tree and a commit-range receipt would be wrong):

```bash
agent-receipt wrap --agent grok --redact --uncommitted --message "uncommitted grok work"
```

Not on `PATH`:

```bash
npx github:pramodreddyboddu/agent-receipt -- wrap --agent grok --redact --message "what changed"
```

In a checkout of **this** repo (dogfood):

```bash
scripts/grok-wrap.sh "what changed"
npm run wrap:grok -- "what changed"
# extra wrap flags after the message:
scripts/grok-wrap.sh "wip" --uncommitted
```

`scripts/grok-wrap.sh` / `npm run wrap:grok` always pass `--agent grok --redact`.
They do **not** force `--uncommitted`, so a clean tree still gets a commit receipt.

Then:

```bash
agent-receipt last
agent-receipt last --json
agent-receipt verify
agent-receipt prove
agent-receipt history
```

Share HTML only from the redacted receipt:

```bash
agent-receipt html --redact --out share.html
```

## Stdin contract

Grok may pass hook JSON on stdin and leave the pipe open (no EOF). The
SessionEnd script and `scripts/grok-wrap.sh` **must not block waiting for EOF**.

- A tty is not read and is not redirected.
- Otherwise `node` (preferred) drains until `HOOK_STDIN_MAX` (default 65536),
  EOF, or `HOOK_STDIN_WAIT_SEC` (default `0.4`), and stops ~30ms after the
  last chunk. A short payload returns even if the writer never closes.
- If `node` is missing, GNU `timeout` + `dd` does one `read(2)`, and only
  when `timeout` accepts the wait value (BusyBox rejects `0.4` and is skipped).
- Stdin is then redirected from `/dev/null`, so a writer blocked on a full
  pipe gets `EPIPE` instead of stalling wrap. The scripts do not `cat` until EOF.
- The JSON is discarded. Wrap is decided from `git status`, not the payload.

Full note: [docs/business.md](business.md#sessionend-stdin-contract).

## What the hook does not do

- It does not run on a clean tree (that would re-receipt the last commit every time a session ends).
- It does not pick a session-specific message (`grok session (uncommitted)`). Run `wrap` yourself when the summary matters.
- It does not call the network. If `agent-receipt` is not on `PATH`, `./node_modules/.bin`, or `./bin/agent-receipt.js`, it skips.
- It does not block the session. A wrap failure is printed and ignored.
- It does not parse stdin, and it does not wait for the host to close it.

High-severity findings (secrets, `.env`, private keys) are a review checklist, not a guarantee. See [SECURITY.md](../SECURITY.md).
