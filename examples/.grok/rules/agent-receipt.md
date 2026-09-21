# agent-receipt (Grok Build wrap-up)

This repo uses **agent-receipt** — tamper-evident git snapshot receipts for agent sessions.

## You must wrap — do not only suggest it

When you finish a Grok Build session that modified files, **run wrap yourself** before telling the user you are done. Do not skip because the diff looks small.

```bash
agent-receipt wrap --agent grok --redact --message "<one-line summary of what you changed>"
```

`wrap` snapshots a **dirty working tree as uncommitted** automatically, prints TL;DR, and verifies. `--redact` masks high/secret findings so the receipt is safer to share (re-hashed; `verify` still passes).

Add `--uncommitted` only to **require** a dirty snapshot. That flag errors if the tree is clean (for example after you already committed):

```bash
agent-receipt wrap --agent grok --redact --uncommitted --message "<summary of uncommitted work>"
```

If `agent-receipt` is not on PATH:

```bash
npx github:pramodreddyboddu/agent-receipt -- wrap --agent grok --redact --message "<summary>"
```

Then:

```bash
agent-receipt last
agent-receipt verify
```

If the receipt shows **high** risk findings (AWS keys, private key blocks, committed `.env`), tell the user immediately and do not treat the session as clean.

## SessionEnd hook

`agent-receipt init --grok` also installs `.grok/hooks/agent-receipt-wrap.sh`. On **SessionEnd** it runs only when the working tree is dirty (`--uncommitted --redact`) and never fails the Grok session. Project hooks do not run until `/hooks-trust` or `grok --trust`.

Prefer the explicit `wrap` above so the message names what changed. The hook is a backstop for uncommitted work, not a replacement.

## Do not

- Do not commit `.env`, private keys, AWS credentials, or token files.
- Do not drop `--redact` when the receipt might be shared.
- Do not skip wrap. It is part of finishing the session.
