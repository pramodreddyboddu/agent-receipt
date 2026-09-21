# Agent integration

Short, practical recipes for capturing receipts after AI coding sessions.
All commands assume Node.js ≥ 20 and `git` on `PATH`.

```bash
npm i -g github:pramodreddyboddu/agent-receipt
# optional one-time setup in the repo
agent-receipt init --cursor
agent-receipt install-hooks
```

Also see the short copies under [`examples/`](../examples/) (`AGENTS.md`,
`claude-code.md`, `aider.md`, `hooks.md`, `.cursor/rules/`, `.grok/`).
Grok Build: [`grok-cli.md`](grok-cli.md).
Team rollout, CI `--json` gates, and share-safety: [`business.md`](business.md).

## Cursor

**Best path:** `agent-receipt init --cursor` drops
[`.cursor/rules/agent-receipt.mdc`](../examples/.cursor/rules/agent-receipt.mdc)
with `alwaysApply: true`. The rule tells the agent to **run capture itself**
when the session finishes — not merely remind you.

After a Cursor agent / Composer session that touched the working tree:

```bash
agent-receipt capture --agent cursor --message "composer: auth refactor" --json

# Whole-branch review
agent-receipt capture --agent cursor --since main --message "PR prep" --full

agent-receipt history
agent-receipt last
agent-receipt verify
```

### Run after session (`watch --once`)

If you (or the agent) are about to commit, wait for that commit, capture, exit:

```bash
agent-receipt watch --once --interval 2 --agent cursor --message "session wrap-up"
```

Long session — leave a terminal running:

```bash
agent-receipt watch --interval 5 --agent cursor
```

**Optional hooks:**

```bash
agent-receipt install-hooks              # post-commit
agent-receipt install-hooks --pre-push   # + pre-push
agent-receipt uninstall-hooks
```

Suggested flags: `--agent cursor`, `--session <chat-title>`, `--json`.

## Grok Build CLI

**Best path:** `agent-receipt init --grok` drops
[`.grok/rules/agent-receipt.md`](../examples/.grok/rules/agent-receipt.md)
plus a SessionEnd hook that wraps **uncommitted** work with `--redact`.
Trust project hooks once (`grok --trust` or `/hooks-trust`).

After a session (recommended — names what changed; dirty tree is automatic):

```bash
agent-receipt wrap --agent grok --redact --message "grok: auth refactor"
agent-receipt last
agent-receipt verify
```

Force a dirty snapshot (errors if clean):

```bash
agent-receipt wrap --agent grok --redact --uncommitted --message "uncommitted grok work"
```

Details: [`grok-cli.md`](grok-cli.md).

## Claude Code

```bash
agent-receipt capture \
  --agent claude-code \
  --message "session: fix flaky tests" \
  --commits 3 \
  --json

agent-receipt last --path
agent-receipt history
```

Run after the next commit:

```bash
agent-receipt watch --once --agent claude-code --message "session wrap-up"
```

For frequent commits, prefer `agent-receipt install-hooks` (set
`AGENT_RECEIPT_AGENT=claude-code`).

Suggested flags: `--agent claude-code`, `--session <id>`, `--since HEAD@{upstream}`.

## Aider

```bash
agent-receipt capture --agent aider --commits 5 --message "aider: type fixes"

# or let the post-commit hook do it
export AGENT_RECEIPT_AGENT=aider
agent-receipt install-hooks
```

Inside Aider:

```text
/run agent-receipt capture --agent aider --message "wrap up" --json
/run agent-receipt watch --once --agent aider
```

## General tips

| Goal | Command |
|------|---------|
| Newest receipt path | `agent-receipt last --path` |
| Recent sessions | `agent-receipt history` |
| Full Markdown dump | `agent-receipt show` |
| Integrity check | `agent-receipt verify` |
| Whole-branch review | `agent-receipt capture --since main --full` |
| Fail CI on secrets | `agent-receipt capture --fail-on high` |
| After next commit | `agent-receipt watch --once --agent <name>` |
| Scripting cwd | `agent-receipt capture --cwd /path/to/repo …` |

Receipts are **tamper-evident**, not signed. Treat high-severity risk hints
(secrets, `.env`, private keys, lockfile/CI deletions) as a review checklist,
not a security boundary.
