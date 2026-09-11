# Agent integration

Short, practical recipes for capturing receipts after AI coding sessions.
All commands assume Node.js ≥ 20 and `git` on `PATH`.

```bash
npm install -g agent-receipt   # or: npx agent-receipt …
# optional one-time setup in the repo
agent-receipt init
```

Also see the short copies under [`examples/`](../examples/) (`AGENTS.md`,
`claude-code.md`, `aider.md`, `hooks.md`, `.cursor/rules/`).

## Cursor

After a Cursor agent / Composer session that touched the working tree:

```bash
agent-receipt capture --agent cursor --message "composer: auth refactor" --json

# Whole-branch review
agent-receipt capture --agent cursor --since main --message "PR prep" --full

agent-receipt last
agent-receipt verify
```

Optional project rule: copy [`examples/.cursor/rules/agent-receipt.mdc`](../examples/.cursor/rules/agent-receipt.mdc)
into your repo’s `.cursor/rules/`.

**Optional hooks:**

```bash
agent-receipt install-hooks              # post-commit
agent-receipt install-hooks --pre-push   # + pre-push
agent-receipt uninstall-hooks
```

Suggested flags: `--agent cursor`, `--session <chat-title>`, `--json`.

## Claude Code

```bash
agent-receipt capture \
  --agent claude-code \
  --message "session: fix flaky tests" \
  --commits 3 \
  --json

agent-receipt last --path
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
```

## General tips

| Goal | Command |
|------|---------|
| Newest receipt path | `agent-receipt last --path` |
| Full Markdown dump | `agent-receipt show` |
| Integrity check | `agent-receipt verify` |
| Whole-branch review | `agent-receipt capture --since main --full` |
| Scripting cwd | `agent-receipt capture --cwd /path/to/repo …` |

Receipts are **tamper-evident**, not signed. Treat high-severity risk hints
(secrets, lockfile/CI deletions) as a review checklist, not a security boundary.
