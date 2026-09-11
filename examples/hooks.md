# Git hooks

## Install

```bash
# post-commit only
npx agent-receipt install-hooks

# post-commit + pre-push
npx agent-receipt install-hooks --pre-push
```

Hooks are written under `.git/hooks/` with managed markers:

```
# >>> agent-receipt hook >>>
...
# <<< agent-receipt hook <<<
```

Existing hook content is preserved; only the managed section is added/updated.

## Environment

| Variable | Purpose |
|----------|---------|
| `AGENT_RECEIPT_BIN` | Absolute path to `agent-receipt.js` (skips `npx`) |
| `AGENT_RECEIPT_AGENT` | Agent label written into the receipt (default `git-hook`) |

Example using a local checkout:

```bash
export AGENT_RECEIPT_BIN="$PWD/node_modules/agent-receipt/bin/agent-receipt.js"
# or after cloning this repo:
export AGENT_RECEIPT_BIN="/path/to/agent-receipt/bin/agent-receipt.js"
npx agent-receipt install-hooks
```

## Uninstall

```bash
npx agent-receipt uninstall-hooks
# also strips a managed pre-push section if present
```

## Behavior

- Hooks are **non-blocking**: capture failures do not fail the commit/push.
- `post-commit` captures `--commits 1`.
- `pre-push` captures `--commits 5`.
- Receipts land in `.agent-receipt/receipts/` by default.
