# Git hooks

## Install

```bash
# After a local or global install (preferred — works without npm publish)
npm i -g github:pramodreddyboddu/agent-receipt
# or: npm i -g /path/to/agent-receipt
# or: npm i -D /path/to/agent-receipt

cd your-git-repo
agent-receipt install-hooks

# post-commit + pre-push
agent-receipt install-hooks --pre-push
```

`install-hooks` resolves this package's `bin/agent-receipt.js` and embeds
`node` + that absolute path into the hook so capture works offline / without
registry publish. `npx` is only a last-resort fallback.

Hooks are written under `.git/hooks/` with managed markers:

```
# >>> agent-receipt hook >>>
...
# <<< agent-receipt hook <<<
```

Existing hook content is preserved; only the managed section is added/updated.

## How the hook picks a binary

At **hook runtime**, resolution order is:

1. **`AGENT_RECEIPT_BIN`** — if set, run that path
2. **Embedded absolute bin** — `node` + path to this install's `bin/agent-receipt.js` (written at `install-hooks` time)
3. **`npx --yes agent-receipt`** — last resort (needs the package on a registry)

## Environment

| Variable | Purpose |
|----------|---------|
| `AGENT_RECEIPT_BIN` | Absolute path to `agent-receipt` / `agent-receipt.js` (checked first at hook runtime; if set when running `install-hooks`, also becomes the embedded default) |
| `AGENT_RECEIPT_AGENT` | Agent label written into the receipt (default `git-hook`) |

Example forcing a specific checkout:

```bash
export AGENT_RECEIPT_BIN="$PWD/node_modules/agent-receipt/bin/agent-receipt.js"
# or after cloning this repo:
export AGENT_RECEIPT_BIN="/path/to/agent-receipt/bin/agent-receipt.js"
agent-receipt install-hooks
```

You can also set `AGENT_RECEIPT_BIN` only in the environment where commits run
(without reinstalling hooks); the managed section always prefers it when set.

## Uninstall

```bash
agent-receipt uninstall-hooks
# also strips a managed pre-push section if present
```

## Behavior

- Hooks are **non-blocking**: capture failures do not fail the commit/push.
- `post-commit` captures `--commits 1`.
- `pre-push` captures `--commits 5`.
- Receipts land in `.agent-receipt/receipts/` by default.
