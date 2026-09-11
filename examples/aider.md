# Aider integration

Run after an Aider session:

```bash
npx agent-receipt capture --agent aider --message "aider session"
```

Or wire a shell alias:

```bash
alias ar-capture='npx agent-receipt capture --agent aider'
ar-capture -m "refactored auth"
```

Optional post-commit hook so every commit gets a receipt:

```bash
npx agent-receipt install-hooks
export AGENT_RECEIPT_AGENT=aider
```
