# Aider integration

Run after an Aider session:

```bash
agent-receipt capture --agent aider --message "aider session"
```

Wait for the next commit:

```bash
agent-receipt watch --once --agent aider --message "aider wrap-up"
```

Or wire a shell alias:

```bash
alias ar-capture='agent-receipt capture --agent aider'
ar-capture -m "refactored auth"
```

Optional post-commit hook so every commit gets a receipt:

```bash
agent-receipt install-hooks
export AGENT_RECEIPT_AGENT=aider
```

Inside Aider:

```text
/run agent-receipt capture --agent aider --message "wrap up" --json
```
