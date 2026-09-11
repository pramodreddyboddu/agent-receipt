# Claude Code integration

One-liner to run after a Claude Code session (from the repo root):

```bash
agent-receipt capture --agent claude-code --message "session wrap-up"
```

Or via GitHub until npm publish:

```bash
npx github:pramodreddyboddu/agent-receipt -- capture --agent claude-code -m "session wrap-up"
```

Wait for the next commit:

```bash
agent-receipt watch --once --agent claude-code --message "session wrap-up"
```

Add to a project `CLAUDE.md` / instructions:

> After finishing file edits in this repo, **run**
> `agent-receipt capture --agent claude-code --message "<summary>"`
> (do not only suggest it) so a tamper-evident receipt is stored under
> `.agent-receipt/receipts/`. Then `agent-receipt history` / `last`.
