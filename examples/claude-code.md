# Claude Code integration

One-liner to run after a Claude Code session (from the repo root):

```bash
npx agent-receipt capture --agent claude-code --message "session wrap-up"
```

Or via GitHub until npm publish:

```bash
npx github:pramodreddyboddu/agent-receipt -- capture --agent claude-code -m "session wrap-up"
```

Add to a project `CLAUDE.md` / instructions:

> After finishing file edits in this repo, run
> `npx agent-receipt capture --agent claude-code --message "<summary>"`
> so a tamper-evident receipt is stored under `.agent-receipt/receipts/`.
