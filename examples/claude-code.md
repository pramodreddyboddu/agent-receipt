# Claude Code integration

Install the project hook once (merges into `.claude/settings.json`; uninstall restores the previous bytes):

```bash
agent-receipt init --claude
# or: agent-receipt adapters install claude-code
# preview: agent-receipt adapters install claude-code --dry-run
```

One-liner to run after a Claude Code session (from the repo root). `--transcript` records tool calls, including MCP, and redacts secrets in the arguments:

```bash
agent-receipt capture --agent claude-code --transcript session.jsonl --message "session wrap-up"
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
