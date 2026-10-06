# Codex integration

Install the project SessionEnd and Stop hooks once. SessionEnd runs when the main thread ends. `--no-stop` keeps SessionEnd only. The `AGENTS.md` block is marked and does not replace text outside those markers. Uninstall restores the previous bytes when the file is unchanged, and strips only the agent-receipt block when it is not.

```bash
agent-receipt init --codex
# or: agent-receipt adapters install codex
# preview: agent-receipt adapters install codex --dry-run
```

After a session, pass the transcript so MCP tool calls land on the receipt:

```bash
agent-receipt wrap --agent codex --redact --transcript session.jsonl --message "session wrap-up"
```

Enable `features.hooks` in Codex config and trust the project hooks. The hook exits 0.
