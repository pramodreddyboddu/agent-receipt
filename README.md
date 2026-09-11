# agent-receipt

Open-source CLI that writes **human-readable receipts** for what an AI coding agent changed in a git repo.

> Status: scaffolding. Cloud Agent build is queued pending plan/credits. This brief is the v0.1 contract.

## Why

Agent sessions leave a pile of diffs. `git log` and `git diff` are accurate but not a shareable “what did the agent do?” summary. `agent-receipt` turns the working tree and recent commits into a clear receipt you can paste into a PR, chat, or audit trail.

## Who it’s for

Developers (and agent operators) who want a durable, human-readable record of an agent’s code changes — without dumping raw patches by default.

## v0.1 scope

| Capability | Notes |
| --- | --- |
| Run in a git working tree | Optional `--cwd` |
| Summarize working tree + last N commits | Flags to narrow |
| Markdown receipt (stdout) | Default |
| JSON receipt | `--json` |
| Write to file | `--out <path>` |
| Agent/session label | `--agent` / `--session` |
| Safe git invocation | `execFile`, `shell: false`, fixed arg arrays |

### Receipt contents

- ISO-8601 timestamp
- Repo identity (name/remote if available), branch, HEAD short SHA
- Change summary (added / modified / deleted + line stats)
- Per-file digest (path, kind, short intent) — full patches only with `--full`

### Non-goals for v0.1

- No MCP server (see sibling [agent-safety-pack](https://github.com/pramodreddyboddu/agent-safety-pack))
- No network calls, no cloud upload
- No rewriting history

## Install (planned)

```bash
npm install -g agent-receipt   # or npx agent-receipt
agent-receipt --help
```

## Usage (planned)

```bash
agent-receipt
agent-receipt --json --out receipt.json
agent-receipt --agent cursor --session bc-… --commits 5
```

## Sibling

Quality bar and packaging should match [agent-safety-pack](https://github.com/pramodreddyboddu/agent-safety-pack) (TypeScript, Node 20+, MIT, real tests).

## License

MIT © Pramod Reddy Boddu