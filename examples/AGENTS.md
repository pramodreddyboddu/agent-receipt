# Agent receipt (project convention)

After finishing a coding session that touched the git working tree, capture a
tamper-evident receipt:

```bash
npx agent-receipt capture --agent <your-agent> --message "<short session summary>"
# until published on npm:
# npx github:pramodreddyboddu/agent-receipt -- capture --agent <your-agent> -m "<summary>"
```

Optional one-time setup in this repo:

```bash
npx agent-receipt init
npx agent-receipt install-hooks   # post-commit capture
```

Show / verify the newest receipt:

```bash
npx agent-receipt last
npx agent-receipt verify
```
