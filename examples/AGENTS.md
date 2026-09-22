# Agent receipt (project convention)

After finishing a coding session that touched the git working tree, **run**
capture (do not only suggest it):

```bash
agent-receipt capture --agent <your-agent> --message "<short session summary>"
# until published on npm:
# npx github:pramodreddyboddu/agent-receipt -- capture --agent <your-agent> -m "<summary>"
```

Optional one-time setup in this repo:

```bash
agent-receipt init --cursor      # Cursor rule that runs capture on wrap-up
agent-receipt init --grok        # Grok rule + SessionEnd hook (--redact)
agent-receipt install-hooks      # post-commit capture
```

Wait for the next commit, capture once:

```bash
agent-receipt watch --once --agent <your-agent> --message "session wrap-up"
```

Show / list / verify:

```bash
agent-receipt history
agent-receipt last
agent-receipt verify
agent-receipt share --out share.html   # redacted HTML + verify + TL;DR
agent-receipt audit --verify          # local capture/watch/wrap/share/export log
agent-receipt prune --dry-run          # opt-in retention; deletes nothing until configured
```
