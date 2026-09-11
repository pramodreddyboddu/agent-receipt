/** Cursor project rule dropped by `agent-receipt init --cursor`. */
export const CURSOR_RULE_REL = '.cursor/rules/agent-receipt.mdc';

export const CURSOR_RULE_MDC = `---
description: After any session that changes git state, YOU run agent-receipt capture
alwaysApply: true
---

# agent-receipt (required wrap-up)

This repo uses **agent-receipt** — tamper-evident git snapshot receipts for agent sessions.

## You must capture — do not only suggest it

When you finish a coding session that modified files (especially after commits), **run capture yourself** before telling the user you are done. Do not skip because the diff looks small.

\`\`\`bash
agent-receipt capture --agent cursor --message "<one-line summary of what you changed>"
\`\`\`

If \`agent-receipt\` is not on PATH (GitHub install until npm publish):

\`\`\`bash
npx github:pramodreddyboddu/agent-receipt -- capture --agent cursor --message "<summary>"
\`\`\`

Then:

\`\`\`bash
agent-receipt last
agent-receipt history
\`\`\`

If the receipt shows **high** risk findings (AWS keys, private key blocks, committed \`.env\`), tell the user immediately and do not treat the session as clean.

## Optional: run after the next commit

If the user will commit next (or you are about to), you may wait for that commit and capture once:

\`\`\`bash
agent-receipt watch --once --interval 2 --agent cursor --message "<session summary>"
\`\`\`

For a long session with many commits, leave this running in a terminal:

\`\`\`bash
agent-receipt watch --interval 5 --agent cursor
\`\`\`

## Do not

- Do not commit \`.env\`, private keys, AWS credentials, or token files.
- Do not skip capture. It is part of finishing the session.
- Prefer \`agent-receipt last\` / \`verify\` / \`history\` when the user asks what changed.
`;
