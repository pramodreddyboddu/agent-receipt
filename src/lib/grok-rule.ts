/**
 * Grok Build project files dropped by `agent-receipt init --grok`.
 * Grok loads every `*.md` under `.grok/rules/`. Project hooks under
 * `.grok/hooks/` run only after `/hooks-trust` or `grok --trust`.
 */

export const GROK_RULE_REL = '.grok/rules/agent-receipt.md';

export const GROK_HOOK_REL = '.grok/hooks/agent-receipt.json';

export const GROK_WRAP_SCRIPT_REL = '.grok/hooks/agent-receipt-wrap.sh';

export const GROK_RULE_MD = `# agent-receipt (Grok Build wrap-up)

This repo uses **agent-receipt** — tamper-evident git snapshot receipts for agent sessions.

## You must wrap — do not only suggest it

When you finish a Grok Build session that modified files, **run wrap yourself** before telling the user you are done. Do not skip because the diff looks small.

\`\`\`bash
agent-receipt wrap --agent grok --redact --message "<one-line summary of what you changed>"
\`\`\`

\`wrap\` snapshots a **dirty working tree as uncommitted** automatically, prints TL;DR, and verifies. \`--redact\` masks high/secret findings so the receipt is safer to share (re-hashed; \`verify\` still passes).

Add \`--uncommitted\` only to **require** a dirty snapshot. That flag errors if the tree is clean (for example after you already committed):

\`\`\`bash
agent-receipt wrap --agent grok --redact --uncommitted --message "<summary of uncommitted work>"
\`\`\`

If \`agent-receipt\` is not on PATH:

\`\`\`bash
npx github:pramodreddyboddu/agent-receipt -- wrap --agent grok --redact --message "<summary>"
\`\`\`

Then:

\`\`\`bash
agent-receipt last
agent-receipt verify
\`\`\`

If the receipt shows **high** risk findings (AWS keys, private key blocks, committed \`.env\`), tell the user immediately and do not treat the session as clean.

## SessionEnd hook

\`agent-receipt init --grok\` also installs \`.grok/hooks/agent-receipt-wrap.sh\`. On **SessionEnd** it runs only when the working tree is dirty (\`--uncommitted --redact\`) and never fails the Grok session. Project hooks do not run until \`/hooks-trust\` or \`grok --trust\`.

Prefer the explicit \`wrap\` above so the message names what changed. The hook is a backstop for uncommitted work, not a replacement.

## Do not

- Do not commit \`.env\`, private keys, AWS credentials, or token files.
- Do not drop \`--redact\` when the receipt might be shared.
- Do not skip wrap. It is part of finishing the session.
`;

export const GROK_HOOK_JSON = `{
  "hooks": {
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "sh .grok/hooks/agent-receipt-wrap.sh",
            "timeout": 120
          }
        ]
      }
    ]
  }
}
`;

export const GROK_WRAP_SCRIPT = `#!/bin/sh
# SessionEnd hook written by \`agent-receipt init --grok\`.
# Wraps only when the working tree is dirty. Always passes --redact.
# Non-blocking: exit 0 if wrap fails or agent-receipt is missing.
# Project hooks run only after \`/hooks-trust\` or \`grok --trust\`.
#
# Stdin contract:
#   The host may write a hook JSON event on stdin and may leave the pipe
#   open (no EOF). This script must not block waiting for EOF.
#   - A tty is not read.
#   - Otherwise at most one read of HOOK_STDIN_MAX bytes (default 65536)
#     is drained. The wait is capped by HOOK_STDIN_WAIT_SEC (default 0.4)
#     when \`timeout\` is available (GNU). \`count=1\` is one read(2), not a
#     full block, so a short payload returns even if the writer never closes.
#   - Without \`timeout\`, \`node\` reads until HOOK_STDIN_MAX, EOF, or the
#     same wait (idle 30ms after the first chunk).
#   - With neither, stdin is left unread. That still does not hang.
#     Do not \`cat\` until EOF.
#   The payload is discarded. Wrap is decided from \`git status\`, not JSON.
set -u

drain_hook_stdin() {
  if [ -t 0 ]; then
    return 0
  fi
  max="\${HOOK_STDIN_MAX:-65536}"
  wait_s="\${HOOK_STDIN_WAIT_SEC:-0.4}"

  # Foreground read: a trailing & on dd points it at /dev/null in POSIX
  # shells without job control (dash), which would skip the real pipe.
  if command -v timeout >/dev/null 2>&1; then
    timeout "$wait_s" dd bs="$max" count=1 of=/dev/null 2>/dev/null || true
    return 0
  fi

  if command -v node >/dev/null 2>&1; then
    HOOK_STDIN_MAX="$max" HOOK_STDIN_WAIT_SEC="$wait_s" node -e 'const max=parseInt(process.env.HOOK_STDIN_MAX||"65536",10); const waitMs=Math.max(0,Math.round(parseFloat(process.env.HOOK_STDIN_WAIT_SEC||"0.4")*1000)); let got=0; const finish=()=>process.exit(0); let timer=setTimeout(finish,waitMs); process.stdin.on("data",(b)=>{got+=b.length; if(got>=max){clearTimeout(timer); finish(); return;} clearTimeout(timer); timer=setTimeout(finish,30);}); process.stdin.on("end",()=>{clearTimeout(timer); finish();}); process.stdin.on("error",()=>{clearTimeout(timer); finish();}); process.stdin.resume();' || true
    return 0
  fi

  return 0
}

drain_hook_stdin

root="\${GROK_WORKSPACE_ROOT:-}"
if [ -z "$root" ]; then
  root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
fi
cd "$root" || exit 0

# Match agent-receipt dirty detection: staged, unstaged, or untracked.
if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
  exit 0
fi

msg="grok session (uncommitted)"

run_wrap() {
  "$@" wrap --agent grok --redact --uncommitted --message "$msg" || exit 0
}

if command -v agent-receipt >/dev/null 2>&1; then
  run_wrap agent-receipt
  exit 0
fi

if [ -x ./node_modules/.bin/agent-receipt ]; then
  run_wrap ./node_modules/.bin/agent-receipt
  exit 0
fi

if [ -f ./bin/agent-receipt.js ]; then
  run_wrap node ./bin/agent-receipt.js
  exit 0
fi

echo "agent-receipt: not on PATH; skipped grok SessionEnd wrap" >&2
exit 0
`;
