#!/bin/sh
# SessionEnd hook written by `agent-receipt init --grok`.
# Wraps only when the working tree is dirty. Always passes --redact.
# Non-blocking: exit 0 if wrap fails or agent-receipt is missing.
# Project hooks run only after `/hooks-trust` or `grok --trust`.
#
# Stdin contract:
#   The host may write a hook JSON event on stdin and may leave the pipe
#   open (no EOF). This script must not block waiting for EOF.
#   - A tty is not read.
#   - Otherwise at most one read of HOOK_STDIN_MAX bytes (default 65536)
#     is drained. The wait is capped by HOOK_STDIN_WAIT_SEC (default 0.4)
#     when `timeout` is available (GNU). `count=1` is one read(2), not a
#     full block, so a short payload returns even if the writer never closes.
#   - Without `timeout`, `node` reads until HOOK_STDIN_MAX, EOF, or the
#     same wait (idle 30ms after the first chunk).
#   - With neither, stdin is left unread. That still does not hang.
#     Do not `cat` until EOF.
#   The payload is discarded. Wrap is decided from `git status`, not JSON.
set -u

drain_hook_stdin() {
  if [ -t 0 ]; then
    return 0
  fi
  max="${HOOK_STDIN_MAX:-65536}"
  wait_s="${HOOK_STDIN_WAIT_SEC:-0.4}"

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

root="${GROK_WORKSPACE_ROOT:-}"
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
