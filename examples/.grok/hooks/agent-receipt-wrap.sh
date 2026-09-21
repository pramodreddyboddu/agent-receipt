#!/bin/sh
# SessionEnd hook written by `agent-receipt init --grok`.
# Wraps only when the working tree is dirty. Always passes --redact.
# Non-blocking: exit 0 if wrap fails or agent-receipt is missing.
# Project hooks run only after `/hooks-trust` or `grok --trust`.
set -u

# Grok passes hook JSON on stdin. Drain a pipe; do not block a terminal.
if [ ! -t 0 ]; then
  cat >/dev/null || true
fi

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
