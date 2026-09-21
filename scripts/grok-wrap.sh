#!/bin/sh
# Post-Grok wrap for this checkout.
# Usage:
#   scripts/grok-wrap.sh
#   scripts/grok-wrap.sh "what changed"
#   scripts/grok-wrap.sh "wip" --uncommitted
#   npm run wrap:grok -- "what changed"
#
# Always passes --agent grok and --redact.
# Does not force --uncommitted: wrap snapshots a dirty tree on its own,
# and --uncommitted errors when the tree is clean. Pass it yourself to require that.
#
# Stdin contract matches the SessionEnd hook (see docs/grok-cli.md):
# a still-open stdin must not hang this script. The payload is discarded.
set -eu

drain_hook_stdin() {
  if [ -t 0 ]; then
    return 0
  fi
  max="${HOOK_STDIN_MAX:-65536}"
  wait_s="${HOOK_STDIN_WAIT_SEC:-0.4}"
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

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
msg="grok session"
if [ "${1:-}" != "" ] && [ "${1#-}" = "$1" ]; then
  msg=$1
  shift
fi
exec node "$root/bin/agent-receipt.js" wrap --agent grok --redact --message "$msg" "$@"
