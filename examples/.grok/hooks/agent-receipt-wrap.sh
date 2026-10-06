#!/bin/sh
# SessionEnd hook written by `agent-receipt init --grok`.
# Wraps only when the working tree is dirty. Always passes --redact.
# Non-blocking: exit 0 if wrap fails or agent-receipt is missing.
# Project hooks run only after `/hooks-trust` or `grok --trust`.
#
# Stdin contract:
#   The host may write a hook JSON event on stdin and may leave the pipe
#   open (no EOF). This script must not block waiting for EOF.
#   - A tty is not read (and is not redirected).
#   - Otherwise node (preferred) drains until HOOK_STDIN_MAX (default 65536,
#     capped at 1 MiB), EOF, or HOOK_STDIN_WAIT_SEC (default 0.4). After the
#     first chunk it stops on ~30ms of quiet, so a short payload returns
#     even if the writer never closes. Several chunks are consumed, not one.
#   - If node is missing, GNU timeout + dd does one read(2) — but only when
#     timeout accepts the wait value. BusyBox timeout rejects decimals and
#     is skipped so it cannot pretend the drain ran.
#   - Then stdin is redirected from /dev/null. A host blocked on a full
#     write gets EPIPE instead of stalling for the rest of wrap. Do not
#     cat until EOF. The payload is discarded. Wrap uses git status, not JSON.
set -u

drain_hook_stdin() {
  if [ -t 0 ]; then
    return 0
  fi
  max="${HOOK_STDIN_MAX:-65536}"
  wait_s="${HOOK_STDIN_WAIT_SEC:-0.4}"
  case "$max" in
    ''|*[!0-9]*) max=65536 ;;
  esac
  if [ "$max" -gt 1048576 ]; then max=1048576; fi
  if [ "$max" -lt 1 ]; then max=1; fi

  # Foreground read only. A trailing & on dd points it at /dev/null in POSIX
  # shells without job control (dash), which would skip the real pipe.
  if command -v node >/dev/null 2>&1; then
    HOOK_STDIN_MAX="$max" HOOK_STDIN_WAIT_SEC="$wait_s" node -e 'const maxRaw=parseInt(process.env.HOOK_STDIN_MAX||"65536",10); const max=Number.isFinite(maxRaw)?Math.min(Math.max(maxRaw,1),1048576):65536; const waitRaw=parseFloat(process.env.HOOK_STDIN_WAIT_SEC||"0.4"); const waitMs=Number.isFinite(waitRaw)?Math.max(0,Math.round(waitRaw*1000)):400; let got=0; let done=false; const finish=()=>{if(done)return; done=true; process.exit(0);}; let timer=setTimeout(finish,waitMs); process.stdin.on("data",(b)=>{got+=b.length; if(got>=max){clearTimeout(timer); finish(); return;} clearTimeout(timer); timer=setTimeout(finish,30);}); process.stdin.on("end",()=>{clearTimeout(timer); finish();}); process.stdin.on("error",()=>{clearTimeout(timer); finish();}); process.stdin.resume();' || true
  elif command -v timeout >/dev/null 2>&1 && timeout "$wait_s" true >/dev/null 2>&1; then
    timeout "$wait_s" dd bs="$max" count=1 of=/dev/null 2>/dev/null || true
  fi

  # Release the pipe before wrap. Oversized payloads may see EPIPE; that
  # unblocks the host instead of hanging the session.
  exec 0</dev/null
}

drain_hook_stdin

root="${GROK_WORKSPACE_ROOT:-}"
if [ -z "$root" ]; then
  root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
fi
cd "$root" || exit 0

# Ignore the receipt out dir and the store files wrap itself writes.
# --untracked-files=all lists files inside an untracked directory instead of
# one collapsed "?? .agent-receipt/" line, which would keep every SessionEnd dirty.
outdirs=".agent-receipt/receipts"
if [ -f .agent-receipt.yml ]; then
  cfg=$(sed -n 's/^outDir:[[:space:]]*//p' .agent-receipt.yml | head -n 1)
  cfg=$(printf '%s' "$cfg" | tr -d '"' | tr -d "'" | sed 's:/*$::')
  if [ -n "$cfg" ]; then
    outdirs="$cfg"
  fi
fi
dirty=$(git status --porcelain=v1 --untracked-files=all 2>/dev/null | while IFS= read -r line; do
  path=${line#???}
  case "$path" in
    *" -> "*) path=${path##* -> } ;;
  esac
  case "$path" in
    "$outdirs"|"$outdirs"/*|.agent-receipt/index.json|.agent-receipt/audit.jsonl|.agent-receipt/resign-provenance.json)
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
done)
if [ -z "$dirty" ]; then
  exit 0
fi

msg="grok session (uncommitted)"

run_wrap() {
  if command -v timeout >/dev/null 2>&1 && timeout 1 true >/dev/null 2>&1; then
    timeout 120 "$@" wrap --agent grok --redact --uncommitted --message "$msg" >/dev/null 2>&1 || true
    return 0
  fi
  "$@" wrap --agent grok --redact --uncommitted --message "$msg" >/dev/null 2>&1 &
  pid=$!
  # `sleep && kill`: a missing sleep must not fall through and kill wrap.
  ( sleep 120 && kill "$pid" 2>/dev/null ) &
  killer=$!
  wait "$pid" 2>/dev/null || true
  kill "$killer" 2>/dev/null || true
  wait "$killer" 2>/dev/null || true
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
