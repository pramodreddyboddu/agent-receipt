/**
 * Project hook that wraps a dirty tree and passes transcript_path when the
 * host puts it on stdin. Stdin is drained with a short quiet period so an
 * open pipe cannot hang wrap. The script always exits 0.
 */
export function wrapHookScript(agent: 'claude-code' | 'codex' | 'cursor'): string {
  return `#!/bin/sh
# ${agent} hook written by agent-receipt.
# Wraps only when the working tree is dirty. Always passes --redact.
# Reads transcript_path (or transcriptPath) from the hook JSON on stdin.
# Non-blocking: a short read, then stdin is closed. Always exits 0.
set -u

transcript=""
if [ -t 0 ]; then
  :
else
  if command -v node >/dev/null 2>&1; then
    transcript=$(HOOK_STDIN_MAX="\${HOOK_STDIN_MAX:-65536}" HOOK_STDIN_WAIT_SEC="\${HOOK_STDIN_WAIT_SEC:-0.4}" node -e 'const maxRaw=parseInt(process.env.HOOK_STDIN_MAX||"65536",10); const max=Number.isFinite(maxRaw)?Math.min(Math.max(maxRaw,1),1048576):65536; const waitRaw=parseFloat(process.env.HOOK_STDIN_WAIT_SEC||"0.4"); const waitMs=Number.isFinite(waitRaw)?Math.max(0,Math.round(waitRaw*1000)):400; let buf=[]; let got=0; let done=false; const finish=()=>{if(done)return; done=true; let path=""; try{ const doc=JSON.parse(Buffer.concat(buf).toString("utf8")); const p=doc&&(doc.transcript_path||doc.transcriptPath); if(typeof p==="string") path=p; }catch(e){} process.stdout.write(path); process.exit(0);}; let timer=setTimeout(finish,waitMs); process.stdin.on("data",(b)=>{buf.push(b); got+=b.length; if(got>=max){clearTimeout(timer); finish(); return;} clearTimeout(timer); timer=setTimeout(finish,30);}); process.stdin.on("end",()=>{clearTimeout(timer); finish();}); process.stdin.on("error",()=>{clearTimeout(timer); finish();}); process.stdin.resume();' || true)
  elif command -v timeout >/dev/null 2>&1 && timeout "\${HOOK_STDIN_WAIT_SEC:-0.4}" true >/dev/null 2>&1; then
    timeout "\${HOOK_STDIN_WAIT_SEC:-0.4}" dd bs="\${HOOK_STDIN_MAX:-65536}" count=1 of=/dev/null 2>/dev/null || true
  fi
  exec 0</dev/null
fi

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$root" || exit 0

# Ignore the receipt out dir and the store files wrap itself writes.
# --untracked-files=all lists files inside an untracked directory instead of
# one collapsed "?? .agent-receipt/" line, which would keep every Stop dirty.
outdirs=".agent-receipt/receipts"
if [ -f .agent-receipt.yml ]; then
  cfg=$(sed -n 's/^outDir:[[:space:]]*//p' .agent-receipt.yml | head -n 1)
  cfg=$(printf '%s' "$cfg" | tr -d '"' | tr -d "'" | sed 's:/*$::')
  if [ -n "$cfg" ]; then
    outdirs="$cfg"
  fi
fi
dirty=$(git status --porcelain=v1 --untracked-files=all 2>/dev/null | while IFS= read -r line; do
  path=\${line#???}
  case "\$path" in
    *" -> "*) path=\${path##* -> } ;;
  esac
  case "\$path" in
    "\$outdirs"|"\$outdirs"/*|.agent-receipt/index.json|.agent-receipt/audit.jsonl|.agent-receipt/resign-provenance.json)
      ;;
    *)
      printf '%s\\n' "\$line"
      ;;
  esac
done)
if [ -z "$dirty" ]; then
  exit 0
fi

run_wrap() {
  if command -v timeout >/dev/null 2>&1 && timeout 1 true >/dev/null 2>&1; then
    if [ -n "$transcript" ] && [ -f "$transcript" ]; then
      timeout 120 "$@" wrap --agent ${agent} --redact --transcript "$transcript" >/dev/null 2>&1 || true
    else
      timeout 120 "$@" wrap --agent ${agent} --redact >/dev/null 2>&1 || true
    fi
    return 0
  fi
  if [ -n "$transcript" ] && [ -f "$transcript" ]; then
    "$@" wrap --agent ${agent} --redact --transcript "$transcript" >/dev/null 2>&1 &
  else
    "$@" wrap --agent ${agent} --redact >/dev/null 2>&1 &
  fi
  pid=$!
  # \`sleep && kill\`: a missing sleep must not fall through and kill wrap.
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

echo "agent-receipt: not on PATH; skipped ${agent} wrap" >&2
exit 0
`;
}
