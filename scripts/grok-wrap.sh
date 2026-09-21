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
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
msg="grok session"
if [ "${1:-}" != "" ] && [ "${1#-}" = "$1" ]; then
  msg=$1
  shift
fi
exec node "$root/bin/agent-receipt.js" wrap --agent grok --redact --message "$msg" "$@"
