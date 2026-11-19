#!/usr/bin/env bash
# Diagnose why Chainsaw matches nothing. Prints version, event counts, a lint of
# the rule+mapping, and a verbose hunt. Run after the stack has handled traffic.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/tools.sh"
M="$ROOT/modules/09-logging-integrity"
EV=/tmp/ls-ev.json
jq -s '.' "$ROOT/logs/app/security.ndjson" > "$EV" 2>/dev/null || echo '[]' > "$EV"

echo "### chainsaw version"
chainsaw --version 2>&1 | head -2
echo "### event counts"
echo "total=$(jq 'length' "$EV")  findings_2004=$(jq '[.[]|select(.class_uid==2004)]|length' "$EV")  authz_6004=$(jq '[.[]|select(.class_uid==6004)]|length' "$EV")"
echo "### one 2004 event (shape)"
jq -c '[.[]|select(.class_uid==2004)][0] | {class_uid,status_id,message,time_dt}' "$EV"
echo "### chainsaw lint"
chainsaw lint --sigma "$M/detections/xff_spoof.yml" 2>&1 | head -20
echo "### chainsaw hunt (verbose, no --json)"
chainsaw hunt "$EV" --sigma "$M/detections/xff_spoof.yml" --mapping "$M/mapping/ocsf-ndjson.yml" 2>&1 | head -40
