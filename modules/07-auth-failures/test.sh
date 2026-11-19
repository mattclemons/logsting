#!/usr/bin/env bash
# A07 two-directional: fire on a failure burst (2004 threshold finding), silent
# on a single successful login.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$(cd "$HERE/../.." && pwd)/scripts/env.sh"
RULE="$HERE/detections/brute_force.yml"; MAP="$HERE/mapping/ocsf-ndjson.yml"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

mark(){ [ -f "$APP_LOG" ] && wc -l < "$APP_LOG" 2>/dev/null | tr -d ' ' || echo 0; }
slice(){ local out="$WORK/${2:-slice}.ndjson"; tail -n +"$(( ${1:-0} + 1 ))" "$APP_LOG" 2>/dev/null > "$out" || true; echo "$out"; }
jqtrue(){ jq -s '[.[]|select(.class_uid==2004 and ((.message//"")|test("authentication failures from one source")))]|length' "$1" 2>/dev/null || echo 0; }
hunt(){ local arr="$WORK/${2:-h}.json"; jq -s '.' "$1" > "$arr" 2>/dev/null || echo '[]' > "$arr"
        chainsaw hunt "$arr" --sigma "$RULE" --mapping "$MAP" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0; }

b0=$(mark); bash "$HERE/benign.sh"; sleep 1; bsnap=$(slice "$b0" benign)
a0=$(mark); bash "$HERE/attack.sh"; sleep 1; asnap=$(slice "$a0" attack)
echo "  ground truth (jq): benign=$(jqtrue "$bsnap")  attack=$(jqtrue "$asnap")"
bhits=$(hunt "$bsnap" b); ahits=$(hunt "$asnap" a)
if [ "${bhits:-0}" -eq 0 ]; then pass "benign silent (chainsaw $bhits)"; else fail "benign fired (chainsaw $bhits)"; fi
if [ "${ahits:-0}" -ge 1 ]; then pass "attack fired (chainsaw $ahits)"; else fail "attack silent (chainsaw $ahits)"; fi
