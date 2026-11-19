#!/usr/bin/env bash
# A10 full arc:
#   1. WAF blocks IP-based SSRF at the edge (403).
#   2. An internal hostname bypasses the WAF; the app's allowlist rejects it.
#   3. An allowlisted import is silent.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$(cd "$HERE/../.." && pwd)/scripts/env.sh"
RULE="$HERE/detections/ssrf.yml"; MAP="$HERE/mapping/ocsf-ndjson.yml"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

mark(){ [ -f "$APP_LOG" ] && wc -l < "$APP_LOG" 2>/dev/null | tr -d ' ' || echo 0; }
slice(){ local out="$WORK/${2:-slice}.ndjson"; tail -n +"$(( ${1:-0} + 1 ))" "$APP_LOG" 2>/dev/null > "$out" || true; echo "$out"; }
jqtrue(){ jq -s '[.[]|select(.class_uid==6003 and ((.message//"")|test("off allowlist")))]|length' "$1" 2>/dev/null || echo 0; }
hunt(){ local arr="$WORK/${2:-h}.json"; jq -s '.' "$1" > "$arr" 2>/dev/null || echo '[]' > "$arr"
        chainsaw hunt "$arr" --sigma "$RULE" --mapping "$MAP" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0; }

# 1. WAF should block the IP-based metadata SSRF.
code=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -G \
       --data-urlencode 'url=http://169.254.169.254/latest/meta-data/' "$BASE/api/import")
if [ "$code" = "403" ]; then pass "WAF blocked IP-based SSRF (403)"; else fail "WAF did not block IP SSRF (got $code)"; fi

# 2/3. benign silent, hostname bypass caught at the app allowlist.
b0=$(mark); bash "$HERE/benign.sh"; sleep 1; bsnap=$(slice "$b0" benign)
a0=$(mark); bash "$HERE/attack.sh"; sleep 1; asnap=$(slice "$a0" attack)
echo "  ground truth (jq): benign=$(jqtrue "$bsnap")  attack=$(jqtrue "$asnap")"
bhits=$(hunt "$bsnap" b); ahits=$(hunt "$asnap" a)
if [ "${bhits:-0}" -eq 0 ]; then pass "benign silent (chainsaw $bhits)"; else fail "benign fired (chainsaw $bhits)"; fi
if [ "${ahits:-0}" -ge 1 ]; then pass "bypass caught at app allowlist (chainsaw $ahits)"; else fail "bypass not caught (chainsaw $ahits)"; fi
