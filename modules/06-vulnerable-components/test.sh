#!/usr/bin/env bash
# A06 two-directional, scan-driven: fire on a manifest with a vulnerable pin,
# silent on a fully patched manifest. No traffic, no app log; the scanner output
# is the input to the detection.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$(cd "$HERE/../.." && pwd)/scripts/env.sh"
RULE="$HERE/detections/vulnerable_dependency.yml"; MAP="$HERE/mapping/ocsf-ndjson.yml"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

bash "$HERE/scan.sh" "$HERE/manifests/clean.json"      > "$WORK/benign.ndjson" 2>/dev/null || true
bash "$HERE/scan.sh" "$HERE/manifests/vulnerable.json" > "$WORK/attack.ndjson" 2>/dev/null || true

jqtrue(){ jq -s '[.[]|select(.class_uid==2004 and ((.message//"")|test("vulnerable dependency")))]|length' "$1" 2>/dev/null || echo 0; }
hunt(){ local arr="$WORK/${2:-h}.json"; jq -s '.' "$1" > "$arr" 2>/dev/null || echo '[]' > "$arr"
        chainsaw hunt "$arr" --sigma "$RULE" --mapping "$MAP" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0; }

echo "  ground truth (jq): benign=$(jqtrue "$WORK/benign.ndjson")  attack=$(jqtrue "$WORK/attack.ndjson")"
bhits=$(hunt "$WORK/benign.ndjson" b); ahits=$(hunt "$WORK/attack.ndjson" a)
if [ "${bhits:-0}" -eq 0 ]; then pass "clean manifest silent (chainsaw $bhits)"; else fail "clean manifest fired (chainsaw $bhits)"; fi
if [ "${ahits:-0}" -ge 1 ]; then pass "vulnerable manifest fired (chainsaw $ahits)"; else fail "vulnerable manifest silent (chainsaw $ahits)"; fi
