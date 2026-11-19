#!/usr/bin/env bash
# A08 attack: submit a tampered rules pack. One byte changed, so the SHA-256 no
# longer matches the pinned digest. A clean POST the WAF cannot judge; the app
# rejects it on integrity and flags it.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
body=$(jq -nc --arg p 'rules-pack-v1:allow maya; version=1; allow attacker' '{name:"rules-pack-v1",payload:$p}')
C -X POST -H 'Content-Type: application/json' -d "$body" "$BASE/api/plugin" >/dev/null
