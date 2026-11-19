#!/usr/bin/env bash
# A01 attack: BOLA/IDOR. Log in as maya (owns order 1), then enumerate order
# IDs she does not own. Each is denied, but the authorization decision is logged,
# so the probe leaves a trail of 6004 denies from one actor.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
tok=$(C -X POST -H 'Content-Type: application/json' \
      -d '{"email":"maya@logsting.test","password":"sunshine"}' \
      "$BASE/api/login" | jq -r '.token')
for id in 2 3 4; do
  C -H "Authorization: Bearer $tok" "$BASE/api/orders/$id" >/dev/null
done
