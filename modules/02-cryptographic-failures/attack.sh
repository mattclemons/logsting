#!/usr/bin/env bash
# A02 attack: tamper a signed session token. Log in to get a valid token, then
# alter the payload portion. The HMAC no longer matches, so the forged token is
# rejected and flagged. The real-world version edits the payload to escalate
# (role=admin, another user's id); it fails identically, because the attacker
# cannot recompute the signature without the key.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
tok=$(C -X POST -H 'Content-Type: application/json' \
      -d '{"email":"maya@logsting.test","password":"sunshine"}' \
      "$BASE/api/login" | jq -r '.token')
body="${tok%.*}"; mac="${tok##*.}"
last="${body: -1}"; [ "$last" = "A" ] && rep="B" || rep="A"
forged="${body%?}${rep}.${mac}"
C -H "Authorization: Bearer $forged" "$BASE/api/orders/1" >/dev/null
