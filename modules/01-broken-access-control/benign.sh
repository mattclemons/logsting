#!/usr/bin/env bash
# A01 benign: maya reads her own order 1. Allowed. One 6004 allow, no deny.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
tok=$(C -X POST -H 'Content-Type: application/json' \
      -d '{"email":"maya@logsting.test","password":"sunshine"}' \
      "$BASE/api/login" | jq -r '.token')
C -H "Authorization: Bearer $tok" "$BASE/api/orders/1" >/dev/null
