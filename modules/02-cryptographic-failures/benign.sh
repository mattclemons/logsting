#!/usr/bin/env bash
# A02 benign: a normal request with the real, untouched token. Signature
# verifies, no finding.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
tok=$(C -X POST -H 'Content-Type: application/json' \
      -d '{"email":"maya@logsting.test","password":"sunshine"}' \
      "$BASE/api/login" | jq -r '.token')
C -H "Authorization: Bearer $tok" "$BASE/api/orders/1" >/dev/null
