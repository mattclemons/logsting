#!/usr/bin/env bash
# A04 benign: a normal checkout, quantity 2. Passes the business rule, no finding.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
tok=$(C -X POST -H 'Content-Type: application/json' \
      -d '{"email":"maya@logsting.test","password":"sunshine"}' \
      "$BASE/api/login" | jq -r '.token')
C -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $tok" \
  -d '{"sku":"sku-blue-shoe","qty":2}' "$BASE/api/checkout" >/dev/null
