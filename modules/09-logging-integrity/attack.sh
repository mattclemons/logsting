#!/usr/bin/env bash
# A09 attack: forge the source IP with a client-set X-Forwarded-For.
# The WAF forwards the request and appends the real hop. A naive app would log
# 203.0.113.9 as the client and poison every IP-based detection downstream.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C -H 'X-Forwarded-For: 203.0.113.9' "$BASE/api/search?q=hello" >/dev/null
