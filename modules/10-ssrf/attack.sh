#!/usr/bin/env bash
# A10 attack (bypass): the WAF blocks IP-based SSRF, so aim at an internal
# hostname instead. CRS does not recognize metadata.internal.lab as dangerous,
# so the request reaches the app, where the allowlist rejects the off-allowlist
# host. Same lesson as A03: the WAF catches the obvious, the app holds the line.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C -G --data-urlencode 'url=http://metadata.internal.lab/latest/meta-data/' "$BASE/api/import" >/dev/null
