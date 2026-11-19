#!/usr/bin/env bash
# A10 benign: import from an allowlisted host. Allowed, no finding.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C -G --data-urlencode 'url=https://cdn.logsting.test/logo.png' "$BASE/api/import" >/dev/null
