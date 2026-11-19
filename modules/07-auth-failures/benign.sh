#!/usr/bin/env bash
# A07 benign: one normal, successful login. No failure burst, no finding.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C -X POST -H 'Content-Type: application/json' \
  -d '{"email":"maya@logsting.test","password":"sunshine"}' \
  "$BASE/api/login" >/dev/null
