#!/usr/bin/env bash
# A05 attack: authenticate with a seeded default account (admin/admin123) that
# should have been removed or rotated. A clean login request; the WAF sees
# nothing wrong. The app knows the account is a default and flags its use.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@logsting.test","password":"admin123"}' \
  "$BASE/api/login" >/dev/null
