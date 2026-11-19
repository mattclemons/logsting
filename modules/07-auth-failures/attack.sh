#!/usr/bin/env bash
# A07 attack: credential brute force. Hammer one account with wrong passwords.
# Each request is a clean login POST; the WAF sees nothing wrong. The app counts
# failures per source and raises a finding once the burst crosses the threshold.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
for i in $(seq 1 6); do
  C -X POST -H 'Content-Type: application/json' \
    -d "{\"email\":\"maya@logsting.test\",\"password\":\"wrong$i\"}" \
    "$BASE/api/login" >/dev/null
done
