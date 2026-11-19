#!/usr/bin/env bash
# A08 benign: apply the genuine rules pack. Its content matches the pinned
# SHA-256, so integrity verifies and it is applied. No finding.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
body=$(jq -nc --arg p 'rules-pack-v1:allow maya; version=1' '{name:"rules-pack-v1",payload:$p}')
C -X POST -H 'Content-Type: application/json' -d "$body" "$BASE/api/plugin" >/dev/null
