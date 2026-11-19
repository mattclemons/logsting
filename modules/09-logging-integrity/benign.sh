#!/usr/bin/env bash
# A09 benign: a normal client. No client-set XFF, so the WAF adds exactly one
# hop and the app records the real client. No finding should fire.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C "$BASE/api/search?q=hello" >/dev/null
