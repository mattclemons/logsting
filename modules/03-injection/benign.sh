#!/usr/bin/env bash
# A03 benign: an ordinary search. No attack tokens anywhere. No finding.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/env.sh"
C "$BASE/api/search?q=blue+shoes" >/dev/null
