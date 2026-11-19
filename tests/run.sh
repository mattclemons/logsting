#!/usr/bin/env bash
# Run every module's test.sh against the one running stack. No rebuild, no branch.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/tools.sh"
ran=0; fails=0
for t in "$ROOT"/modules/*/test.sh; do
  [ -f "$t" ] || continue
  m=$(basename "$(dirname "$t")")
  ran=$((ran+1))
  echo "=== $m ==="
  bash "$t" || fails=$((fails+1))
done
echo "-------------------------"
echo "modules run: $ran   failed: $fails"
[ "$fails" -eq 0 ]
