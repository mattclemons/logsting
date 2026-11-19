# Sourced by module attack/benign scripts and tests.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export BASE="${BASE:-http://localhost:8080}"
export APP_LOG="$ROOT/logs/app/security.ndjson"
export WAF_LOG="$ROOT/logs/waf/audit.json"
C(){ curl -s --noproxy '*' --max-time 20 "$@"; }
pass(){ printf 'PASS  %s\n' "$1"; }
fail(){ printf 'FAIL  %s\n' "$1"; exit 1; }
