#!/usr/bin/env bash
# Visibility demo: prove the app logs the REAL client, not the WAF.
# Sends one request through the WAF, then prints the src_ip the app recorded.
# If XFF forwarding were off, this would show the WAF's subnet (172.30.0.x).
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/env.sh"
C "$BASE/api/search?q=hello" >/dev/null
sleep 1
ip=$(tail -n 1 "$APP_LOG" 2>/dev/null | jq -r '.src_endpoint.ip // "unknown"')
echo "app logged src_ip: $ip"
echo "(a 172.30.0.x value here means XFF is NOT reaching the app: you are seeing the WAF)"
