#!/usr/bin/env bash
# A06 scanner: emit an OCSF 2004 finding for each dependency below its fixed
# version. Pure jq, no network, no node on the host required. In production this
# is npm audit / OSV / GitHub advisories; the local DB keeps the lab offline.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${1:?usage: scan.sh <manifest.json>}"
now_ms=$(( $(date +%s) * 1000 ))
now_iso="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
jq -c -n \
  --slurpfile adv "$HERE/advisories.json" \
  --slurpfile deps "$MANIFEST" \
  --argjson now "$now_ms" --arg iso "$now_iso" '
  def lt($a;$b):
    ($a|split(".")|map(tonumber)) as $pa |
    ($b|split(".")|map(tonumber)) as $pb |
    ( [range(0;3)] | map( ($pa[.]//0) - ($pb[.]//0) ) | map(select(.!=0)) ) as $d |
    if ($d|length)==0 then false else ($d[0] < 0) end;
  ($deps[0]) as $D | ($adv[0]) as $A |
  $D | to_entries[] as $dep | $A[] |
  select(.name==$dep.key and lt($dep.value; .fixed)) |
  { category_uid:2, class_uid:2004, activity_id:1, type_uid:200401,
    severity_id: (if .severity=="high" then 4 else 3 end),
    time:$now, time_dt:$iso,
    metadata:{product:{name:"logsting",vendor_name:"logsting-lab",version:"0.1.0"},version:"1.1.0"},
    finding_info:{title:("vulnerable dependency ("+.cve+")"),desc:.desc},
    message:("vulnerable dependency detected: "+$dep.key+"@"+$dep.value+" "+.cve),
    unmapped:{dependency:$dep.key,version:$dep.value,fixed:.fixed,cve:.cve} }
'
