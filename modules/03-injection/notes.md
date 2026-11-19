# A03 — Injection (WAF catch, bypass, app catch)

## The point
This is the module that shows the WAF's value and its limit in one place.
- The WAF blocks injection in what it inspects: query args, request bodies. A
  naive `' OR 1=1-- -` in `q` is blocked at the edge (403).
- The WAF does not inspect what it was not told to. The app reads an advanced
  filter from a custom header, `X-Search-Filter`. CRS does not parse arbitrary
  custom headers, so the same payload there reaches the app.
- The app catches it at the sink, because the app knows the input's context.

## Why the WAF misses the bypass
A WAF inspects a defined set of locations. Anything your app reads from outside
that set, a custom header, a field the WAF does not decode, an encoding it does
not normalize, arrives unflagged. The bypass here is not a clever evasion string;
it is input in a place the WAF never looked.

## What the app does
`/api/search` runs the attack-signature check over both the query arg and the
`X-Search-Filter` header. A match raises an OCSF Detection Finding (2004) that
records which input carried the payload. The query stays parameterized and safe;
the finding is about visibility, not a SQL vulnerability.

## The detection
`detections/injection.yml` matches the 2004 "attack signature" finding.
`test.sh` asserts three things: the WAF blocks the naive query payload (403), a
benign search is silent, and the header bypass is caught at the app.

## Tuning note
The WAF-block assertion depends on CRS blocking the naive payload at paranoia 1,
which libinjection does by default. The bypass depends on CRS not inspecting the
custom header, which is the default. If your CRS build differs, this is the
module to adjust first.
