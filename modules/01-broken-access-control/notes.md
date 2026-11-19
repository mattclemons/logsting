# A01 — Broken Access Control (BOLA/IDOR)

## The point
The classic flaw: the app checks authentication but not ownership. A logged-in
user asks for another user's object by id and gets it. The fix is the ownership
check. The detection is the logged decision, allow or deny, on every access.

## Why the WAF is blind
`GET /api/orders/2` with a valid session is a normal request. No payload, no
signature for CRS to match. Access control is identity plus ownership, which the
edge does not know. This lives in the app by definition.

## What the app does
Every order read logs an OCSF Web Resources Access event (6004) with the actor,
the resource, and the decision. A denied read is status Failure, decision deny.
It also returns 404 on deny, so the response does not confirm the object exists,
but the log still records the attempt.

## The detection
`detections/idor.yml` matches a 6004 deny. One deny is noise; the real signal is
rate: several denies from one actor in a short window is enumeration. Chainsaw
does not aggregate, so the shipped rule flags the deny event and the production
note is to add a per-actor count threshold in the SIEM. `test.sh` enumerates
three non-owned ids (fires) versus one owner read (silent).
