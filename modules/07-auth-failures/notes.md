# A07 — Identification and Authentication Failures (brute force)

## The point
One failed login is normal. A run of them from one source is an attack. The
difference is rate, and rate is only visible if you count. A07 is about measuring
authentication at the point attempts arrive, and acting on the pattern.

## Why the WAF is blind
Each login is a clean POST with a valid-looking body. The WAF inspects one
request at a time; it has no memory of the last five from this source and no
model of your accounts. Brute force is a property of the sequence, not any single
request.

## What the app does
The app keeps a per-source failure count in a sliding window. Every failure is
logged as an OCSF Authentication event (3002). When failures from one source
cross the threshold, the app raises a Detection Finding (2004). A successful
login clears the streak.

## The detection
`detections/brute_force.yml` matches the 2004 threshold finding, not the
individual 3002 failures, so it fires once the burst is real rather than on every
miss. `test.sh` sends six wrong passwords (fires) and one correct login (silent).
On shared egress IPs, key on account as well as source to avoid grouping
unrelated users.
