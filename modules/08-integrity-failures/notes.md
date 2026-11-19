# A08 — Software and Data Integrity Failures

## The point
Code and data arrive from somewhere: an update server, a CI artifact, a plugin
upload. If you apply them without checking integrity, an attacker who can alter
the bytes in transit or at rest controls your app. The defense is verifying
content against a trusted, pinned digest or signature before you use it.

## Why the WAF is blind
The payload is a normal POST body. The WAF has no idea what the bytes should hash
to; it holds no pin and no signing key. Integrity is defined by the app's trust
anchor, so only the app can check it.

## What the app does
`/api/plugin` accepts a named update and computes its SHA-256. It applies the
update only if the digest matches the pinned value for that release. A mismatch,
one changed byte, means tampered or untrusted content, so the app rejects it and
raises an OCSF Detection Finding (2004). A real pipeline would verify a signature
over the digest; the pin is the same idea with the key left out of the lab.

## The detection
`detections/integrity_failure.yml` matches the 2004 integrity-check finding.
`test.sh` submits the genuine pinned payload (silent) and a tampered one (fires).
