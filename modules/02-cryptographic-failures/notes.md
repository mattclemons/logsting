# A02 — Cryptographic Failures (tampered session token)

## The point
The session token is signed: `base64url(payload).base64url(HMAC-SHA256(payload))`.
The signature is what makes the payload trustworthy. If the app does not verify
it, or verifies it weakly, an attacker edits the payload (role=admin, another
user's id) and walks in. A02 is about getting the crypto right, and about seeing
when someone tests it.

## Why the WAF is blind
A forged token is a well-formed bearer token with a valid-looking value. No
payload signature for CRS to match. Only the app holds the signing key, so only
the app can tell a real token from a forged one.

## What the app does
- Verifies the HMAC on every request, with a constant-time compare. A plain
  string `===` leaks timing and is itself an A02 failure.
- Distinguishes a missing token (just unauthenticated) from a token that is
  present but fails verification (a tamper or forgery attempt). The second case
  raises an OCSF Detection Finding (2004).

## The detection
`detections/tampered_token.yml` matches the 2004 HMAC-failure finding. `test.sh`
sends a tampered token (fires) and a valid token (silent). The attack alters the
payload; because it cannot recompute the signature without the key, verification
fails and the finding fires.
