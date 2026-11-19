# A05 — Security Misconfiguration (default credentials)

## The point
Misconfiguration is not a payload; it is a state. A seeded admin account with a
known password, left enabled after deployment, is the textbook case. The attack
is just logging in. The defense is removing or rotating the account, and the
detection is noticing when a default account authenticates at all.

## Why the WAF is blind
`admin@logsting.test / admin123` is a valid login request. The WAF has no
inventory of your accounts, so it cannot know this one should not exist. Which
accounts are defaults is app and deployment knowledge.

## What the app does
Default accounts are flagged in the app. On any login touching a flagged
account, success or failure, the app raises an OCSF Detection Finding (2004)
naming the account and whether it succeeded. In production the real fix is to
remove the account; the finding covers the window before that happens and catches
anyone probing known defaults.

## The detection
`detections/default_credential.yml` matches the 2004 default-credential finding.
`test.sh` logs in as the default admin (fires) and as a normal user (silent).
Keep a deliberate break-glass account out of the alert with an explicit
exclusion.
