# LogSting

A secure, well-instrumented web app behind an OWASP Core Rule Set WAF, built to
show how to log and detect the OWASP Top 10 properly. It is the positive
counterpart to a deliberately vulnerable app: nothing here is exploitable by
design. Attacks are run against it, and the point is what the WAF and the app's
security log *see*, and which attacks slip past the WAF and are caught only at
the application layer.

## Two tiers, one Debian box

```
client ──▶ WAF (OWASP CRS, nginx)  ──▶  app (Node, secure + instrumented)
             │ JSON audit log              │ OCSF security events (NDJSON)
             ▼                             ▼
          logs/waf/audit.json          logs/app/security.ndjson
```

- **WAF tier** (`owasp/modsecurity-crs`): the edge. Catches the naive, generic
  payloads (SQLi, XSS, traversal) and logs them as a JSON audit record. It is
  blind to anything that looks like a normal request: IDOR, auth brute force,
  business-logic abuse.
- **App tier** (`app/`): secure, and instrumented to emit one OCSF event per
  security-relevant decision. This is where the durable detection lives, because
  it logs the *decision* (who, what, allowed or denied), not a pattern.

## Logging done right

Every event the app writes follows the same rules:

- **Structured**, one event per line, OCSF schema, so a SIEM ingests it unchanged.
- **The right events**: authentication outcomes, authorization decisions
  (allow and deny), input-validation failures, privileged access, and
  state-changing actions. Not page views, not debug noise.
- **The right fields**: timestamp, actor, source IP (the real client, taken from
  `X-Forwarded-For` behind the WAF), action, outcome, resource, and a
  `correlation_uid` so a single request joins across the WAF log and the app log.
- **Never** passwords, tokens, secrets, full card numbers or raw PII. A failed
  login logs the username and the outcome, never the attempted password.
- **A separate stream**: security events go to their own sink
  (`logs/app/security.ndjson`), not mixed into application or debug logs.

OCSF classes used: Authentication (3002), Web Resources Access (6004),
API Activity (6003), Detection Finding (2004).

## OWASP Top 10 coverage

| OWASP | WAF catches naive payload? | Where detection lives |
|---|---|---|
| A01 Broken Access Control | no | app: Web Resources Access 6004 allow/deny |
| A03 Injection | yes (bypassable) | WAF audit + app Detection Finding at the sink |
| A04 Insecure Design / business logic | no | app: API Activity 6003 anomaly |
| A05 Security Misconfiguration | no | app: Detection Finding 2004 on default-credential use |
| A06 Vulnerable & Outdated Components | n/a | scan: Detection Finding 2004 per dependency below its fix |
| A07 Identification & Authentication | no | app: Authentication 3002 failure rate |
| A08 Software & Data Integrity | no | app: Detection Finding 2004 on digest mismatch |
| A09 Logging & Monitoring Failures | no | app: Detection Finding 2004 on spoofed X-Forwarded-For |
| A10 SSRF | yes (bypassable) | WAF blocks IP target; app allowlist blocks hostname bypass (6003) |

A09 is where the logging pipeline itself is attacked. Two steps, in order:
enable XFF forwarding or the app logs the WAF's IP and the real attacker is
invisible; then trust XFF only from the WAF, or a client forges its source IP
and poisons the logs. CRS does not catch the spoof; the app does. See
`modules/09-logging-integrity/`.

A02 and A06 are configuration and dependency concerns rather than request-time
telemetry; the repo notes them but does not fake a runtime event.

## Run it

One command on a fresh Debian box. Clone, bootstrap, done.

```
git clone https://github.com/mattclemons/logsting.git
cd logsting
./bootstrap.sh
```

`bootstrap.sh` installs Docker if it is missing, builds the images, starts the
WAF and app, waits for health, and prints the URL. There are no branches and no
per-module checkout. The whole lab is the one running stack.

If Docker is already present, `make up` does the same build-and-start without
the install step. Other targets:

```
make test        # run every module's attack/benign tests against the stack
make app-log     # watch the OCSF security events
make waf-log     # watch the WAF JSON audit log
make down        # stop
make reset       # stop, wipe logs, rebuild
```

The WAF listens on 8080 and proxies to the app. Point your browser at
`http://localhost:8080/` or `http://<vm-ip>:8080/`.

If you replace repo files while the stack is running (re-extract an archive, for
example), recreate the containers so bind mounts rebind to the new directories:
`make reset`. A stale mount makes the app's log file writes fail silently.

## Modules

Each OWASP category is a module under `modules/NN-<name>/` with the same shape:

- `attack.sh` runs the attack through the WAF; `benign.sh` runs normal traffic.
- `detections/*.yml` are Sigma rules over the WAF log, the app log, or both.
- `test.sh` replays attack and benign traffic and asserts, with Chainsaw, that
  the rule fires on the attack and stays silent on the benign.

`make test` walks every module and runs its `test.sh` against the one stack that
is already up. No rebuild, no branch switch. To drive each module by hand with
`curl` and read the detections out of the OCSF log, see `VALIDATE.md`.

The contract is two-directional: a detection that fires on everything is as
useless as one that fires on nothing, so every test checks both.

## Status

Base stack: WAF + instrumented app + OCSF logging. Modules are added in OWASP
order, A01 through A10.

- A01 Broken Access Control (BOLA/IDOR) — built
- A02 Cryptographic Failures (tampered session token) — built
- A03 Injection (WAF catch, header bypass, app catch) — built
- A04 Insecure Design (business-logic checkout) — built
- A05 Security Misconfiguration (default credentials) — built
- A06 Vulnerable & Outdated Components (dependency scan) — built
- A07 Identification & Authentication Failures (brute force) — built
- A08 Software & Data Integrity Failures (pinned-digest check) — built
- A09 Logging & Monitoring Failures (XFF log poisoning) — built
- A10 SSRF (WAF catch, hostname bypass, app allowlist) — built
