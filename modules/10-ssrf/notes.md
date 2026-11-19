# A10 — Server-Side Request Forgery (SSRF)

## The point
SSRF turns your server into a proxy: the attacker supplies a URL and the server
fetches it from its own network position. The prize is internal, cloud metadata
at 169.254.169.254, internal admin pages, databases. The control is an allowlist
of hosts the app may reach; the signal is any attempt to leave it.

## WAF catch, bypass, app catch
- The WAF blocks the obvious target. A dotted-IP metadata URL in a parameter
  trips the CRS RFI rule and is rejected at the edge (403). Decimal and nip.io
  encodings of the same IP are blocked too.
- The WAF does not block what it does not recognize. `http://metadata.internal.lab/`
  is a plausible internal hostname with no IP for CRS to flag, so it reaches the
  app.
- The app holds the line. The host is not on the import allowlist, so the fetch
  is refused and logged.

## Why the allowlist, not a blocklist
You cannot enumerate every internal address an attacker might try: IPs, encodings,
DNS tricks, redirects. You can name the few hosts the app legitimately needs. An
allowlist fails closed; a blocklist fails open on the first encoding you forgot.

## What the app does
`/api/import` parses the target host and fetches only allowlisted hosts. Any
other target, internal hostname or external, is refused and logged as an OCSF API
Activity event (6003, status Failure).

## The detection
`detections/ssrf.yml` matches the 6003 off-allowlist failure. `test.sh` asserts
the WAF blocks the IP SSRF (403), an allowlisted import is silent, and the
internal-hostname bypass is caught at the app allowlist.
