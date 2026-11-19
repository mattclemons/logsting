# A09 — Security Logging and Monitoring Failures: X-Forwarded-For log poisoning

## The point
A09 is usually treated as process and config, not a runtime event. XFF makes it
concrete. The thing under attack is the log itself.

Behind a reverse-proxy WAF the app no longer sees the client's real IP on the
socket; it sees the WAF. The real client is carried in `X-Forwarded-For`. The
trap: XFF is just a request header, so the client can set it. If the app trusts
the leftmost value, an attacker picks the IP that lands in your SIEM.

## Why the WAF does not save you
CRS matches payloads: SQLi, XSS, traversal. A spoofed XFF is a well-formed
header with a valid IP. Nothing for CRS to match. The request passes clean.
This is the WAF/app split in one request: the edge is blind, the app is not.

## What the app does
- `trust proxy` is set to the WAF subnet, never `true`. Express resolves the
  real client by walking XFF right to left and skipping the trusted hop.
- Behind one proxy, a legitimate request shows exactly one XFF entry. More than
  one means the client injected its own. The app emits an OCSF Detection Finding
  (class_uid 2004) with the claimed IP, the resolved client, and the full chain.

## The detection
`detections/xff_spoof.yml` matches the 2004 finding. `test.sh` runs the attack
and benign traffic through the WAF, slurps the NDJSON into a JSON array, and
hunts with Chainsaw. Contract: fire on attack, silent on benign.

## Production note
The "more than one hop means spoof" rule holds because this lab has one proxy.
In a real CDN -> WAF -> app chain you expect a known hop count; trust by the
count or by trusted-proxy CIDRs, not by assuming one.

## The other half: you must enable XFF first
Integrity (do not trust XFF blindly) only matters once you have visibility
(the app receives XFF at all). These are two separate steps:

1. Enable forwarding at the proxy. Without it the backend's socket peer is the
   WAF, so `src_ip` is the WAF on every event and the real attacker is invisible.
   The CRS nginx image forwards XFF and X-Real-IP in proxy mode by default; many
   stacks do not, so treat it as a step you own. See `reference/proxy-headers.conf`.
2. Trust it correctly. Now that the client controls a header the app reads, bind
   trust to the WAF subnet and resolve the real client from the right, as the app
   does. Enabling XFF without this is what creates the spoofing exposure above.

Prove visibility: `bash scripts/show-client-ip.sh` prints the `src_ip` the app
recorded. A WAF-subnet address there means XFF is not reaching the app.
