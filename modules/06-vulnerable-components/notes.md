# A06 — Vulnerable and Outdated Components

## The point
A06 is not a request. The flaw ships with the app: a dependency with a known
CVE. There is no payload to catch at runtime and nothing for the WAF to match.
The control is software composition analysis: know what you ship, compare it to
advisories, and alert on a match.

## Why this module has a different shape
Every other module drives traffic and reads the app log. This one runs a scan.
`scan.sh` reads a dependency manifest and a local advisory list and emits an
OCSF Detection Finding (2004) for each component below its fixed version. The
same Sigma rule and Chainsaw evaluation then apply, so A06 lands in the same
detection pipeline as everything else.

## What the scan does
- `advisories.json` is a small local CVE list (lodash, minimist, express).
- `manifests/vulnerable.json` pins lodash and minimist below their fixes.
- `manifests/clean.json` is fully patched.
- `scan.sh <manifest>` prints one 2004 finding per vulnerable dependency.

The local advisory list keeps the lab offline. In production this is `npm audit`,
OSV, or GitHub advisories against the real lockfile. The app's own dependencies
are current; these manifests are fixtures for the exercise.

## The detection
`detections/vulnerable_dependency.yml` matches the 2004 vulnerable-dependency
finding. `test.sh` scans the vulnerable manifest (fires) and the clean one
(silent).
