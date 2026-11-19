# LogSting manual validation

Each module is driven by hand with `curl`, twice. First vulnerable, then patched,
so you see the attack working and invisible, then the same request blocked and
logged.

The lab flag `?vuln=1` (or header `X-Lab-Vuln: 1`) runs an endpoint's vulnerable
path: the control is off and nothing is written to the security log. Drop the
flag and the control is enforced and the detection fires. Same running stack, no
restart. The flag is lab-only and never ships.

All commands assume the stack is up (`./bootstrap.sh`) and you are in the repo
root. The WAF listens on `:8080` and proxies to the app.

## Watch the logs

```
make app-log      # ./logs/app/security.ndjson   (OCSF security events)
make waf-log      # ./logs/waf/audit.json         (WAF JSON audit)
```

Compact viewer, prints the last N security events, one line each:

```
ev(){ tail -n "${1:-3}" logs/app/security.ndjson \
      | jq -c '{class_uid,status_id,sev:.severity_id,src:.src_endpoint.ip,msg:.message}'; }
```

A viewer for the WAF audit log. It holds only relevant (flagged or blocked)
transactions, so benign traffic never appears here:

```
waf(){ tail -n "${1:-3}" logs/waf/audit.json \
       | jq -c '{uri:.transaction.request.uri, msgs:[.transaction.messages[]?.message]}'; }
```

Login helper, reused below:

```
login(){ curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' \
         -d "{\"email\":\"$1\",\"password\":\"$2\"}" http://localhost:8080/api/login; }
```

OCSF fields you will read: `class_uid` (3002 Authentication, 6004 Web Resources
Access, 6003 API Activity, 2004 Detection Finding), `status_id` (1 Success, 2
Failure), `message`, `src_endpoint.ip`.

How to read the two runs: after a **vulnerable** request, `ev` shows no new
finding (the attack left no trace). After the **patched** request, `ev` shows the
detection. Where a module logs an ordinary event even when vulnerable (logins),
that event is still there; what is missing is the finding.

---

## A01 — Broken Access Control (BOLA/IDOR)

maya (user 2) reaches for order 2, which belongs to user 3.

```
TOK=$(login maya@logsting.test sunshine | jq -r .token)

# VULNERABLE: no ownership check, nothing logged
curl -s --noproxy '*' -H "Authorization: Bearer $TOK" "http://localhost:8080/api/orders/2?vuln=1"
# {"order":{"id":2,"user_id":3,...}}   another user's order leaks
ev 1    # last event is unrelated: the read was not logged

# PATCHED: ownership enforced, denied and logged
curl -s --noproxy '*' -H "Authorization: Bearer $TOK" "http://localhost:8080/api/orders/2"
# {"error":"no such order"}   (404, does not confirm the order exists)
ev 1
# {"class_uid":6004,"status_id":2,...,"msg":"order read denied (not owner)"}
```

Automated: `bash modules/01-broken-access-control/test.sh`

---

## A02 — Cryptographic Failures (forged session token)

Forge a token that claims to be user 3, with a garbage signature.

```
FB=$(printf '%s' '{"sub":3,"email":"sam@logsting.test","role":"customer"}' | base64 | tr '+/' '-_' | tr -d '=')
FORGED="$FB.notavalidsignature"

# VULNERABLE: signature not verified, forged identity accepted
curl -s --noproxy '*' -H "Authorization: Bearer $FORGED" "http://localhost:8080/api/orders/2?vuln=1"
# {"order":{...}}   the forged token is trusted
ev 1    # no finding

# PATCHED: HMAC checked, forged token rejected and logged
curl -s --noproxy '*' -H "Authorization: Bearer $FORGED" "http://localhost:8080/api/orders/2"
# {"error":"log in first"}   (401)
ev 1
# {"class_uid":2004,...,"msg":"session token failed HMAC verification: possible forgery or tampering"}
```

Automated: `bash modules/02-cryptographic-failures/test.sh`

---

## A03 — Injection (WAF catch, header bypass, app catch)

The WAF blocks naive SQLi in a query arg, always:

```
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' -G \
  --data-urlencode "q=' OR 1=1-- -" http://localhost:8080/api/search
# 403   blocked at the edge, never reaches the app

# the WAF audit log records the block; the app log shows nothing for it
waf 2
# {"uri":"/api/search?q=' OR 1=1-- -","msgs":["... SQL Injection Attack Detected ..."]}
```

The bypass rides a custom header the WAF does not inspect. It will not appear in
the WAF log either, because nothing flagged it there.

```
# VULNERABLE: the app does not inspect the input, nothing logged
curl -s --noproxy '*' -H "X-Search-Filter: ' OR 1=1-- -" "http://localhost:8080/api/search?q=hello&vuln=1" >/dev/null
ev 1    # no finding: the bypass is invisible

# PATCHED: the app checks the input at the sink and flags it
curl -s --noproxy '*' -H "X-Search-Filter: ' OR 1=1-- -" "http://localhost:8080/api/search?q=hello" >/dev/null
ev 1
# {"class_uid":2004,...,"msg":"request matched an attack signature after the WAF"}
```

Automated: `bash modules/03-injection/test.sh`

---

## A04 — Insecure Design (business logic)

Checkout a negative quantity against a positive price.

```
TOK=$(login maya@logsting.test sunshine | jq -r .token)

# VULNERABLE: no quantity rule, the negative total is accepted
curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
  -d '{"sku":"sku-blue-shoe","qty":-5}' "http://localhost:8080/api/checkout?vuln=1"
# {"sku":"sku-blue-shoe","qty":-5,"total":-24995}   refund abuse works
ev 1    # no finding

# PATCHED: the rule rejects it and logs it
curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
  -d '{"sku":"sku-blue-shoe","qty":-5}' "http://localhost:8080/api/checkout"
# {"error":"invalid checkout"}   (400)
ev 1
# {"class_uid":6003,"status_id":2,...,"msg":"checkout rejected: business rule violation"}
```

Automated: `bash modules/04-insecure-design/test.sh`

---

## A05 — Security Misconfiguration (default credentials)

Log in as the seeded `admin / admin123` account.

```
# VULNERABLE: default-account use is not flagged
curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@logsting.test","password":"admin123"}' "http://localhost:8080/api/login?vuln=1" >/dev/null
ev 1    # a 3002 login success, but no default-credential finding

# PATCHED: the default login is flagged
curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@logsting.test","password":"admin123"}' "http://localhost:8080/api/login" >/dev/null
ev 2
# a 3002 login success, plus
# {"class_uid":2004,...,"msg":"login with a known default credential succeeded"}
```

Automated: `bash modules/05-security-misconfiguration/test.sh`

---

## A06 — Vulnerable and Outdated Components

Not a request; a scan. The two manifests are the before and after.

```
cd modules/06-vulnerable-components

# VULNERABLE manifest: pinned to old versions -> one finding per CVE
bash scan.sh manifests/vulnerable.json | jq -c '{msg:.message,cve:.unmapped.cve}'
# lodash@4.17.11 CVE-2019-10744, minimist@1.2.5 CVE-2021-44906

# PATCHED manifest: fully updated -> no output
bash scan.sh manifests/clean.json
cd ../..
```

Automated: `bash modules/06-vulnerable-components/test.sh`

---

## A07 — Authentication Failures (brute force)

Hammer one account with wrong passwords.

```
# VULNERABLE: the burst is never flagged
for i in $(seq 1 6); do
  curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' \
    -d "{\"email\":\"maya@logsting.test\",\"password\":\"wrong$i\"}" \
    "http://localhost:8080/api/login?vuln=1" >/dev/null
done
ev 3    # 3002 login failures, but no threshold finding

# clear state, then PATCHED
login maya@logsting.test sunshine >/dev/null
for i in $(seq 1 6); do login maya@logsting.test "wrong$i" >/dev/null; done
ev 3
# {"class_uid":2004,...,"msg":"repeated authentication failures from one source exceeded threshold"}
```

Automated: `bash modules/07-auth-failures/test.sh`

---

## A08 — Software and Data Integrity Failures

Submit a tampered rules pack.

```
PKG='{"name":"rules-pack-v1","payload":"rules-pack-v1:allow maya; version=1; allow attacker"}'

# VULNERABLE: applied without an integrity check
curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' -d "$PKG" \
  "http://localhost:8080/api/plugin?vuln=1"
# {"ok":true,"name":"rules-pack-v1","applied":true}   malicious update applied
ev 1    # no finding

# PATCHED: digest mismatch rejected and logged
curl -s --noproxy '*' -X POST -H 'Content-Type: application/json' -d "$PKG" \
  "http://localhost:8080/api/plugin"
# {"error":"integrity check failed"}   (409)
ev 1
# {"class_uid":2004,...,"msg":"update payload failed integrity check: digest mismatch"}
```

Automated: `bash modules/08-integrity-failures/test.sh`

---

## A09 — Logging and Monitoring Failures (X-Forwarded-For)

Log in while forging an X-Forwarded-For, and watch which source the SOC records.

```
# VULNERABLE: the app trusts the client's XFF, so the logged source is a lie
curl -s --noproxy '*' -H 'X-Forwarded-For: 203.0.113.9' -X POST -H 'Content-Type: application/json' \
  -d '{"email":"maya@logsting.test","password":"sunshine"}' "http://localhost:8080/api/login?vuln=1" >/dev/null
ev 1
# "src":"203.0.113.9"   the attacker chose the IP in your logs, and no finding

# PATCHED: the real client is resolved and the spoof is flagged
curl -s --noproxy '*' -H 'X-Forwarded-For: 203.0.113.9' -X POST -H 'Content-Type: application/json' \
  -d '{"email":"maya@logsting.test","password":"sunshine"}' "http://localhost:8080/api/login" >/dev/null
ev 2
# the 3002 login shows "src":"172.30.0.1" (the real hop), plus
# {"class_uid":2004,...,"msg":"client supplied its own X-Forwarded-For before the WAF appended the real hop"}
```

Automated: `bash modules/09-logging-integrity/test.sh`

---

## A10 — Server-Side Request Forgery (SSRF)

The WAF blocks the IP target, always:

```
curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' -G \
  --data-urlencode 'url=http://169.254.169.254/latest/meta-data/' http://localhost:8080/api/import
# 403

waf 2
# the blocked import shows here with the CRS rule that caught the IP target
```

An internal hostname slips past the WAF to the app.

```
# VULNERABLE: no allowlist, the fetch proceeds
curl -s --noproxy '*' -G --data-urlencode 'url=http://metadata.internal.lab/latest/meta-data/' \
  "http://localhost:8080/api/import?vuln=1"
# {"ok":true,"host":"metadata.internal.lab","fetched":true}   SSRF succeeds
ev 1    # no finding

# PATCHED: the allowlist rejects it and logs it
curl -s --noproxy '*' -G --data-urlencode 'url=http://metadata.internal.lab/latest/meta-data/' \
  "http://localhost:8080/api/import"
# {"error":"host not on the import allowlist"}   (400)
ev 1
# {"class_uid":6003,"status_id":2,...,"msg":"import blocked (off allowlist)"}
```

Automated: `bash modules/10-ssrf/test.sh`

---

## The quick automated check

All ten at once, on the patched path, against the running stack:

```
make test
```

Each module runs its attack and benign traffic, slurps the OCSF log into a JSON
array, and hunts it with the module's Sigma rule via Chainsaw. The contract is
two-directional: the rule fires on the attack and stays silent on the benign.
Green across all ten means the detections hold both ways.
