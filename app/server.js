// logsting reference service.
//
// Unlike a vulnerable app, this one is SECURE and well instrumented. Attacks run
// against it; the WAF in front and the OCSF security log here are what detect them.
// Each endpoint logs the security-relevant event (auth outcome, authz decision,
// suspicious input, sensitive action) with actor, source IP, outcome and a
// correlation id, and never logs secrets.
const crypto = require('crypto');
const express = require('express');
const ocsf = require('./lib/ocsf');
const log = require('./lib/log');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Trust only the WAF in front of us, named by its subnet on the compose network.
// With a named proxy (never `true`), Express resolves req.ip by walking the
// X-Forwarded-For chain right-to-left and skipping trusted hops, so the leftmost
// value a client can set is never believed. Set TRUSTED_PROXY to the real proxy
// in production; `true` would trust any client's XFF and is itself the bug.
const TRUSTED_PROXY = process.env.TRUSTED_PROXY || '172.30.0.0/24';
app.set('trust proxy', TRUSTED_PROXY);

const SECRET = process.env.APP_SECRET || 'dev-only-not-a-real-secret';
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// --- tiny fixture world (in-memory) ------------------------------------------
const users = {
  'maya@logsting.test': { id: 2, role: 'customer', pass: sha256('sunshine') },
  'leo@logsting.test': { id: 4, role: 'customer', pass: sha256('qwerty') },
  'admin@logsting.test': { id: 1, role: 'admin', pass: sha256('admin123'), isDefault: true },
};
const byId = Object.fromEntries(Object.entries(users).map(([email, u]) => [u.id, { email, ...u }]));
const orders = {
  1: { id: 1, user_id: 2, amount: 4999, status: 'paid' }, // maya
  2: { id: 2, user_id: 3, amount: 499, status: 'paid' }, // sam (no login, just an owner id)
};
const IMPORT_ALLOW = new Set(['cdn.logsting.test', 'assets.logsting.test']);
const SUSPICIOUS = /(\bunion\b.*\bselect\b|--|\bor\b\s+1\s*=\s*1|<script|onerror\s*=|\.\.\/|%2e%2e|\bexec\b\()/i;

// --- session helpers ---------------------------------------------------------
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token) {
  if (!token) return { payload: null, reason: 'none' };
  if (!token.includes('.')) return { payload: null, reason: 'malformed' };
  const [body, mac] = token.split('.');
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  // Constant-time compare. A plain === leaks timing and is itself an A02 failure.
  const a = Buffer.from(mac);
  const b = Buffer.from(good);
  const macOk = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!macOk) return { payload: null, reason: 'bad_signature' };
  try {
    return { payload: JSON.parse(Buffer.from(body, 'base64url').toString()), reason: 'ok' };
  } catch (e) {
    return { payload: null, reason: 'bad_payload' };
  }
}
function session(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : (req.headers['x-session'] || '');
  if (vuln(req)) {
    // VULNERABLE: trust the token without verifying its signature. A forged
    // identity is accepted and nothing is logged.
    const body = token.split('.')[0] || '';
    try { return JSON.parse(Buffer.from(body, 'base64url').toString()); } catch (e) { return null; }
  }
  const { payload, reason } = verify(token);
  // A02 — a token presented with a broken signature is a forgery or tamper
  // attempt. HMAC verification catches it; the WAF cannot, since it is a
  // valid-looking bearer token. Emit a Detection Finding. A missing or empty
  // token is just unauthenticated, not an attack, so it raises nothing.
  if (reason === 'bad_signature' || reason === 'bad_payload') {
    log.emit(
      ocsf.detectionFinding({
        title: 'tampered session token (signature verification failed)',
        severity_id: ocsf.SEV.HIGH,
        src_ip: req.clientIp,
        message: 'session token failed HMAC verification: possible forgery or tampering',
        finding: { reason },
      }),
      req.rid
    );
  }
  return payload;
}

// Lab-only switch. With ?vuln=1 (or header X-Lab-Vuln: 1) an endpoint runs its
// vulnerable path: the control is off and nothing is written to the security
// log, so a walkthrough can show the attack succeeding and invisible, then the
// same request patched and logged. Never ship this flag.
function vuln(req) {
  return req.query.vuln === '1' || req.headers['x-lab-vuln'] === '1';
}

// --- per-request context: correlation id + real client IP (behind the WAF) ---
app.use((req, res, next) => {
  req.rid = req.headers['x-request-id'] || crypto.randomUUID();
  res.setHeader('x-request-id', req.rid);
  const chain = (req.headers['x-forwarded-for'] || '')
    .split(',').map((s) => s.trim()).filter(Boolean);

  if (vuln(req)) {
    // VULNERABLE: trust the client-supplied X-Forwarded-For and do not detect
    // spoofing. The logged source becomes whatever the attacker put in the
    // header, poisoning every event that follows.
    req.clientIp = chain[0] || req.ip || req.socket.remoteAddress || '';
    return next();
  }

  // Express already walked the XFF chain using the trusted-proxy setting above.
  // req.ip is the first address the WAF did not vouch for: the real client.
  req.clientIp = req.ip || req.socket.remoteAddress || '';

  // Log-poisoning signal. Behind one proxy, a legitimate request carries exactly
  // one XFF entry: the client IP the WAF appended. More than one means the client
  // sent its own XFF to forge the source. CRS does not flag this; the app does,
  // because it knows its own proxy topology.
  if (chain.length > 1) {
    log.emit(
      ocsf.detectionFinding({
        title: 'spoofed X-Forwarded-For (log poisoning attempt)',
        severity_id: ocsf.SEV.HIGH,
        src_ip: req.clientIp,
        message: 'client supplied its own X-Forwarded-For before the WAF appended the real hop',
        finding: { xff_chain: chain, resolved_client: req.clientIp, claimed: chain[0] },
      }),
      req.rid
    );
  }
  next();
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

// A07 — in-memory failure tracker for brute force / credential stuffing.
// Brute force is a rate, not a single event, so the app counts failures per
// source in a sliding window and raises a finding when a burst crosses it.
const AUTH_WINDOW_MS = 60000;
const AUTH_FAIL_THRESHOLD = 5;
const authFailures = new Map(); // src -> [failure timestamps within the window]

// A07 — authentication outcomes. Never log the password. Downstream detection
// counts failures per actor/IP to catch brute force and spraying.
app.post('/api/login', (req, res) => {
  const email = (req.body.email || '').toLowerCase();
  const u = users[email];
  const ok = u && u.pass === sha256(req.body.password || '');
  log.emit(
    ocsf.authentication({
      status_id: ok ? ocsf.STATUS.SUCCESS : ocsf.STATUS.FAILURE,
      user: email,
      src_ip: req.clientIp,
      severity_id: ok ? ocsf.SEV.INFO : ocsf.SEV.LOW,
      message: ok ? 'login success' : 'login failure',
    }),
    req.rid
  );
  // A07 — count failures per source; raise a finding when a burst crosses the
  // threshold. A single failure is noise; a rapid run from one source is not.
  if (!ok) {
    const key = req.clientIp || 'unknown';
    const now = Date.now();
    const recent = (authFailures.get(key) || []).filter((t) => now - t < AUTH_WINDOW_MS);
    recent.push(now);
    authFailures.set(key, recent);
    if (recent.length >= AUTH_FAIL_THRESHOLD && !vuln(req)) {
      // VULNERABLE (vuln=1): the burst is never flagged.
      log.emit(
        ocsf.detectionFinding({
          title: 'authentication brute force / credential stuffing',
          severity_id: ocsf.SEV.HIGH,
          src_ip: req.clientIp,
          message: 'repeated authentication failures from one source exceeded threshold',
          finding: { source: key, failures: recent.length, window_s: AUTH_WINDOW_MS / 1000 },
        }),
        req.rid
      );
    }
  } else {
    authFailures.delete(req.clientIp || 'unknown'); // a success clears the streak
  }
  // A05 — a seeded default account is still enabled. Its use is a
  // misconfiguration the WAF cannot see; the app knows which accounts are
  // defaults and should never be authenticating in production.
  if (u && u.isDefault && !vuln(req)) {
    // VULNERABLE (vuln=1): default-account use is not flagged.
    log.emit(
      ocsf.detectionFinding({
        title: 'default credential in use (security misconfiguration)',
        severity_id: ocsf.SEV.HIGH,
        user: email,
        src_ip: req.clientIp,
        message: ok
          ? 'login with a known default credential succeeded'
          : 'login attempt against a known default credential account',
        finding: { account: email, succeeded: ok },
      }),
      req.rid
    );
  }
  if (!ok) return res.status(401).json({ error: 'invalid email or password' });
  return res.json({ token: sign({ sub: u.id, email, role: u.role }) });
});

// A01 — read an order. Authorization decision is logged either way, so a BOLA
// probe leaves a trail even though it is denied.
app.get('/api/orders/:id', (req, res) => {
  const s = session(req);
  if (!s) return res.status(401).json({ error: 'log in first' });
  const order = orders[req.params.id];
  if (vuln(req)) {
    // VULNERABLE: no ownership check, no logging. The attack reads any order and
    // leaves no trace.
    return order ? res.json({ order }) : res.status(404).json({ error: 'no such order' });
  }
  const allowed = !!order && order.user_id === Number(s.sub);
  log.emit(
    ocsf.webResourceAccess({
      status_id: allowed ? ocsf.STATUS.SUCCESS : ocsf.STATUS.FAILURE,
      user: s.email,
      src_ip: req.clientIp,
      resource: 'order/' + req.params.id,
      decision: allowed ? 'allow' : 'deny',
      severity_id: allowed ? ocsf.SEV.INFO : ocsf.SEV.MEDIUM,
      message: allowed ? 'order read' : 'order read denied (not owner)',
    }),
    req.rid
  );
  if (!allowed) return res.status(404).json({ error: 'no such order' });
  return res.json({ order });
});

// A01 — privileged access. Admin hits are always logged.
app.get('/admin', (req, res) => {
  const s = session(req);
  const allowed = !!s && s.role === 'admin';
  log.emit(
    ocsf.webResourceAccess({
      status_id: allowed ? ocsf.STATUS.SUCCESS : ocsf.STATUS.FAILURE,
      user: s ? s.email : undefined,
      src_ip: req.clientIp,
      resource: 'admin',
      decision: allowed ? 'allow' : 'deny',
      severity_id: allowed ? ocsf.SEV.LOW : ocsf.SEV.HIGH,
      message: allowed ? 'admin access' : 'admin access denied',
    }),
    req.rid
  );
  if (!allowed) return res.status(403).json({ error: 'forbidden' });
  return res.json({ users: Object.values(byId).map((u) => ({ id: u.id, email: u.email, role: u.role })) });
});

// A03 — search is parameterized and safe. If an attack signature still reaches
// the app, that means it got past the WAF, so we raise a Detection Finding.
app.get('/api/search', (req, res) => {
  const q = req.query.q || '';
  // The app also honors an advanced-filter header. The WAF inspects query args
  // and bodies, but not arbitrary custom headers, so this is a vector it does
  // not see. Input the WAF never parsed still reaches the sink, so the app must
  // check it here, at the decision point, where it knows the input's context.
  const hdr = req.headers['x-search-filter'] || '';
  if (vuln(req)) return res.json({ q, count: 0, rows: [] }); // VULNERABLE: no input inspection, no logging
  for (const [param, value] of [['q', q], ['header:x-search-filter', hdr]]) {
    if (value && SUSPICIOUS.test(value)) {
      log.emit(
        ocsf.detectionFinding({
          title: 'suspicious input reached application',
          severity_id: ocsf.SEV.HIGH,
          src_ip: req.clientIp,
          message: 'request matched an attack signature after the WAF',
          finding: { param, value: String(value).slice(0, 200) },
        }),
        req.rid
      );
    }
  }
  // parameterized query would run here; fixtures return nothing interesting
  return res.json({ q, count: 0, rows: [] });
});

// A04 — insecure design / business logic. Price is server-side; quantity is
// bounded. A negative or absurd quantity, or a client-supplied price, is a
// well-formed HTTP request the WAF cannot judge. Only the app knows the rule.
const CATALOG = { 'sku-blue-shoe': 4999, 'sku-red-hat': 1999 }; // cents, server-side
const MAX_QTY = 10;
app.post('/api/checkout', (req, res) => {
  const s = session(req);
  if (!s) return res.status(401).json({ error: 'auth required' });
  const sku = String(req.body.sku || '');
  const qty = Number(req.body.qty);
  const price = CATALOG[sku];
  if (vuln(req)) {
    // VULNERABLE: no business-rule check, no logging. A negative quantity yields
    // a negative total (refund abuse).
    return res.json({ sku, qty, total: (price || 0) * qty });
  }
  const qtyOk = Number.isInteger(qty) && qty >= 1 && qty <= MAX_QTY;
  const clientPrice = req.body.unit_price !== undefined; // price tampering attempt
  const reason = price === undefined ? 'unknown_sku'
    : !qtyOk ? 'invalid_quantity'
    : clientPrice ? 'client_supplied_price'
    : null;
  log.emit(
    ocsf.apiActivity({
      status_id: reason ? ocsf.STATUS.FAILURE : ocsf.STATUS.SUCCESS,
      src_ip: req.clientIp,
      user: s.email,
      operation: 'checkout',
      severity_id: reason ? ocsf.SEV.HIGH : ocsf.SEV.INFO,
      message: reason ? 'checkout rejected: business rule violation' : 'checkout ok',
      extra: { sku, qty: req.body.qty, unit_price: req.body.unit_price, reason },
    }),
    req.rid
  );
  if (reason) return res.status(400).json({ error: 'invalid checkout' });
  return res.json({ sku, qty, total: price * qty });
});

// A08 — software/data integrity. An update (a rules pack) is trusted only when
// its content matches the pinned SHA-256 for that release. A digest mismatch
// means the payload was tampered with or is unsigned/untrusted. The WAF cannot
// know the expected hash; integrity verification lives with the app.
const PLUGIN_PIN = {
  'rules-pack-v1': '4b4e78c418a32841d9f41bcf9d5fcb2111f89dd1fad5c9da06db86aa7ec037e7',
};
app.post('/api/plugin', (req, res) => {
  const name = String(req.body.name || '');
  const payload = String(req.body.payload || '');
  const expected = PLUGIN_PIN[name];
  const actual = crypto.createHash('sha256').update(payload).digest('hex');
  if (vuln(req)) {
    // VULNERABLE: apply the update without verifying its integrity, no logging.
    return res.json({ ok: true, name, applied: true });
  }
  const ok = expected !== undefined && actual === expected;
  if (!ok) {
    log.emit(
      ocsf.detectionFinding({
        title: 'data integrity verification failed (untrusted update)',
        severity_id: ocsf.SEV.HIGH,
        src_ip: req.clientIp,
        message: 'update payload failed integrity check: digest mismatch',
        finding: { name, expected: expected || null, actual },
      }),
      req.rid
    );
    return res.status(409).json({ error: 'integrity check failed' });
  }
  return res.json({ ok: true, name, applied: true });
});

// A10 — server-side import with an allowlist. Off-allowlist targets are blocked
// and logged.
app.get('/api/import', (req, res) => {
  const url = req.query.url || '';
  let host = '';
  try {
    host = new URL(url).hostname;
  } catch (e) {
    host = '';
  }
  if (vuln(req)) {
    // VULNERABLE: fetch any host, no allowlist, no logging. SSRF succeeds.
    return res.json({ ok: true, host, fetched: true });
  }
  const allowed = IMPORT_ALLOW.has(host);
  log.emit(
    ocsf.apiActivity({
      activity_id: 2,
      status_id: allowed ? ocsf.STATUS.SUCCESS : ocsf.STATUS.FAILURE,
      src_ip: req.clientIp,
      operation: 'import',
      severity_id: allowed ? ocsf.SEV.INFO : ocsf.SEV.HIGH,
      message: allowed ? 'import fetch' : 'import blocked (off allowlist)',
      extra: { url: String(url).slice(0, 200), host },
    }),
    req.rid
  );
  if (!allowed) return res.status(400).json({ error: 'host not on the import allowlist' });
  return res.json({ ok: true, host });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => process.stdout.write('logsting listening on ' + port + '\n'));
