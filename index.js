// index.js - Secure Loader Backend (max protection)
// Env required: REPO_RAW_URL, SECRET_KEY, SECRET_CHECKSUM (md5(SECRET_KEY)), GITLAB_TOKEN (opt), ALERT_WEBHOOK (opt)

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = globalThis.fetch ? globalThis.fetch : (...args) => import('node-fetch').then(m => m.default(...args));

const app = express();
app.use(express.json({ limit: '128kb' }));

const PORT = process.env.PORT || 8080;
const REPO_RAW_URL = process.env.REPO_RAW_URL || "";
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = process.env.SECRET_CHECKSUM || ""; // md5(SECRET_KEY)
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || "";

if (!REPO_RAW_URL || !SECRET_KEY || !SECRET_CHECKSUM) {
  console.error("Missing REPO_RAW_URL or SECRET_KEY or SECRET_CHECKSUM in .env");
  process.exit(1);
}

// in-memory stores
const tokens = new Map(); // token -> { hwid, ip, expires, used }
const nonces = new Map(); // nonceKey -> ts

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of tokens) if (v.expires <= now) tokens.delete(k);
  for (const [k, ts] of nonces) if (now - ts > 30000) nonces.delete(k);
}, 5000);

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
}));

function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function hmac_sha256_hex(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

// verify fingerprint: accept Valve headers OR custom X-Client-Fp
function verifyFingerprint(req, hwid, nonce) {
  const ua = (req.headers['user-agent'] || "").toString();
  const acs = (req.headers['accept-charset'] || "").toString();
  const aenc = (req.headers['accept-encoding'] || "").toString();
  const xfp = (req.headers['x-client-fp'] || "").toString();

  const valveOk = ua.includes("Valve/Steam HTTP Client") && acs.toLowerCase().includes("iso-8859-1") && aenc.toLowerCase().includes("identity");
  if (valveOk) return true;

  // else accept custom fingerprint computed as md5(hwid:nonce:SECRET_CHECKSUM)
  if (xfp && xfp === md5(hwid + ":" + nonce + ":" + SECRET_CHECKSUM)) return true;

  // fallback — reject but log
  console.warn("Fingerprint mismatch", { ua, acs, aenc, xfp });
  return false;
}

async function alertAdmin(text) {
  if (!ALERT_WEBHOOK) return;
  try {
    await fetch(ALERT_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
  } catch (e) { console.warn("alert failed", e); }
}

function xorEncryptUtf8(text, key) {
  const buf = Buffer.from(text, 'utf8');
  const kb = Buffer.from(key, 'utf8');
  for (let i = 0; i < buf.length; i++) buf[i] ^= kb[i % kb.length];
  return buf.toString('base64');
}

app.get('/health', (req, res) => {
  res.json({ ok: true, tokens: tokens.size, nonces: nonces.size, repo: !!REPO_RAW_URL });
});

// AUTH
app.post('/auth', async (req, res) => {
  try {
    const { hwid, timestamp, nonce, signature, client_fp } = req.body || {};
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || "").toString();

    if (!hwid || !timestamp || !nonce || !signature) return res.status(400).json({ error: 'Missing params' });

    // timestamp + window 30s
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(Date.now() - ts) > 30000) {
      await alertAdmin(`Expired timestamp from ${ip} hwid:${hwid ? hwid.substring(0,8) : "-"}`);
      return res.status(403).json({ error: 'Timestamp invalid/expired' });
    }

    // anti-replay nonce
    const nonceKey = `${timestamp}:${nonce}`;
    if (nonces.has(nonceKey)) {
      await alertAdmin(`Replay attempt ${hwid.substring(0,8)} ip:${ip}`);
      return res.status(403).json({ error: 'Replay detected' });
    }
    nonces.set(nonceKey, Date.now());

    // fingerprint check (server-side)
    if (!verifyFingerprint(req, hwid, nonce)) {
      await alertAdmin(`Fingerprint failed ${hwid.substring(0,8)} ip:${ip}`);
      return res.status(403).json({ error: 'Invalid client fingerprint' });
    }

    // expected signature: MD5(SECRET_KEY + hwid + timestamp + nonce)
    const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
    if (signature !== expectedSig) {
      await alertAdmin(`Invalid signature ${hwid.substring(0,8)} ip:${ip}`);
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // issue token one-time
    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, { hwid, ip, expires: Date.now() + 10000, used: false });
    console.log(`Token issued ${token.substring(0,8)} for ${hwid.substring(0,8)} ip:${ip}`);
    return res.json({ token, expires_in: 10 });
  } catch (err) {
    console.error("AUTH ERROR", err);
    return res.status(500).json({ error: 'Internal' });
  }
});

// LOAD
app.post('/load', async (req, res) => {
  try {
    const { token } = req.body || {};
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || "").toString();
    if (!token) return res.status(400).json({ error: 'Missing token' });
    const t = tokens.get(token);
    if (!t) return res.status(403).json({ error: 'Invalid token' });
    if (t.used) return res.status(403).json({ error: 'Token already used' });
    if (Date.now() > t.expires) { tokens.delete(token); return res.status(403).json({ error: 'Token expired' }); }

    // IP binding
    if (t.ip !== ip) {
      await alertAdmin(`IP mismatch for token ${token.substring(0,8)} expected ${t.ip} got ${ip}`);
      return res.status(403).json({ error: 'IP mismatch' });
    }

    // fetch raw script
    const headers = {};
    if (GITLAB_TOKEN) headers['PRIVATE-TOKEN'] = GITLAB_TOKEN;
    const r = await fetch(REPO_RAW_URL, { headers });
    if (!r.ok) {
      console.error("Upstream fetch failed", r.status);
      return res.status(502).json({ error: 'Upstream' });
    }
    const script = await r.text();

    // encrypt bytes with hwid
    const encrypted = xorEncryptUtf8(script, t.hwid);
    t.used = true; tokens.delete(token);
    console.log(`Script delivered to ${t.hwid.substring(0,8)} ip:${ip}`);
    res.type('text/plain').send(encrypted);
  } catch (err) {
    console.error("LOAD ERROR", err);
    return res.status(500).json({ error: 'Internal' });
  }
});

// disallow GETs on these endpoints
app.get('/auth', (_, res) => res.status(405).json({ error: 'POST only' }));
app.get('/load', (_, res) => res.status(405).json({ error: 'POST only' }));
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => console.log(`Secure loader running on port ${PORT}`));
