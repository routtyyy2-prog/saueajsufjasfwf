// index.js - Secure Loader Backend (max protection)
require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = (globalThis.fetch) ? globalThis.fetch : (...args) => import('node-fetch').then(m => m.default(...args));

const app = express();
app.use(express.json({ limit: '128kb' }));

const PORT = process.env.PORT || 8080;
const REPO_RAW_URL = process.env.REPO_RAW_URL || "";
const SECRET_KEY = process.env.SECRET_KEY || "";
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || ""; // optional Slack/Discord webhook for alerts

if (!REPO_RAW_URL || !SECRET_KEY) {
  console.error("Missing REPO_RAW_URL or SECRET_KEY");
  process.exit(1);
}

// in-memory stores (suitable for single instance)
const tokens = new Map(); // token -> { hwid, ip, expires, used }
const nonces = new Map(); // nonceKey -> timestamp

// Cleanup job
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of tokens) if (v.expires <= now) tokens.delete(k);
  for (const [k, ts] of nonces) if (now - ts > 30000) nonces.delete(k);
}, 5000);

// Rate limit
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true, legacyHeaders: false
}));

// helpers
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

function verifyValveFingerprint(req) {
  const ua = (req.headers['user-agent']||"").toString();
  const acs = (req.headers['accept-charset']||"").toString();
  const aenc = (req.headers['accept-encoding']||"").toString();
  if (!ua.includes("Valve/Steam HTTP Client")) return false;
  if (!acs.toLowerCase().includes("iso-8859-1")) return false;
  if (!aenc.toLowerCase().includes("identity")) return false;
  return true;
}

function alertAdmin(payload) {
  if (!ALERT_WEBHOOK) return;
  try {
    fetch(ALERT_WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: payload }) });
  } catch (e) { console.warn("alert failed", e); }
}

function xorEncryptUtf8(text, key) {
  const buf = Buffer.from(text, 'utf8');
  const kb = Buffer.from(key, 'utf8');
  for (let i = 0; i < buf.length; i++) buf[i] ^= kb[i % kb.length];
  return buf.toString('base64');
}

// health
app.get('/health', (req, res) => {
  res.json({ ok: true, tokens: tokens.size, nonces: nonces.size, repo: !!REPO_RAW_URL });
});

// AUTH
app.post('/auth', async (req, res) => {
  try {
    const { hwid, timestamp, signature, nonce } = req.body || {};
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "";

    if (!verifyValveFingerprint(req)) {
      return res.status(403).json({ error: 'Invalid client' });
    }
    if (!hwid || !timestamp || !signature || !nonce) {
      return res.status(400).json({ error: 'Missing params' });
    }
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(Date.now() - ts) > 30000) {
      return res.status(403).json({ error: 'Timestamp invalid/expired' });
    }
    const nonceKey = `${timestamp}:${nonce}`;
    if (nonces.has(nonceKey)) {
      alertAdmin(`Replay attempt ${hwid.substring(0,8)} from ${ip}`);
      return res.status(403).json({ error: 'Replay detected' });
    }
    nonces.set(nonceKey, Date.now());

    const expected = md5(SECRET_KEY + hwid + timestamp + nonce);
    if (signature !== expected) {
      alertAdmin(`Invalid signature attempt ${hwid.substring(0,8)} from ${ip}`);
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // issue token
    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, { hwid, ip, expires: Date.now() + 10000, used: false });
    console.log(`Token issued ${token.substring(0,8)} for ${hwid.substring(0,8)} from ${ip}`);
    res.json({ token, expires_in: 10 });
  } catch (err) {
    console.error("auth error", err);
    res.status(500).json({ error: 'Internal' });
  }
});

// LOAD
app.post('/load', async (req, res) => {
  try {
    if (!verifyValveFingerprint(req)) return res.status(403).json({ error: 'Invalid client' });
    const { token } = req.body || {};
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "";

    if (!token) return res.status(400).json({ error: 'Missing token' });
    const t = tokens.get(token);
    if (!t) return res.status(403).json({ error: 'Invalid token' });
    if (t.used) return res.status(403).json({ error: 'Token already used' });
    if (Date.now() > t.expires) {
      tokens.delete(token);
      return res.status(403).json({ error: 'Token expired' });
    }
    if (t.ip !== ip) {
      alertAdmin(`IP mismatch token ${token.substring(0,8)} ${t.ip} != ${ip}`);
      return res.status(403).json({ error: 'IP mismatch' });
    }

    // fetch script from repo
    const headers = {};
    if (GITLAB_TOKEN) headers['PRIVATE-TOKEN'] = GITLAB_TOKEN;
    const r = await fetch(REPO_RAW_URL, { headers });
    if (!r.ok) {
      console.error("upstream fetch failed", r.status);
      return res.status(502).json({ error: 'Upstream' });
    }
    const script = await r.text();

    // encrypt script bytes with hwid
    const encrypted = xorEncryptUtf8(script, t.hwid);
    t.used = true;
    tokens.delete(token);
    console.log(`Script delivered to ${t.hwid.substring(0,8)} (${ip})`);
    res.type('text/plain').send(encrypted);
  } catch (err) {
    console.error("load error", err);
    res.status(500).json({ error: 'Internal' });
  }
});

// block GETs and other methods
app.get('/load', (req, res) => res.status(405).json({ error: 'Use POST' }));
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => console.log("Secure loader running on port", PORT));
