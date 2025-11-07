// index.js - Ultra Secure Loader Backend
// Protection: replay attacks, IP spoofing, token reuse, timing, bruteforce, MITM, proxy, browser

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

let _fetch = globalThis.fetch;
if (!_fetch) {
  _fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
}
const fetch = (...args) => _fetch(...args);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));

// === CONFIGURATION ===
const PORT = process.env.PORT || 8080;
const REPO_RAW_URL = process.env.REPO_RAW_URL || "";
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || "";

if (!REPO_RAW_URL || !SECRET_KEY) {
  console.error("❌ Missing required env: REPO_RAW_URL or SECRET_KEY");
  process.exit(1);
}

// === SECURITY STORES ===
const tokens = new Map();
const nonces = new Map();
const failedAttempts = new Map();
const rateLimitStore = new Map();

// periodic cleanup
setInterval(() => {
  const now = Date.now();
  for (const [t, d] of tokens.entries()) if (now > d.expires) tokens.delete(t);
  for (const [n, ts] of nonces.entries()) if (now - ts > 30000) nonces.delete(n);
  for (const [ip, d] of failedAttempts.entries()) if (now - d.lastAttempt > 300000) failedAttempts.delete(ip);
  for (const [hwid, d] of rateLimitStore.entries()) if (now > d.resetTime) rateLimitStore.delete(hwid);
}, 5000);

// === GLOBAL RATE LIMIT ===
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: 'Too many requests' }
});
app.use(globalLimiter);

// === UTILS ===
function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown')
    .split(',')[0].trim();
}

function constantTimeCompare(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// XOR encrypt text
function xorEncrypt(txt, key) {
  const tb = Buffer.from(txt, 'utf8');
  const kb = Buffer.from(key, 'utf8');
  const res = Buffer.alloc(tb.length);
  for (let i = 0; i < tb.length; i++) res[i] = tb[i] ^ kb[i % kb.length];
  return res.toString('base64');
}

// Discord alert
async function sendAlert(message, level = 'warning') {
  if (!ALERT_WEBHOOK) return;
  const color = level === 'critical' ? 15158332 : (level === 'warning' ? 16776960 : 3447003);
  try {
    const resp = await fetch(ALERT_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `🔒 Loader Security Alert [${level.toUpperCase()}]`,
          description: message,
          color,
          timestamp: new Date().toISOString()
        }]
      })
    });
    if (!resp.ok) console.error("Alert webhook resp:", resp.status);
  } catch (e) { console.error("Alert webhook failed:", e.message); }
}

// helpers for alerts
function looksLikeBrowserUA(ua) {
  if (!ua) return false;
  ua = ua.toLowerCase();
  return ua.includes("mozilla") || ua.includes("chrome") || ua.includes("safari") ||
         ua.includes("edge") || ua.includes("firefox") || ua.includes("brave");
}
function looksLikeProxyHeaders(req) {
  const h = req.headers;
  return !!(h['via'] || h['forwarded'] || h['proxy-connection'] || h['x-proxy-id']);
}
function sanitizeHeaders(req) {
  const keep = ['user-agent','accept','accept-encoding','accept-language','via','x-forwarded-for','x-client-fp','x-signature'];
  const out = {};
  for (const k of keep) if (req.headers[k]) out[k] = String(req.headers[k]).slice(0,200);
  return out;
}
function sanitizeBody(b) {
  const s = typeof b === 'string' ? b : JSON.stringify(b);
  return s.replace(/"token"\s*:\s*"[^"]*"/gi, '"token":"<redacted>"')
          .replace(/"signature"\s*:\s*"[^"]*"/gi, '"signature":"<redacted>"')
          .slice(0,500);
}

// === RATE LIMITING PER HWID ===
function checkHwidRateLimit(hwid) {
  const now = Date.now();
  const limit = rateLimitStore.get(hwid);
  if (!limit) { rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 }); return true; }
  if (now > limit.resetTime) { rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 }); return true; }
  if (limit.count >= 4) return false;
  limit.count++; return true;
}

// === VERIFY CLIENT FP ===
function verifyClientFingerprint(req, hwid, nonce) {
  const got = (req.headers['x-client-fp'] || '').toString();
  const expected = md5(`${hwid}:${nonce}:${SECRET_CHECKSUM}`);
  if (constantTimeCompare(got, expected)) return true;
  console.warn("FP mismatch", { got: got.slice(0,8), exp: expected.slice(0,8), hwid: (hwid||'').slice(0,8) });
  return false;
}

function logSuspiciousActivity(ip, hwid, reason) {
  const k = ip;
  const a = failedAttempts.get(k) || { count: 0, lastAttempt: 0 };
  a.count++; a.lastAttempt = Date.now(); failedAttempts.set(k, a);
  console.warn(`⚠️ Suspicious: ${reason} | IP: ${ip} | HWID: ${hwid?.slice(0,8)} | #${a.count}`);
  if (a.count >= 3) sendAlert(`**Possible attack detected!**\nIP: \`${ip}\`\nHWID: \`${hwid?.slice(0,12)}\`\nReason: ${reason}\nAttempts: ${a.count}`, 'critical');
}

// === HEALTH ===
app.get('/health', (req, res) => res.json({ status: 'online', tokens: tokens.size, nonces: nonces.size }));

// === AUTH ===
app.post('/auth', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  const { hwid, timestamp, nonce, signature } = req.body || {};

  // Anti-browser/proxy
  if (looksLikeBrowserUA(ua) || looksLikeProxyHeaders(req)) {
    await sendAlert(`**Browser/proxy access**\nIP: \`${ip}\`\nUA: \`${ua}\`\nHeaders: \`${JSON.stringify(sanitizeHeaders(req))}\``, 'critical');
    return res.status(403).json({ error: 'Forbidden client type' });
  }

  // Verify X-Signature (optional)
  const gotXSig = (req.headers['x-signature'] || '').toString();
  if (gotXSig) {
    const bodyString = JSON.stringify({ hwid, timestamp, nonce, signature });
    const expectedXSig = crypto.createHmac('sha256', SECRET_KEY).update(bodyString).digest('hex');
    if (!constantTimeCompare(gotXSig, expectedXSig)) {
      await sendAlert(`**Bad X-Signature**\nIP: \`${ip}\`\nHWID: \`${(hwid||'').slice(0,12)}\`\nHeaders: \`${JSON.stringify(sanitizeHeaders(req))}\``, 'critical');
      return res.status(403).json({ error: 'Bad X-Signature' });
    }
  } else {
    await sendAlert(`**Missing X-Signature**\nIP: \`${ip}\`\nHWID: \`${(hwid||'').slice(0,12)}\`\nUA: \`${ua}\``, 'warning');
  }

  try {
    if (!hwid || !timestamp || !nonce || !signature) {
      logSuspiciousActivity(ip, hwid, 'Missing params');
      return res.status(400).json({ error: 'Missing parameters' });
    }

    if (!checkHwidRateLimit(hwid)) {
      logSuspiciousActivity(ip, hwid, 'HWID rate limit exceeded');
      return res.status(429).json({ error: 'Too many requests' });
    }

    const reqTime = parseInt(timestamp);
    const now = Date.now();
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 30000) {
      logSuspiciousActivity(ip, hwid, 'Timestamp invalid');
      return res.status(403).json({ error: 'Expired timestamp' });
    }

    const nonceKey = `${hwid}:${timestamp}:${nonce}`;
    if (nonces.has(nonceKey)) {
      logSuspiciousActivity(ip, hwid, 'Replay detected');
      await sendAlert(`**Replay attack**\nIP: \`${ip}\`\nHWID: \`${hwid?.slice(0,12)}\``, 'critical');
      return res.status(403).json({ error: 'Replay' });
    }
    nonces.set(nonceKey, now);

    if (!verifyClientFingerprint(req, hwid, nonce)) {
      logSuspiciousActivity(ip, hwid, 'Invalid fingerprint');
      await sendAlert(`**Invalid fingerprint**\nIP: \`${ip}\`\nHWID: \`${hwid?.slice(0,12)}\`\nHeaders: \`${JSON.stringify(sanitizeHeaders(req))}\`\nBody: \`${sanitizeBody(req.body)}\``, 'critical');
      return res.status(403).json({ error: 'Bad fingerprint' });
    }

    const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
    if (!constantTimeCompare(signature, expectedSig)) {
      logSuspiciousActivity(ip, hwid, 'Invalid signature');
      return res.status(403).json({ error: 'Bad signature' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const data = { hwid, ip, ua, expires: now + 5000, used: false, created: now };
    tokens.set(token, data);
    console.log(`✅ Token issued: ${token.slice(0,8)}... | HWID: ${hwid.slice(0,8)} | IP: ${ip}`);

    res.json({ token, expires_in: 5 });
  } catch (e) {
    console.error("❌ AUTH ERROR:", e);
    logSuspiciousActivity(ip, hwid, 'Server auth error');
    res.status(500).json({ error: 'Internal error' });
  }
});

// === LOAD ===
app.post('/load', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  const { token } = req.body || {};
  if (!token) {
    logSuspiciousActivity(ip, null, 'Missing token');
    return res.status(400).json({ error: 'Missing token' });
  }

  const tdata = tokens.get(token);
  if (!tdata) {
    logSuspiciousActivity(ip, null, 'Invalid token');
    return res.status(403).json({ error: 'Bad token' });
  }

  if (Date.now() > tdata.expires) {
    tokens.delete(token);
    logSuspiciousActivity(ip, tdata.hwid, 'Token expired');
    return res.status(403).json({ error: 'Token expired' });
  }

  if (tdata.used) {
    logSuspiciousActivity(ip, tdata.hwid, 'Token reuse');
    await sendAlert(`**Token reuse**\nIP: \`${ip}\`\nHWID: \`${tdata.hwid.slice(0,12)}\``, 'critical');
    return res.status(403).json({ error: 'Token used' });
  }

  if (tdata.ip !== ip) {
    logSuspiciousActivity(ip, tdata.hwid, `IP mismatch (expected ${tdata.ip})`);
    await sendAlert(`**Token stolen**\nExpected IP: \`${tdata.ip}\`\nActual: \`${ip}\`\nHWID: \`${tdata.hwid.slice(0,12)}\``, 'critical');
    return res.status(403).json({ error: 'IP mismatch' });
  }

  tdata.used = true;

  try {
    const headers = GITLAB_TOKEN ? { 'PRIVATE-TOKEN': GITLAB_TOKEN } : {};
    const resp = await fetch(REPO_RAW_URL, { headers });
    if (!resp.ok) {
      console.error("❌ GitLab fetch failed", resp.status);
      return res.status(502).json({ error: 'Upstream error' });
    }
    const script = await resp.text();
    const enc = xorEncrypt(script, tdata.hwid);
    tokens.delete(token);
    console.log(`✅ Script delivered: ${tdata.hwid.slice(0,8)} | ${ip} | ${enc.length}b`);
    res.type('text/plain').send(enc);
  } catch (e) {
    console.error("❌ LOAD ERROR:", e);
    logSuspiciousActivity(ip, null, 'Load error');
    res.status(500).json({ error: 'Internal error' });
  }
});

// === BLOCK GET REQUESTS ===
app.get('/auth', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,'GET /auth'); res.status(405).json({error:'POST only'}); });
app.get('/load', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,'GET /load'); res.status(405).json({error:'POST only'}); });
app.all('/get_main', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,'Deprecated /get_main'); res.status(410).json({error:'Deprecated'}); });
app.use((req,res)=>res.status(404).json({error:'Not found'}));

// === STARTUP ===
app.listen(PORT, () => {
  console.log(`\n🔒 ============================================`);
  console.log(`   SECURE LOADER PROXY - ULTRA PROTECTION`);
  console.log(`   ============================================`);
  console.log(`   ✅ Running on port ${PORT}`);
  console.log(`   ✅ Repo linked: ${!!REPO_RAW_URL}`);
  console.log(`   ✅ Alerts: ${!!ALERT_WEBHOOK}`);
  console.log(`   🔐 Features: IP binding, replay, HWID+IP limit, FP, HMAC sig, XOR enc`);
  console.log(`============================================\n`);
});
