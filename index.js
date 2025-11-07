// index.js - ULTRA SECURE (Anti-MITM, Certificate Pinning, Auto-ban)
// Защита: Fiddler, Charles, mitmproxy, replay, script dump

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

// === CONFIG ===
const PORT = process.env.PORT || 8080;
const REPO_RAW_URL = process.env.REPO_RAW_URL || "";
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const GITLAB_PROJECT_ID = process.env.GITLAB_PROJECT_ID || "";
const GITLAB_BRANCH = process.env.GITLAB_BRANCH || "main";
const KEYS_FILE = "keys.json";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || "";

// === ANTI-MITM: Expected certificate fingerprint (SHA256 of Railway cert) ===
// Client will verify this to detect proxy interception
const EXPECTED_CERT_FINGERPRINT = process.env.CERT_FINGERPRINT || "RAILWAY_CERT_SHA256_HERE";

if (!REPO_RAW_URL || !SECRET_KEY || !GITLAB_TOKEN || !GITLAB_PROJECT_ID) {
  console.error("❌ Missing env vars");
  process.exit(1);
}

// === STORES ===
const tokens = new Map();
const nonces = new Map();
const failedAttempts = new Map();
const rateLimitStore = new Map();
const bannedHwids = new Set();
const suspiciousIPs = new Map(); // Track MITM attempts
const keysCache = { data: null, lastFetch: 0, ttl: 10000 };

setInterval(() => {
  const now = Date.now();
  for (const [t, d] of tokens.entries()) if (now > d.expires) tokens.delete(t);
  for (const [n, ts] of nonces.entries()) if (now - ts > 30000) nonces.delete(n);
  for (const [ip, d] of failedAttempts.entries()) if (now - d.lastAttempt > 300000) failedAttempts.delete(ip);
  for (const [hwid, d] of rateLimitStore.entries()) if (now > d.resetTime) rateLimitStore.delete(hwid);
  for (const [ip, d] of suspiciousIPs.entries()) if (now - d.lastSeen > 600000) suspiciousIPs.delete(ip);
}, 5000);

// === GITLAB ===
function gitlabHeaders() {
  return {
    'PRIVATE-TOKEN': GITLAB_TOKEN,
    'Content-Type': 'application/json'
  };
}

async function fetchGitLabKeys() {
  const now = Date.now();
  if (keysCache.data && (now - keysCache.lastFetch) < keysCache.ttl) {
    return keysCache.data;
  }

  const encodedPath = KEYS_FILE.replace(/([^a-zA-Z0-9-._~])/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  const url = `https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/repository/files/${encodedPath}/raw?ref=${GITLAB_BRANCH}`;

  try {
    const res = await fetch(url, { headers: gitlabHeaders() });
    if (!res.ok) {
      console.error("❌ GitLab fetch failed:", res.status);
      return null;
    }
    const text = await res.text();
    const data = JSON.parse(text);
    keysCache.data = data;
    keysCache.lastFetch = now;
    return data;
  } catch (e) {
    console.error("❌ GitLab error:", e.message);
    return null;
  }
}

async function banKeyInGitLab(keyName, reason, hwid, ip) {
  const data = await fetchGitLabKeys();
  if (!data || !data.keys || !data.keys[keyName]) {
    console.warn("⚠️ Key not found for ban:", keyName);
    return false;
  }

  data.keys[keyName].banned = true;
  data.keys[keyName].ban_reason = reason;
  data.keys[keyName].banned_at = Math.floor(Date.now() / 1000);
  data.keys[keyName].banned_hwid = hwid;
  data.keys[keyName].banned_ip = ip;

  const encodedPath = KEYS_FILE.replace(/([^a-zA-Z0-9-._~])/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  const url = `https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/repository/files/${encodedPath}`;

  try {
    const res = await fetch(url, {
      method: 'PUT',
      headers: gitlabHeaders(),
      body: JSON.stringify({
        branch: GITLAB_BRANCH,
        content: JSON.stringify(data, null, 2),
        commit_message: `[AUTO-BAN] ${keyName} - ${reason} | HWID: ${hwid?.slice(0,12)} | IP: ${ip}`
      })
    });
    if (res.ok) {
      console.log(`✅ Key banned: ${keyName} (${reason})`);
      keysCache.data = null;
      return true;
    } else {
      console.error("❌ GitLab ban failed:", res.status);
      return false;
    }
  } catch (e) {
    console.error("❌ GitLab ban error:", e.message);
    return false;
  }
}

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

// ENHANCED XOR with randomized padding
function xorEncrypt(txt, key) {
  const padding = crypto.randomBytes(16).toString('hex'); // 32 chars
  const fullText = padding + txt + padding;
  
  const tb = Buffer.from(fullText, 'utf8');
  const kb = Buffer.from(key, 'utf8');
  const res = Buffer.alloc(tb.length);
  
  for (let i = 0; i < tb.length; i++) {
    res[i] = tb[i] ^ kb[i % kb.length] ^ (i & 0xFF); // Extra XOR with position
  }
  
  return res.toString('base64');
}

async function sendAlert(message, level = 'warning') {
  if (!ALERT_WEBHOOK) return;
  const color = level === 'critical' ? 15158332 : (level === 'warning' ? 16776960 : 3447003);
  try {
    await fetch(ALERT_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `🔒 Security Alert [${level.toUpperCase()}]`,
          description: message,
          color,
          timestamp: new Date().toISOString(),
          footer: { text: 'Ultra Secure Loader' }
        }]
      })
    });
  } catch (e) { console.error("Alert error:", e.message); }
}

function detectMITM(req) {
  const indicators = [];
  
  // Check for proxy headers
  if (req.headers['via']) indicators.push('Via header');
  if (req.headers['forwarded']) indicators.push('Forwarded header');
  if (req.headers['proxy-connection']) indicators.push('Proxy-Connection');
  if (req.headers['x-proxy-id']) indicators.push('X-Proxy-ID');
  
  // Check for modified Accept headers (Fiddler signature)
  const accept = (req.headers['accept'] || '').toLowerCase();
  if (accept.includes('fiddler') || accept.includes('charles')) {
    indicators.push('Proxy tool detected in Accept');
  }
  
  // Check Connection header (proxies often modify)
  const conn = (req.headers['connection'] || '').toLowerCase();
  if (conn.includes('proxy')) indicators.push('Proxy in Connection');
  
  // Check for missing or weird User-Agent
  const ua = req.headers['user-agent'] || '';
  if (!ua || ua.length < 20) indicators.push('Suspicious UA');
  
  // Check for TLS interception markers
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  if (proto !== 'https') indicators.push('Non-HTTPS');
  
  return indicators;
}

function checkHwidRateLimit(hwid) {
  const now = Date.now();
  const limit = rateLimitStore.get(hwid);
  if (!limit) { rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 }); return true; }
  if (now > limit.resetTime) { rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 }); return true; }
  if (limit.count >= 3) return false; // Снижено до 3
  limit.count++; return true;
}

function verifyClientFingerprint(req, hwid, nonce) {
  const got = (req.headers['x-client-fp'] || '').toString();
  const expected = md5(`${hwid}:${nonce}:${SECRET_CHECKSUM}`);
  return constantTimeCompare(got, expected);
}

async function logSuspiciousActivity(ip, hwid, key, reason, autoban = false) {
  const k = ip;
  const a = failedAttempts.get(k) || { count: 0, lastAttempt: 0 };
  a.count++; a.lastAttempt = Date.now(); failedAttempts.set(k, a);
  
  console.warn(`⚠️ SUSPICIOUS: ${reason} | IP: ${ip} | HWID: ${hwid?.slice(0,8)} | Key: ${key?.slice(0,8)} | #${a.count}`);
  
  // Auto-ban logic
  if (autoban || a.count >= 3) {
    if (hwid) bannedHwids.add(hwid);
    if (key) {
      await banKeyInGitLab(key, reason, hwid, ip);
      await sendAlert(
        `**🚨 AUTO-BAN TRIGGERED**\n` +
        `**Reason:** ${reason}\n` +
        `**Key:** \`${key}\`\n` +
        `**HWID:** \`${hwid || 'unknown'}\`\n` +
        `**IP:** \`${ip}\`\n` +
        `**Attempts:** ${a.count}`,
        'critical'
      );
    }
  }
}

// === GLOBAL RATE LIMIT ===
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: 'Rate limit' }
});
app.use(globalLimiter);

// === HEALTH ===
app.get('/health', (req, res) => res.json({ 
  status: 'online', 
  tokens: tokens.size,
  banned: bannedHwids.size,
  cert_fp: EXPECTED_CERT_FINGERPRINT.slice(0, 16) + "..."
}));

// === AUTH ===
app.post('/auth', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  const { hwid, timestamp, nonce, signature, key, client_cert_fp } = req.body || {};

  // MITM Detection
  const mitmIndicators = detectMITM(req);
  if (mitmIndicators.length > 0) {
    const suspData = suspiciousIPs.get(ip) || { count: 0, lastSeen: 0 };
    suspData.count++;
    suspData.lastSeen = Date.now();
    suspiciousIPs.set(ip, suspData);
    
    await sendAlert(
      `**🔴 MITM DETECTED**\n` +
      `**IP:** \`${ip}\`\n` +
      `**Indicators:** ${mitmIndicators.join(', ')}\n` +
      `**HWID:** \`${hwid?.slice(0,12) || 'unknown'}\`\n` +
      `**Key:** \`${key?.slice(0,12) || 'unknown'}\`\n` +
      `**Attempts:** ${suspData.count}`,
      'critical'
    );
    
    if (suspData.count >= 2) {
      await logSuspiciousActivity(ip, hwid, key, `MITM: ${mitmIndicators.join(',')}`, true);
    }
    
    return res.status(403).json({ error: 'Proxy detected' });
  }

  // Certificate Pinning Check (client должен отправить fingerprint сертификата)
  if (client_cert_fp && !constantTimeCompare(client_cert_fp, EXPECTED_CERT_FINGERPRINT)) {
    await sendAlert(
      `**🔴 CERT PINNING FAIL**\n` +
      `**Expected:** \`${EXPECTED_CERT_FINGERPRINT.slice(0,32)}...\`\n` +
      `**Got:** \`${client_cert_fp.slice(0,32)}...\`\n` +
      `**IP:** \`${ip}\`\n` +
      `**HWID:** \`${hwid?.slice(0,12)}\``,
      'critical'
    );
    await logSuspiciousActivity(ip, hwid, key, 'Certificate mismatch', true);
    return res.status(403).json({ error: 'Invalid certificate' });
  }

  try {
    if (!hwid || !timestamp || !nonce || !signature || !key) {
      await logSuspiciousActivity(ip, hwid, key, 'Missing params');
      return res.status(400).json({ error: 'Missing params' });
    }

    // Ban check
    if (bannedHwids.has(hwid)) {
      await sendAlert(`**Banned HWID tried access**\nHWID: \`${hwid}\`\nIP: \`${ip}\``, 'critical');
      return res.status(403).json({ error: 'Banned' });
    }

    // Rate limit
    if (!checkHwidRateLimit(hwid)) {
      await logSuspiciousActivity(ip, hwid, key, 'Rate limit');
      return res.status(429).json({ error: 'Too many requests' });
    }

    // Timestamp
    const reqTime = parseInt(timestamp);
    const now = Date.now();
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 30000) {
      await logSuspiciousActivity(ip, hwid, key, 'Invalid timestamp');
      return res.status(403).json({ error: 'Timestamp' });
    }

    // Replay
    const nonceKey = `${hwid}:${timestamp}:${nonce}`;
    if (nonces.has(nonceKey)) {
      await logSuspiciousActivity(ip, hwid, key, 'Replay attack', true);
      await sendAlert(`**🔴 REPLAY**\nHWID: \`${hwid}\`\nIP: \`${ip}\`\nKey: \`${key}\``, 'critical');
      return res.status(403).json({ error: 'Replay' });
    }
    nonces.set(nonceKey, now);

    // Fingerprint
    if (!verifyClientFingerprint(req, hwid, nonce)) {
      await logSuspiciousActivity(ip, hwid, key, 'Bad fingerprint', true);
      await sendAlert(`**🔴 FINGERPRINT FAIL**\nHWID: \`${hwid}\`\nIP: \`${ip}\`\nKey: \`${key}\``, 'critical');
      return res.status(403).json({ error: 'Bad FP' });
    }

    // Signature
    const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
    if (!constantTimeCompare(signature, expectedSig)) {
      await logSuspiciousActivity(ip, hwid, key, 'Bad signature');
      return res.status(403).json({ error: 'Bad sig' });
    }

    // === KEY VALIDATION ===
    const keysData = await fetchGitLabKeys();
    if (!keysData || !keysData.keys) {
      console.error("❌ Cannot fetch keys");
      return res.status(500).json({ error: 'Server error' });
    }

    let keyEntry = null;
    let realKeyName = null;
    const keyLower = key.toLowerCase();
    for (const [k, v] of Object.entries(keysData.keys)) {
      if (k.toLowerCase() === keyLower) {
        keyEntry = v;
        realKeyName = k;
        break;
      }
    }

    if (!keyEntry) {
      await logSuspiciousActivity(ip, hwid, key, 'Invalid key');
      return res.status(403).json({ error: 'Invalid key' });
    }

    if (keyEntry.banned) {
      await sendAlert(`**Banned key access**\nKey: \`${realKeyName}\`\nReason: \`${keyEntry.ban_reason}\`\nHWID: \`${hwid}\`\nIP: \`${ip}\``, 'critical');
      return res.status(403).json({ error: 'Banned key' });
    }

    const keyExpiry = parseInt(keyEntry.expires) || 0;
    if (keyExpiry === 0 || Math.floor(now / 1000) >= keyExpiry) {
      await logSuspiciousActivity(ip, hwid, key, 'Key expired');
      return res.status(403).json({ error: 'Expired' });
    }

    const keyHwid = String(keyEntry.hwid || "*");
    if (keyHwid !== "*" && keyHwid !== "" && keyHwid !== hwid) {
      await logSuspiciousActivity(ip, hwid, key, 'HWID mismatch', true);
      await sendAlert(`**🔴 HWID MISMATCH**\nKey: \`${realKeyName}\`\nExpected: \`${keyHwid}\`\nGot: \`${hwid}\`\nIP: \`${ip}\``, 'critical');
      return res.status(403).json({ error: 'HWID mismatch' });
    }

    // SUCCESS
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256(token); // Store hash, send plain
    
    const data = { 
      hwid, 
      ip, 
      ua, 
      key: realKeyName,
      expires: now + 5000, 
      used: false, 
      created: now 
    };
    tokens.set(tokenHash, data);

    console.log(`✅ Token: ${token.slice(0,8)}... | Key: ${realKeyName} | HWID: ${hwid.slice(0,8)} | IP: ${ip}`);
    
    res.json({ 
      token, 
      expires_in: 5,
      server_fp: EXPECTED_CERT_FINGERPRINT // Отправляем клиенту для проверки
    });

  } catch (e) {
    console.error("❌ AUTH ERROR:", e);
    await logSuspiciousActivity(ip, hwid, key, 'Server error');
    res.status(500).json({ error: 'Internal error' });
  }
});

// === LOAD ===
app.post('/load', async (req, res) => {
  const ip = getClientIP(req);
  const { token } = req.body || {};
  
  if (!token) {
    await logSuspiciousActivity(ip, null, null, 'No token');
    return res.status(400).json({ error: 'No token' });
  }

  const tokenHash = sha256(token);
  const tdata = tokens.get(tokenHash);
  
  if (!tdata) {
    await logSuspiciousActivity(ip, null, null, 'Invalid token');
    return res.status(403).json({ error: 'Bad token' });
  }

  if (Date.now() > tdata.expires) {
    tokens.delete(tokenHash);
    await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'Token expired');
    return res.status(403).json({ error: 'Expired' });
  }

  if (tdata.used) {
    await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'Token reuse', true);
    await sendAlert(`**🔴 TOKEN REUSE**\nKey: \`${tdata.key}\`\nHWID: \`${tdata.hwid}\`\nIP: \`${ip}\``, 'critical');
    return res.status(403).json({ error: 'Token used' });
  }

  if (tdata.ip !== ip) {
    await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'IP change', true);
    await sendAlert(`**🔴 TOKEN STOLEN**\nKey: \`${tdata.key}\`\nExpected: \`${tdata.ip}\`\nGot: \`${ip}\`\nHWID: \`${tdata.hwid}\``, 'critical');
    return res.status(403).json({ error: 'IP mismatch' });
  }

  tdata.used = true;

  try {
    const headers = { 'PRIVATE-TOKEN': GITLAB_TOKEN };
    const resp = await fetch(REPO_RAW_URL, { headers });
    
    if (!resp.ok) {
      console.error("❌ Script fetch failed:", resp.status);
      return res.status(502).json({ error: 'Upstream error' });
    }

    const script = await resp.text();
    const enc = xorEncrypt(script, tdata.hwid);
    tokens.delete(tokenHash);

    console.log(`✅ Script delivered: Key=${tdata.key} | HWID=${tdata.hwid.slice(0,8)} | IP=${ip}`);
    res.type('text/plain').send(enc);

  } catch (e) {
    console.error("❌ LOAD ERROR:", e);
    await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'Load error');
    res.status(500).json({ error: 'Internal error' });
  }
});

// === TAMPER REPORT ===
app.post('/report_tamper', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, key, reason, details } = req.body || {};

  if (!hwid || !reason) {
    return res.status(400).json({ error: 'Missing data' });
  }

  console.warn(`🚨 TAMPER: ${reason} | HWID: ${hwid?.slice(0,8)} | Key: ${key?.slice(0,8)} | IP: ${ip}`);

  bannedHwids.add(hwid);

  if (key) {
    await banKeyInGitLab(key, `Hook: ${reason}`, hwid, ip);
  }

  await sendAlert(
    `**🚨 HOOK/TAMPER DETECTED**\n` +
    `**Type:** ${reason}\n` +
    `**Details:** \`${details || 'none'}\`\n` +
    `**HWID:** \`${hwid}\`\n` +
    `**Key:** \`${key || 'unknown'}\`\n` +
    `**IP:** \`${ip}\`\n` +
    `**Action:** ✅ Key banned, HWID blocked`,
    'critical'
  );

  res.json({ status: 'banned', message: 'Your key has been permanently banned' });
});

// === BLOCK INVALID ===
app.get('/auth', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,null,'GET /auth'); res.status(405).json({error:'POST only'}); });
app.get('/load', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,null,'GET /load'); res.status(405).json({error:'POST only'}); });
app.use((req,res)=>res.status(404).json({error:'Not found'}));

// === START ===
app.listen(PORT, () => {
  console.log(`\n🔒 ============================================`);
  console.log(`   ULTRA SECURE LOADER v3.0 (Anti-MITM)`);
  console.log(`   ============================================`);
  console.log(`   ✅ Port: ${PORT}`);
  console.log(`   ✅ Auto-ban: ENABLED`);
  console.log(`   ✅ MITM detection: ENABLED`);
  console.log(`   ✅ Certificate pinning: ${!!EXPECTED_CERT_FINGERPRINT}`);
  console.log(`============================================\n`);
});
