// ULTRA SECURE RAILWAY SERVER WITH POSTGRESQL
require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { Pool } = require('pg');

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
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const GITLAB_PROJECT_ID = process.env.GITLAB_PROJECT_ID || "";
const GITLAB_BRANCH = process.env.GITLAB_BRANCH || "main";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || "";
const EXPECTED_CERT_FINGERPRINT = process.env.CERT_FINGERPRINT || "";
const DATABASE_URL = process.env.DATABASE_URL;
function md5hex(s) {
  return crypto.createHash('md5').update(s, 'utf8').digest('hex');
}

// Ð’Ð°Ð¶Ð½Ð¾: Ð¸Ð¼Ð¸Ñ‚Ð¸Ñ€ÑƒÐµÐ¼ Ñ‚Ð²Ð¾ÑŽ Lua-Ñ„ÑƒÐ½ÐºÑ†Ð¸ÑŽ: md5(ipad..msg) => hex, Ð·Ð°Ñ‚ÐµÐ¼ md5(opad..innerHex)
function hmacMd5LuaCompat(key, msg) {
  const block = 64;
  if (key.length > block) key = md5hex(key); // ÐºÐ°Ðº Ð² Ñ‚Ð²Ð¾Ñ‘Ð¼ Lua

  const kb = Buffer.from(key, 'utf8');
  let ipad = '';
  let opad = '';
  for (let i = 0; i < block; i++) {
    const b = i < kb.length ? kb[i] : 0;
    ipad += String.fromCharCode(b ^ 0x36);
    opad += String.fromCharCode(b ^ 0x5c);
  }
  const inner = md5hex(ipad + msg);     // md5 â†’ HEX-Ð¡Ð¢Ð ÐžÐšÐ
  const outer = md5hex(opad + inner);   // md5(opad || HEX(inner))
  return outer;                         // hex
}

// ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ JSON Ñ Ð¿Ð¾Ð´Ð¿Ð¸ÑÑŒÑŽ (Ð¿Ð¾Ð´Ð¿Ð¸ÑÑ‹Ð²Ð°ÐµÐ¼ Ñ€Ð¾Ð²Ð½Ð¾ JSON.stringify(obj))
function signedJson(res, obj) {
  const body = JSON.stringify(obj);
  const sig  = hmacMd5LuaCompat(SECRET_KEY, body);
  res.set('X-Resp-Sig', sig);
  res.type('application/json').send(body);
}

// ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ text/plain Ñ Ð¿Ð¾Ð´Ð¿Ð¸ÑÑŒÑŽ (Ð´Ð»Ñ /load)
function signedText(res, text) {
  const sig = hmacMd5LuaCompat(SECRET_KEY, text);
  res.set('X-Resp-Sig', sig);
  res.type('text/plain').send(text);
}
const SCRIPT_REGISTRY = {
  "kaelis.gs": "test12.lua",
  // Ð´Ð¾Ð±Ð°Ð²Ð»ÑÐ¹Ñ‚Ðµ Ð´Ñ€ÑƒÐ³Ð¸Ðµ ÑÐºÑ€Ð¸Ð¿Ñ‚Ñ‹
};

if (!SECRET_KEY) {
  console.error("âŒ Missing SECRET_KEY");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("âŒ Missing DATABASE_URL");
  process.exit(1);
}

// === POSTGRESQL ===
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('âŒ PostgreSQL pool error:', err);
});
async function runMigrations() {
  await pool.query(`
  CREATE TABLE IF NOT EXISTS keys (
    key_name TEXT PRIMARY KEY,
    hwid TEXT DEFAULT NULL,
    expires BIGINT NOT NULL,
    scripts JSONB DEFAULT '[]',
    banned BOOLEAN DEFAULT FALSE,
    ban_reason TEXT,
    banned_at BIGINT,
    banned_hwid TEXT,
    banned_ip TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS banned_hwids (
    hwid TEXT PRIMARY KEY,
    reason TEXT,
    banned_at BIGINT,
    banned_by_key TEXT,
    banned_ip TEXT
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT,
    ip TEXT,
    hwid TEXT,
    key_name TEXT,
    details TEXT,
    timestamp BIGINT
  );
  `);
  console.log('âœ… DB migrations applied');
}

const tokens = new Map();
const nonces = new Map();
const failedAttempts = new Map();
const rateLimitStore = new Map();
const suspiciousIPs = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [t, d] of tokens.entries()) if (now > d.expires) tokens.delete(t);
  for (const [n, ts] of nonces.entries()) if (now - ts > 30000) nonces.delete(n);
  for (const [ip, d] of failedAttempts.entries()) if (now - d.lastAttempt > 300000) failedAttempts.delete(ip);
  for (const [hwid, d] of rateLimitStore.entries()) if (now > d.resetTime) rateLimitStore.delete(hwid);
  for (const [ip, d] of suspiciousIPs.entries()) if (now - d.lastSeen > 600000) suspiciousIPs.delete(ip);
}, 5000);

// === DATABASE FUNCTIONS ===
async function getKeyByName(keyName) {
  const client = await pool.connect();
  try {
    // Case-insensitive Ð¿Ð¾Ð¸ÑÐº
    const result = await client.query(
      'SELECT * FROM keys WHERE LOWER(key_name) = LOWER($1) LIMIT 1',
      [keyName]
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function updateKeyHwid(keyName, hwid) {
  const client = await pool.connect();
  try {
    await client.query(
      'UPDATE keys SET hwid = $1, updated_at = CURRENT_TIMESTAMP WHERE LOWER(key_name) = LOWER($2)',
      [hwid, keyName]
    );
    console.log(`âœ… HWID bound: ${keyName} -> ${hwid.slice(0, 12)}`);
    return true;
  } catch (e) {
    console.error('âŒ Failed to update HWID:', e.message);
    return false;
  } finally {
    client.release();
  }
}

async function banKey(keyName, reason, hwid, ip) {
  const client = await pool.connect();
  try {
    const banTime = Math.floor(Date.now() / 1000);
    await client.query(
      `UPDATE keys 
       SET banned = TRUE, ban_reason = $1, banned_at = $2, banned_hwid = $3, banned_ip = $4, updated_at = CURRENT_TIMESTAMP
       WHERE LOWER(key_name) = LOWER($5)`,
      [reason, banTime, hwid, ip, keyName]
    );
    console.log(`âœ… Key banned: ${keyName} (${reason})`);
    return true;
  } catch (e) {
    console.error('âŒ Failed to ban key:', e.message);
    return false;
  } finally {
    client.release();
  }
}

async function addBannedHwid(hwid, reason, keyName, ip) {
  const client = await pool.connect();
  try {
    const banTime = Math.floor(Date.now() / 1000);
    await client.query(
      `INSERT INTO banned_hwids (hwid, reason, banned_at, banned_by_key, banned_ip)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (hwid) DO NOTHING`,
      [hwid, reason, banTime, keyName, ip]
    );
    console.log(`âœ… HWID banned: ${hwid.slice(0, 12)}`);
    return true;
  } catch (e) {
    console.error('âŒ Failed to ban HWID:', e.message);
    return false;
  } finally {
    client.release();
  }
}

async function isHwidBanned(hwid) {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT 1 FROM banned_hwids WHERE hwid = $1 LIMIT 1',
      [hwid]
    );
    return result.rows.length > 0;
  } finally {
    client.release();
  }
}

async function logActivity(eventType, ip, hwid, keyName, details) {
  const client = await pool.connect();
  try {
    await client.query(
      `INSERT INTO activity_log (event_type, ip, hwid, key_name, details, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [eventType, ip, hwid, keyName, details, Date.now()]
    );
  } catch (e) {
    console.error('âŒ Failed to log activity:', e.message);
  } finally {
    client.release();
  }
}

// === GITLAB (Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð´Ð»Ñ Ð·Ð°Ð³Ñ€ÑƒÐ·ÐºÐ¸ ÑÐºÑ€Ð¸Ð¿Ñ‚Ð¾Ð²) ===
function gitlabHeaders() {
  return {
    'PRIVATE-TOKEN': GITLAB_TOKEN,
    'Content-Type': 'application/json'
  };
}

async function fetchGitLabScript(scriptPath) {
  if (!GITLAB_TOKEN || !GITLAB_PROJECT_ID) {
    console.warn('âš ï¸ GitLab not configured for scripts');
    return null;
  }

  const encodedPath = scriptPath.replace(/([^a-zA-Z0-9-._~])/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  const url = `https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/repository/files/${encodedPath}/raw?ref=${GITLAB_BRANCH}`;

  try {
    const res = await fetch(url, { headers: gitlabHeaders() });
    if (!res.ok) {
      console.error("âŒ Script fetch failed:", res.status);
      return null;
    }
    return await res.text();
  } catch (e) {
    console.error("âŒ Script fetch error:", e.message);
    return null;
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

function xorEncrypt(txt, key) {
  const padding = crypto.randomBytes(16).toString('hex');
  const fullText = padding + txt + padding;
  
  const tb = Buffer.from(fullText, 'utf8');
  const kb = Buffer.from(key, 'utf8');
  const res = Buffer.alloc(tb.length);
  
  for (let i = 0; i < tb.length; i++) {
    res[i] = tb[i] ^ kb[i % kb.length] ^ (i & 0xFF);
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
          title: `ðŸ”’ Security Alert [${level.toUpperCase()}]`,
          description: message,
          color,
          timestamp: new Date().toISOString(),
          footer: { text: 'Loader' }
        }]
      })
    });
  } catch (e) { console.error("Alert error:", e.message); }
}

function detectMITM(req) {
  const indicators = [];
  
  if (req.headers['via']) indicators.push('Via header');
  if (req.headers['forwarded']) indicators.push('Forwarded header');
  if (req.headers['proxy-connection']) indicators.push('Proxy-Connection');
  if (req.headers['x-proxy-id']) indicators.push('X-Proxy-ID');
  
  const accept = (req.headers['accept'] || '').toLowerCase();
  if (accept.includes('fiddler') || accept.includes('charles')) {
    indicators.push('Proxy tool detected');
  }
  
  const conn = (req.headers['connection'] || '').toLowerCase();
  if (conn.includes('proxy')) indicators.push('Proxy in Connection');
  
  const ua = req.headers['user-agent'] || '';
  if (!ua || ua.length < 20) indicators.push('Suspicious UA');
  
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  if (proto !== 'https') indicators.push('Non-HTTPS');
  
  return indicators;
}

function checkHwidRateLimit(hwid) {
  const now = Date.now();
  const limit = rateLimitStore.get(hwid);
  if (!limit) { rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 }); return true; }
  if (now > limit.resetTime) { rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 }); return true; }
  if (limit.count >= 3) return false;
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
  
  console.warn(`âš ï¸ SUSPICIOUS: ${reason} | IP: ${ip} | HWID: ${hwid?.slice(0,8)} | Key: ${key?.slice(0,8)} | #${a.count}`);
  
  await logActivity('suspicious', ip, hwid, key, reason);
  
  if (autoban || a.count >= 3) {
    if (hwid) await addBannedHwid(hwid, reason, key, ip);
    if (key) {
      await banKey(key, reason, hwid, ip);
      await sendAlert(
        `**ðŸš¨ AUTO-BAN TRIGGERED**\n` +
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

function checkScriptAllowed(keyEntry, scriptName) {
  if (!keyEntry) return false;
  if (!keyEntry.scripts || keyEntry.scripts.length === 0) return true;
  return keyEntry.scripts.includes(scriptName);
}

// === RATE LIMIT ===
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: 'Rate limit' },
  skip: (req) => req.path === '/load_manifest' || req.path === '/load_chunk'
});
app.use(globalLimiter);


// === HEALTH ===
app.get('/health', async (req, res) => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    
    res.json({ 
      status: 'online',
      database: 'connected',
      tokens: tokens.size,
      cert_fp: EXPECTED_CERT_FINGERPRINT.slice(0, 16) + "..."
    });
  } catch (e) {
    res.status(500).json({ 
      status: 'degraded',
      database: 'error',
      error: e.message
    });
  }
});

// === AUTH (Ñ Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐºÐ¾Ð¹ ÐºÐ»ÑŽÑ‡Ð° Ð¸Ð· PostgreSQL) ===
app.post('/auth', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  const { hwid, timestamp, nonce, signature, key, script_name, client_cert_fp } = req.body || {};

  // MITM Detection
  const mitmIndicators = detectMITM(req);
  if (mitmIndicators.length > 0) {
    const suspData = suspiciousIPs.get(ip) || { count: 0, lastSeen: 0 };
    suspData.count++;
    suspData.lastSeen = Date.now();
    suspiciousIPs.set(ip, suspData);
    
    await sendAlert(
      `**ðŸ”´ MITM DETECTED**\n` +
      `**IP:** \`${ip}\`\n` +
      `**Indicators:** ${mitmIndicators.join(', ')}\n` +
      `**HWID:** \`${hwid?.slice(0,12) || 'unknown'}\`\n` +
      `**Key:** \`${key?.slice(0,12) || 'unknown'}\``,
      'critical'
    );
    
    if (suspData.count >= 2) {
      await logSuspiciousActivity(ip, hwid, key, `MITM: ${mitmIndicators.join(',')}`, true);
    }
    
    return res.status(403).json({ error: 'Proxy detected' });
  }

  // Certificate Pinning
  if (client_cert_fp && EXPECTED_CERT_FINGERPRINT && !constantTimeCompare(client_cert_fp, EXPECTED_CERT_FINGERPRINT)) {
    await sendAlert(
      `**ðŸ”´ CERT PINNING FAIL**\n` +
      `**Expected:** \`${EXPECTED_CERT_FINGERPRINT.slice(0,32)}...\`\n` +
      `**Got:** \`${client_cert_fp.slice(0,32)}...\`\n` +
      `**IP:** \`${ip}\``,
      'critical'
    );
    await logSuspiciousActivity(ip, hwid, key, 'Certificate mismatch', true);
    return res.status(403).json({ error: 'Invalid certificate' });
  }

  try {
    if (!hwid || !timestamp || !nonce || !signature || !key || !script_name) {
      await logSuspiciousActivity(ip, hwid, key, 'Missing params');
      return res.status(400).json({ error: 'Missing params' });
    }

    // Ban check
    if (await isHwidBanned(hwid)) {
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
      await sendAlert(`**ðŸ”´ REPLAY**\nHWID: \`${hwid}\`\nIP: \`${ip}\`\nKey: \`${key}\``, 'critical');
      return res.status(403).json({ error: 'Replay' });
    }
    nonces.set(nonceKey, now);

    // Fingerprint
    if (!verifyClientFingerprint(req, hwid, nonce)) {
      await logSuspiciousActivity(ip, hwid, key, 'Bad fingerprint', true);
      await sendAlert(`**ðŸ”´ FINGERPRINT FAIL**\nHWID: \`${hwid}\`\nIP: \`${ip}\``, 'critical');
      return res.status(403).json({ error: 'Bad FP' });
    }

    // Signature
    const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
    if (!constantTimeCompare(signature, expectedSig)) {
      await logSuspiciousActivity(ip, hwid, key, 'Bad signature');
      return res.status(403).json({ error: 'Bad sig' });
    }

    // === KEY VALIDATION (POSTGRESQL) ===
    const keyEntry = await getKeyByName(key);
    
    if (!keyEntry) {
      await logSuspiciousActivity(ip, hwid, key, 'Invalid key');
      return res.status(403).json({ error: 'Invalid key' });
    }

    if (keyEntry.banned) {
      await sendAlert(`**Banned key access**\nKey: \`${keyEntry.key_name}\`\nReason: \`${keyEntry.ban_reason}\`\nHWID: \`${hwid}\`\nIP: \`${ip}\``, 'critical');
      return res.status(403).json({ error: 'Banned key' });
    }

    const keyExpiry = parseInt(keyEntry.expires) || 0;
    if (keyExpiry === 0 || Math.floor(now / 1000) >= keyExpiry) {
      await logSuspiciousActivity(ip, hwid, key, 'Key expired');
      return res.status(403).json({ error: 'Expired' });
    }

    const keyHwid = String(keyEntry.hwid || "*");
    
    // Ð˜Ð¡ÐŸÐ ÐÐ’Ð›Ð•ÐÐ˜Ð•: ÐŸÑ€Ð¸Ð²ÑÐ·ÐºÐ° HWID Ðº ÐºÐ»ÑŽÑ‡Ñƒ
    if (keyHwid === "*" || keyHwid === "" || keyHwid === null) {
      // ÐšÐ»ÑŽÑ‡ Ð½Ðµ Ð¿Ñ€Ð¸Ð²ÑÐ·Ð°Ð½ - Ð¿Ñ€Ð¸Ð²ÑÐ·Ñ‹Ð²Ð°ÐµÐ¼ HWID
      await updateKeyHwid(keyEntry.key_name, hwid);
      console.log(`ðŸ”— HWID auto-bound: ${keyEntry.key_name} -> ${hwid.slice(0, 12)}`);
    } else if (keyHwid !== hwid) {
      // HWID Ð½Ðµ ÑÐ¾Ð²Ð¿Ð°Ð´Ð°ÐµÑ‚
      await logSuspiciousActivity(ip, hwid, key, 'HWID mismatch', true);
      await sendAlert(`**ðŸ”´ HWID MISMATCH**\nKey: \`${keyEntry.key_name}\`\nExpected: \`${keyHwid}\`\nGot: \`${hwid}\`\nIP: \`${ip}\``, 'critical');
      return res.status(403).json({ error: 'HWID mismatch' });
    }

    // Ð•ÑÐ»Ð¸ ÑÑ‚Ð¾ Ð·Ð°Ð¿Ñ€Ð¾Ñ Ð²Ð°Ð»Ð¸Ð´Ð°Ñ†Ð¸Ð¸ (Ð±ÐµÐ· Ð·Ð°Ð³Ñ€ÑƒÐ·ÐºÐ¸ ÑÐºÑ€Ð¸Ð¿Ñ‚Ð°)
    if (script_name === "__validate__") {
      console.log(`âœ… Key validated: ${keyEntry.key_name} | HWID: ${hwid.slice(0,8)} | IP: ${ip}`);
      await logActivity('validate', ip, hwid, keyEntry.key_name, 'success');
      return signedJson(res, {
        success: true,
        expires: keyExpiry,
        key: keyEntry.key_name
      });
    }

    // Script permission check
    if (!checkScriptAllowed(keyEntry, script_name)) {
      await logSuspiciousActivity(ip, hwid, key, 'Script not allowed');
      return res.status(403).json({ error: 'Script not allowed' });
    }

    // === Ð£Ð¡ÐŸÐ•Ð¥ - Ð“Ð•ÐÐ•Ð Ð˜Ð Ð£Ð•Ðœ Ð¢ÐžÐšÐ•Ð ===
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256(token);
    
    const tokenData = { 
      hwid, 
      ip, 
      ua, 
      key: keyEntry.key_name,
      script_name,
      expires: now + 15000,  // Ñ‚Ð¾ÐºÐµÐ½ Ð¶Ð¸Ð²ÐµÑ‚ 5 ÑÐµÐºÑƒÐ½Ð´
      used: false, 
      created: now 
    };
    
    tokens.set(tokenHash, tokenData);

    // Ð¨Ð¸Ñ„Ñ€ÑƒÐ¹ Ñ‚Ð¾ÐºÐµÐ½ Ð¿ÐµÑ€ÐµÐ´ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÐºÐ¾Ð¹ (Ð·Ð°Ñ‰Ð¸Ñ‚Ð° Ð¾Ñ‚ Fiddler)
    const encryptedToken = xorEncrypt(token, hwid);

    console.log(`âœ… Token: ${token.slice(0,8)}... | Key: ${keyEntry.key_name} | Script: ${script_name} | HWID: ${hwid.slice(0,8)} | IP: ${ip}`);
    await logActivity('auth_success', ip, hwid, keyEntry.key_name, script_name);
    
    signedJson(res, {
      token: encryptedToken,
      expires_in: 5,
      server_fp: (EXPECTED_CERT_FINGERPRINT || '').trim()
    });

  } catch (e) {
    console.error("âŒ AUTH ERROR:", e);
    await logSuspiciousActivity(ip, hwid, key, 'Server error');
    res.status(500).json({ error: 'Internal error' });
  }
});


// === LOAD (Ñ Ð·Ð°Ð³Ñ€ÑƒÐ·ÐºÐ¾Ð¹ Ð¸Ð· GitLab) ===
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
    await sendAlert(`**ðŸ”´ TOKEN REUSE**\nKey: \`${tdata.key}\`\nHWID: \`${tdata.hwid}\`\nIP: \`${ip}\``, 'critical');
    return res.status(403).json({ error: 'Token used' });
  }

  if (tdata.ip !== ip) {
    await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'IP change', true);
    await sendAlert(`**ðŸ”´ TOKEN STOLEN**\nKey: \`${tdata.key}\`\nExpected: \`${tdata.ip}\`\nGot: \`${ip}\``, 'critical');
    return res.status(403).json({ error: 'IP mismatch' });
  }

  tdata.used = true;

  try {
    // ÐÐ°Ð¹Ñ‚Ð¸ Ñ„Ð°Ð¹Ð» ÑÐºÑ€Ð¸Ð¿Ñ‚Ð°
    const scriptPath = SCRIPT_REGISTRY[tdata.script_name];
    if (!scriptPath) {
      console.error("âŒ Unknown script:", tdata.script_name);
      await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'Unknown script');
      return res.status(404).json({ error: 'Script not found' });
    }

    // Ð—Ð°Ð³Ñ€ÑƒÐ·Ð¸Ñ‚ÑŒ Ð¸Ð· GitLab
    const scriptCode = await fetchGitLabScript(scriptPath);
    if (!scriptCode) {
      console.error("âŒ Script fetch failed");
      await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'Script fetch failed');
      return res.status(502).json({ error: 'Upstream error' });
    }

    // Ð¨Ð¸Ñ„Ñ€ÑƒÐ¹ ÑÐºÑ€Ð¸Ð¿Ñ‚
    const encryptedScript = xorEncrypt(scriptCode, tdata.hwid);
    
    // Ð£Ð´Ð°Ð»Ð¸ Ñ‚Ð¾ÐºÐµÐ½ (Ð¾Ð´Ð½Ð¾Ñ€Ð°Ð·Ð¾Ð²Ñ‹Ð¹)
    tokens.delete(tokenHash);

    console.log(`âœ… Script delivered: ${tdata.script_name} | Key=${tdata.key} | HWID=${tdata.hwid.slice(0,8)} | IP=${ip} | Size=${encryptedScript.length}b`);
    await logActivity('load_success', ip, tdata.hwid, tdata.key, tdata.script_name);
    
    signedText(res, encryptedScript);


  } catch (e) {
    console.error("âŒ LOAD ERROR:", e);
    await logSuspiciousActivity(ip, tdata.hwid, tdata.key, 'Load error: ' + e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});
// Хранилище частей на время сессии загрузки
const chunkStores = new Map(); // tokenHash -> { items, served: Set<number>, hwid, key, ip, created }

// Детерминированно режем код
function splitTextDeterministic(text, parts = 50) {
  const out = [];
  const chunkSize = Math.ceil(text.length / parts);
  for (let i = 0; i < parts; i++) {
    const start = i * chunkSize, end = start + chunkSize;
    const slice = text.slice(start, end);
    if (slice.length) out.push(slice);
  }
  return out;
}
function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// 1) Манифест: готовим части и кладём в chunkStores (без отдачи самих данных)
app.post('/load_manifest', async (req, res) => {
  const ip = getClientIP(req);
  const { token, parts = 50 } = req.body || {};

  if (!token) return res.status(400).json({ error: 'No token' });

  const tokenHash = sha256(token);
  const tdata = tokens.get(tokenHash);
  if (!tdata) return res.status(403).json({ error: 'Bad token' });
  if (Date.now() > tdata.expires) {
    tokens.delete(tokenHash);
    return res.status(403).json({ error: 'Expired' });
  }
  if (tdata.ip !== ip) return res.status(403).json({ error: 'IP mismatch' });

  try {
    const scriptPath = SCRIPT_REGISTRY[tdata.script_name];
    if (!scriptPath) return res.status(404).json({ error: 'Script not found' });

    const scriptCode = await fetchGitLabScript(scriptPath);
    if (!scriptCode) return res.status(502).json({ error: 'Upstream error' });

    const slices = splitTextDeterministic(scriptCode, Number(parts) || 50);
    // заранее шифруем и подписываем каждую часть
    const items = slices.map((plain, i) => {
      const enc = xorEncrypt(plain, tdata.hwid);
      return { idx: i + 1, data: enc, sig: hmacMd5LuaCompat(SECRET_KEY, enc) };
    });
    // порядок для клиента можно перемешать (он всё равно соберёт по idx)
    shuffleInPlace(items);

    chunkStores.set(tokenHash, {
      items,
      served: new Set(),
      hwid: tdata.hwid,
      key: tdata.key,
      ip,
      created: Date.now()
    });

    // ВНИМАНИЕ: НЕ помечаем token как used; он нужен для последующих /load_chunk
    signedJson(res, {
      count: items.length,
      order_hint: items.map(x => x.idx) // необязательно, чисто информативно
    });
  } catch (e) {
    console.error('LOAD_MANIFEST ERROR:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// 2) Отдача одной части по запросу индекса
app.post('/load_chunk', async (req, res) => {
  const ip = getClientIP(req);
  const { token, idx } = req.body || {};
  if (!token || !idx) return res.status(400).json({ error: 'Missing params' });

  const tokenHash = sha256(token);
  const tdata = tokens.get(tokenHash);
  if (!tdata) return res.status(403).json({ error: 'Bad token' });
  if (Date.now() > tdata.expires) return res.status(403).json({ error: 'Expired' });
  if (tdata.ip !== ip) return res.status(403).json({ error: 'IP mismatch' });

  const store = chunkStores.get(tokenHash);
  if (!store) return res.status(404).json({ error: 'No manifest' });

  const part = store.items.find(x => x.idx === Number(idx));
  if (!part) return res.status(404).json({ error: 'No such part' });

  store.served.add(Number(idx));
  // Когда отдали все — чистим
  if (store.served.size >= store.items.length) {
    chunkStores.delete(tokenHash);
    // теперь можно «погасить» токен, чтобы его нельзя было переиспользовать
    tokens.delete(tokenHash);
  }

  signedJson(res, part);
});



// === TAMPER REPORT ===
app.post('/report_tamper', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, key, reason, details } = req.body || {};

  if (!hwid || !reason) {
    return res.status(400).json({ error: 'Missing data' });
  }

  console.warn(`ðŸš¨ TAMPER: ${reason} | HWID: ${hwid?.slice(0,8)} | Key: ${key?.slice(0,8)} | IP: ${ip}`);

  await addBannedHwid(hwid, `Hook: ${reason}`, key, ip);

  if (key) {
    await banKey(key, `Hook: ${reason}`, hwid, ip);
  }

  await sendAlert(
    `**ðŸš¨ HOOK/TAMPER DETECTED**\n` +
    `**Type:** ${reason}\n` +
    `**Details:** \`${details || 'none'}\`\n` +
    `**HWID:** \`${hwid}\`\n` +
    `**Key:** \`${key || 'unknown'}\`\n` +
    `**IP:** \`${ip}\`\n` +
    `**Action:** âœ… Key banned, HWID blocked`,
    'critical'
  );

  res.json({ status: 'banned', message: 'Your key has been permanently banned' });
});

// === BLOCK INVALID ===
app.get('/auth', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,null,'GET /auth'); res.status(405).json({error:'POST only'}); });
app.get('/load', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,null,'GET /load'); res.status(405).json({error:'POST only'}); });
app.use((req,res)=>res.status(404).json({error:'Not found'}));

// === START ===
app.listen(PORT, async () => {
  await runMigrations();
  console.log(`\nðŸ”’ ============================================`);
  console.log(`   ULTRA SECURE LOADER v5.0 (PostgreSQL)`);
  console.log(`   ============================================`);
  console.log(`   âœ… Port: ${PORT}`);
  console.log(`   âœ… Database: PostgreSQL`);
  console.log(`   âœ… Auto-ban: ENABLED`);
  console.log(`   âœ… MITM detection: ENABLED`);
  console.log(`   âœ… HWID binding: AUTO`);
  console.log(`   âœ… Scripts: ${Object.keys(SCRIPT_REGISTRY).length}`);
  console.log(`============================================\n`);
  
  // Test database connection
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('âœ… Database connection: OK\n');
  } catch (e) {
    console.error('âŒ Database connection failed:', e.message);
    process.exit(1);
  }
});





