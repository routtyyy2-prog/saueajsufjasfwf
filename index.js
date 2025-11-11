// ULTRA SECURE SERVER v6.0 - Maximum Server-Side Logic
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));

// ==================== CONFIG ====================
const PORT = process.env.PORT || 8080;
const MASTER_SECRET = process.env.MASTER_SECRET || crypto.randomBytes(32).toString('hex');
const DATABASE_URL = process.env.DATABASE_URL;
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const GITLAB_PROJECT_ID = process.env.GITLAB_PROJECT_ID || "";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || "";

if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL");
  process.exit(1);
}

// ==================== DATABASE ====================
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => console.error('❌ PostgreSQL error:', err));

async function runMigrations() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      key_name TEXT PRIMARY KEY,
      hwid TEXT,
      expires BIGINT NOT NULL,
      scripts JSONB DEFAULT '["kaelis.gs"]',
      banned BOOLEAN DEFAULT FALSE,
      ban_reason TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      hwid TEXT PRIMARY KEY,
      session_key TEXT NOT NULL,
      challenge TEXT NOT NULL,
      challenge_answer TEXT,
      server_nonce TEXT NOT NULL,
      ip TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      validated BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS tokens (
      token_hash TEXT PRIMARY KEY,
      hwid TEXT NOT NULL,
      key_name TEXT NOT NULL,
      script_name TEXT NOT NULL,
      prev_token_hash TEXT,
      ip TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      used_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS behavioral_log (
      id BIGSERIAL PRIMARY KEY,
      hwid TEXT NOT NULL,
      event_type TEXT NOT NULL,
      details JSONB,
      timestamp BIGINT NOT NULL,
      risk_score INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS banned_hwids (
      hwid TEXT PRIMARY KEY,
      reason TEXT,
      banned_at BIGINT
    );

    CREATE INDEX IF NOT EXISTS idx_tokens_hwid ON tokens(hwid);
    CREATE INDEX IF NOT EXISTS idx_behavioral_hwid ON behavioral_log(hwid);
  `);
  console.log('✅ Migrations applied');
}

// ==================== IN-MEMORY STORES ====================
const activeSessions = new Map(); // hwid -> session data
const rateLimits = new Map(); // ip -> {count, reset}
const suspiciousIPs = new Map(); // ip -> risk_score

// Cleanup
setInterval(() => {
  const now = Date.now();
  for (const [hwid, sess] of activeSessions.entries()) {
    if (now > sess.expires_at) activeSessions.delete(hwid);
  }
  for (const [ip, limit] of rateLimits.entries()) {
    if (now > limit.reset) rateLimits.delete(ip);
  }
}, 10000);

// ==================== UTILS ====================
function md5(s) {
  return crypto.createHash('md5').update(s, 'utf8').digest('hex');
}

function sha256(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function hmacMd5(key, msg) {
  const block = 64;
  if (key.length > block) key = md5(key);
  const kb = Buffer.from(key, 'utf8');
  let ipad = '', opad = '';
  for (let i = 0; i < block; i++) {
    const b = i < kb.length ? kb[i] : 0;
    ipad += String.fromCharCode(b ^ 0x36);
    opad += String.fromCharCode(b ^ 0x5c);
  }
  const inner = md5(ipad + msg);
  return md5(opad + inner);
}

function signedJson(res, obj) {
  const body = JSON.stringify(obj);
  const sig = hmacMd5(MASTER_SECRET, body);
  res.set('X-Resp-Sig', sig);
  res.json(obj);
}

function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function xorEncrypt(text, key) {
  const padding = crypto.randomBytes(16).toString('hex');
  const full = padding + text + padding;
  const tb = Buffer.from(full, 'utf8');
  const kb = Buffer.from(key, 'utf8');
  const res = Buffer.alloc(tb.length);
  for (let i = 0; i < tb.length; i++) {
    res[i] = tb[i] ^ kb[i % kb.length] ^ (i & 0xFF);
  }
  return res.toString('base64');
}

function checkRateLimit(ip, limit = 5) {
  const now = Date.now();
  const entry = rateLimits.get(ip);
  
  if (!entry) {
    rateLimits.set(ip, { count: 1, reset: now + 60000 });
    return true;
  }
  
  if (now > entry.reset) {
    rateLimits.set(ip, { count: 1, reset: now + 60000 });
    return true;
  }
  
  if (entry.count >= limit) return false;
  
  entry.count++;
  return true;
}

async function logBehavior(hwid, eventType, details, riskScore = 0) {
  try {
    await pool.query(
      'INSERT INTO behavioral_log (hwid, event_type, details, timestamp, risk_score) VALUES ($1, $2, $3, $4, $5)',
      [hwid, eventType, JSON.stringify(details), Date.now(), riskScore]
    );
  } catch (e) {
    console.error('Behavior log error:', e.message);
  }
}

async function analyzeBehavior(hwid) {
  const client = await pool.connect();
  try {
    const result = await pool.query(
      'SELECT SUM(risk_score) as total FROM behavioral_log WHERE hwid = $1 AND timestamp > $2',
      [hwid, Date.now() - 3600000] // last hour
    );
    
    const totalRisk = parseInt(result.rows[0]?.total || 0);
    return totalRisk;
  } finally {
    client.release();
  }
}

async function banHwid(hwid, reason) {
  await pool.query(
    'INSERT INTO banned_hwids (hwid, reason, banned_at) VALUES ($1, $2, $3) ON CONFLICT (hwid) DO NOTHING',
    [hwid, reason, Date.now()]
  );
  console.log(`🔨 HWID banned: ${hwid.slice(0,12)} - ${reason}`);
}

async function isHwidBanned(hwid) {
  const result = await pool.query('SELECT 1 FROM banned_hwids WHERE hwid = $1 LIMIT 1', [hwid]);
  return result.rows.length > 0;
}

async function sendAlert(message, level = 'warning') {
  if (!ALERT_WEBHOOK) return;
  const color = level === 'critical' ? 15158332 : 16776960;
  try {
    const https = require('https');
    const url = new URL(ALERT_WEBHOOK);
    const payload = JSON.stringify({
      embeds: [{
        title: `🚨 Security Alert [${level.toUpperCase()}]`,
        description: message,
        color,
        timestamp: new Date().toISOString()
      }]
    });
    
    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length
      }
    };
    
    const req = https.request(options);
    req.write(payload);
    req.end();
  } catch (e) {
    console.error('Alert error:', e.message);
  }
}

// ==================== CHALLENGE GENERATION ====================
function generateChallenge() {
  const types = ['reverse', 'sum', 'xor'];
  const type = types[Math.floor(Math.random() * types.length)];
  
  switch (type) {
    case 'reverse':
      const str = crypto.randomBytes(8).toString('hex');
      return { challenge: str, answer: str.split('').reverse().join('') };
    
    case 'sum':
      const a = Math.floor(Math.random() * 100);
      const b = Math.floor(Math.random() * 100);
      return { challenge: `${a}+${b}`, answer: String(a + b) };
    
    case 'xor':
      const x = Math.floor(Math.random() * 255);
      const y = Math.floor(Math.random() * 255);
      return { challenge: `${x}^${y}`, answer: String(x ^ y) };
  }
}

// ==================== GITLAB ====================
async function fetchScriptFromGitlab(scriptName) {
  const scriptMap = {
    'kaelis.gs': 'test12.lua'
  };
  
  const path = scriptMap[scriptName];
  if (!path) return null;
  
  const url = `https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/repository/files/${encodeURIComponent(path)}/raw?ref=main`;
  
  try {
    const fetch = (await import('node-fetch')).default;
    const res = await fetch(url, {
      headers: { 'PRIVATE-TOKEN': GITLAB_TOKEN }
    });
    
    if (!res.ok) return null;
    return await res.text();
  } catch (e) {
    console.error('GitLab fetch error:', e.message);
    return null;
  }
}

// ==================== CODE OBFUSCATION ====================
function obfuscateCode(code) {
  // Простая обфускация: добавляем junk, переименовываем переменные
  const junk = `-- ${crypto.randomBytes(32).toString('hex')}\n`;
  const wrapped = `(function()${junk}${code}\nend)()`;
  return wrapped;
}

// ==================== ENDPOINTS ====================

// 1. INIT - Создание сессии
app.post('/init', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid } = req.body;
  
  if (!checkRateLimit(ip, 3)) {
    return res.status(429).json({ error: 'Rate limit' });
  }
  
  if (!hwid || hwid.length < 10) {
    return res.status(400).json({ error: 'Invalid HWID' });
  }
  
  if (await isHwidBanned(hwid)) {
    await sendAlert(`Banned HWID tried init: ${hwid}`, 'critical');
    return res.status(403).json({ error: 'Banned' });
  }
  
  try {
    // Генерируем сессионный ключ
    const sessionKey = crypto.randomBytes(32).toString('hex');
    const { challenge, answer } = generateChallenge();
    const serverNonce = crypto.randomBytes(16).toString('hex');
    
    const sessionData = {
      hwid,
      session_key: sessionKey,
      challenge,
      challenge_answer: answer,
      server_nonce: serverNonce,
      ip,
      created_at: Date.now(),
      expires_at: Date.now() + 300000, // 5 min
      validated: false
    };
    
    activeSessions.set(hwid, sessionData);
    
    // Сохраняем в БД
    await pool.query(
      `INSERT INTO sessions (hwid, session_key, challenge, challenge_answer, server_nonce, ip, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (hwid) DO UPDATE SET
       session_key = $2, challenge = $3, challenge_answer = $4, server_nonce = $5, ip = $6, created_at = $7, expires_at = $8`,
      [hwid, sessionKey, challenge, answer, serverNonce, ip, sessionData.created_at, sessionData.expires_at]
    );
    
    await logBehavior(hwid, 'init', { ip }, 0);
    
    console.log(`✅ Session init: ${hwid.slice(0,12)} | IP: ${ip}`);
    
    signedJson(res, {
      session_key: sessionKey,
      challenge,
      server_nonce: serverNonce
    });
    
  } catch (e) {
    console.error('Init error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// 2. VALIDATE - Проверка ключа
app.post('/validate', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, data, nonce } = req.body;
  
  if (!checkRateLimit(ip, 3)) {
    return res.status(429).json({ error: 'Rate limit' });
  }
  
  if (!hwid || !data || !nonce) {
    return res.status(400).json({ error: 'Missing params' });
  }
  
  if (await isHwidBanned(hwid)) {
    return res.status(403).json({ error: 'Banned' });
  }
  
  try {
    const session = activeSessions.get(hwid);
    if (!session) {
      await logBehavior(hwid, 'validate_no_session', { ip }, 10);
      return res.status(403).json({ error: 'No session' });
    }
    
    if (Date.now() > session.expires_at) {
      activeSessions.delete(hwid);
      return res.status(403).json({ error: 'Session expired' });
    }
    
    if (nonce !== session.server_nonce) {
      await logBehavior(hwid, 'validate_bad_nonce', { ip }, 15);
      return res.status(403).json({ error: 'Invalid nonce' });
    }
    
    if (session.ip !== ip) {
      await logBehavior(hwid, 'validate_ip_change', { old_ip: session.ip, new_ip: ip }, 20);
      await sendAlert(`IP change detected!\nHWID: ${hwid}\nOld: ${session.ip}\nNew: ${ip}`, 'critical');
      return res.status(403).json({ error: 'IP mismatch' });
    }
    
    // Расшифровываем данные
    const encrypted = Buffer.from(data, 'base64');
    const kb = Buffer.from(session.session_key, 'utf8');
    const decrypted = Buffer.alloc(encrypted.length);
    
    for (let i = 0; i < encrypted.length; i++) {
      decrypted[i] = encrypted[i] ^ kb[i % kb.length] ^ (i & 0xFF);
    }
    
    const payload = decrypted.toString('utf8');
    const [payloadHwid, key, challengeAnswer] = payload.split(':');
    
    // Проверяем challenge
    if (challengeAnswer !== session.challenge_answer) {
      await logBehavior(hwid, 'validate_bad_challenge', { ip }, 25);
      await banHwid(hwid, 'Failed challenge');
      await sendAlert(`Challenge failed!\nHWID: ${hwid}\nIP: ${ip}`, 'critical');
      return res.status(403).json({ error: 'Challenge failed' });
    }
    
    // Проверяем ключ в БД
    const keyResult = await pool.query(
      'SELECT * FROM keys WHERE LOWER(key_name) = LOWER($1) LIMIT 1',
      [key]
    );
    
    if (keyResult.rows.length === 0) {
      await logBehavior(hwid, 'validate_invalid_key', { key: key.slice(0,8), ip }, 30);
      return res.status(403).json({ error: 'Invalid key' });
    }
    
    const keyEntry = keyResult.rows[0];
    
    if (keyEntry.banned) {
      return res.status(403).json({ error: 'Banned key' });
    }
    
    const now = Math.floor(Date.now() / 1000);
    if (now >= keyEntry.expires) {
      return res.status(403).json({ error: 'Expired' });
    }
    
    // HWID binding
    if (!keyEntry.hwid || keyEntry.hwid === '*') {
      await pool.query('UPDATE keys SET hwid = $1 WHERE key_name = $2', [hwid, keyEntry.key_name]);
      console.log(`✅ HWID bound: ${keyEntry.key_name} -> ${hwid.slice(0,12)}`);
    } else if (keyEntry.hwid !== hwid) {
      await logBehavior(hwid, 'validate_hwid_mismatch', { expected: keyEntry.hwid, got: hwid }, 50);
      await banHwid(hwid, 'HWID mismatch');
      await sendAlert(`HWID mismatch!\nKey: ${keyEntry.key_name}\nExpected: ${keyEntry.hwid}\nGot: ${hwid}`, 'critical');
      return res.status(403).json({ error: 'HWID mismatch' });
    }
    
    // Обновляем сессию
    session.validated = true;
    session.key_name = keyEntry.key_name;
    
    await pool.query('UPDATE sessions SET validated = TRUE WHERE hwid = $1', [hwid]);
    await logBehavior(hwid, 'validate_success', { key: keyEntry.key_name }, 0);
    
    console.log(`✅ Validated: ${keyEntry.key_name} | HWID: ${hwid.slice(0,12)}`);
    
    signedJson(res, {
      success: true,
      expires: keyEntry.expires
    });
    
  } catch (e) {
    console.error('Validate error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// 3. REQUEST_TOKEN - Получение токена для загрузки
app.post('/request_token', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, key, script, prev_token } = req.body;
  
  if (!checkRateLimit(ip, 5)) {
    return res.status(429).json({ error: 'Rate limit' });
  }
  
  if (!hwid || !key || !script) {
    return res.status(400).json({ error: 'Missing params' });
  }
  
  if (await isHwidBanned(hwid)) {
    return res.status(403).json({ error: 'Banned' });
  }
  
  try {
    const session = activeSessions.get(hwid);
    if (!session || !session.validated) {
      await logBehavior(hwid, 'token_no_session', { ip }, 15);
      return res.status(403).json({ error: 'Not authenticated' });
    }
    
    // Behavioral analysis
    const riskScore = await analyzeBehavior(hwid);
    if (riskScore > 100) {
      await banHwid(hwid, 'High risk score: ' + riskScore);
      await sendAlert(`Auto-ban: High risk\nHWID: ${hwid}\nScore: ${riskScore}`, 'critical');
      return res.status(403).json({ error: 'Banned' });
    }
    
    // Проверяем ключ
    const keyResult = await pool.query('SELECT * FROM keys WHERE key_name = $1', [key]);
    if (keyResult.rows.length === 0 || keyResult.rows[0].banned) {
      return res.status(403).json({ error: 'Invalid key' });
    }
    
    const keyEntry = keyResult.rows[0];
    const scripts = keyEntry.scripts || [];
    if (scripts.length > 0 && !scripts.includes(script)) {
      await logBehavior(hwid, 'token_unauthorized_script', { script }, 20);
      return res.status(403).json({ error: 'Script not allowed' });
    }
    
    // Проверяем token chain
    let prevTokenHash = null;
    if (prev_token) {
      prevTokenHash = sha256(prev_token);
      const prevResult = await pool.query('SELECT * FROM tokens WHERE token_hash = $1', [prevTokenHash]);
      if (prevResult.rows.length === 0) {
        await logBehavior(hwid, 'token_invalid_chain', { ip }, 25);
        return res.status(403).json({ error: 'Invalid token chain' });
      }
    }
    
    // Генерируем новый токен
    const token = crypto.randomBytes(48).toString('hex');
    const tokenHash = sha256(token);
    
    const tokenData = {
      token_hash: tokenHash,
      hwid,
      key_name: keyEntry.key_name,
      script_name: script,
      prev_token_hash: prevTokenHash,
      ip,
      created_at: Date.now(),
      expires_at: Date.now() + 10000, // 10 sec
      used: false
    };
    
    await pool.query(
      `INSERT INTO tokens (token_hash, hwid, key_name, script_name, prev_token_hash, ip, created_at, expires_at, used)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [tokenHash, hwid, keyEntry.key_name, script, prevTokenHash, ip, tokenData.created_at, tokenData.expires_at, false]
    );
    
    await logBehavior(hwid, 'token_issued', { script }, 0);
    
    console.log(`✅ Token issued: ${script} | ${hwid.slice(0,12)}`);
    
    signedJson(res, { token });
    
  } catch (e) {
    console.error('Token error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// 4. DOWNLOAD - Загрузка скрипта
app.post('/download', async (req, res) => {
  const ip = getClientIP(req);
  const { token, hwid } = req.body;
  
  if (!checkRateLimit(ip, 3)) {
    return res.status(429).json({ error: 'Rate limit' });
  }
  
  if (!token || !hwid) {
    return res.status(400).json({ error: 'Missing params' });
  }
  
  if (await isHwidBanned(hwid)) {
    return res.status(403).json({ error: 'Banned' });
  }
  
  try {
    const tokenHash = sha256(token);
    const tokenResult = await pool.query('SELECT * FROM tokens WHERE token_hash = $1', [tokenHash]);
    
    if (tokenResult.rows.length === 0) {
      await logBehavior(hwid, 'download_invalid_token', { ip }, 30);
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    const tokenData = tokenResult.rows[0];
    
    if (tokenData.used) {
      await logBehavior(hwid, 'download_token_reuse', { ip }, 40);
      await banHwid(hwid, 'Token reuse');
      await sendAlert(`Token reuse!\nHWID: ${hwid}\nIP: ${ip}`, 'critical');
      return res.status(403).json({ error: 'Token already used' });
    }
    
    if (Date.now() > tokenData.expires_at) {
      return res.status(403).json({ error: 'Token expired' });
    }
    
    if (tokenData.hwid !== hwid) {
      await logBehavior(hwid, 'download_hwid_mismatch', { ip }, 45);
      await banHwid(hwid, 'Token HWID mismatch');
      return res.status(403).json({ error: 'HWID mismatch' });
    }
    
    if (tokenData.ip !== ip) {
      await logBehavior(hwid, 'download_ip_change', { old: tokenData.ip, new: ip }, 50);
      await banHwid(hwid, 'Token IP change');
      return res.status(403).json({ error: 'IP mismatch' });
    }
    
    // Отмечаем токен как использованный
    await pool.query('UPDATE tokens SET used = TRUE, used_at = $1 WHERE token_hash = $2', [Date.now(), tokenHash]);
    
    // Загружаем скрипт
    const scriptCode = await fetchScriptFromGitlab(tokenData.script_name);
    if (!scriptCode) {
      console.error('Script fetch failed');
      return res.status(502).json({ error: 'Script unavailable' });
    }
    
    // Обфусцируем
    const obfuscated = obfuscateCode(scriptCode);
    
    // Шифруем
    const encrypted = xorEncrypt(obfuscated, hwid);
    
    await logBehavior(hwid, 'download_success', { script: tokenData.script_name }, 0);
    
    console.log(`✅ Script delivered: ${tokenData.script_name} | ${hwid.slice(0,12)} | Size: ${encrypted.length}b`);
    
    res.set('X-Resp-Sig', hmacMd5(MASTER_SECRET, encrypted));
    res.type('text/plain').send(encrypted);
    
  } catch (e) {
    console.error('Download error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ==================== ADMIN ====================
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'online',
      sessions: activeSessions.size,
      timestamp: Date.now()
    });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// ==================== START ====================
app.listen(PORT, async () => {
  await runMigrations();
  console.log(`
╔════════════════════════════════════════╗
║   🔒 ULTRA SECURE LOADER v6.0         ║
╠════════════════════════════════════════╣
║   ✅ Port: ${PORT.toString().padEnd(27)} ║
║   ✅ Database: PostgreSQL              ║
║   ✅ Challenge-Response: ENABLED       ║
║   ✅ Token Chaining: ENABLED           ║
║   ✅ Behavioral Analysis: ENABLED      ║
║   ✅ Code Obfuscation: ENABLED         ║
╚════════════════════════════════════════╝
  `);
  
  try {
    await pool.query('SELECT 1');
    console.log('✅ Database connected\n');
  } catch (e) {
    console.error('❌ Database error:', e.message);
    process.exit(1);
  }
});
