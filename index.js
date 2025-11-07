// index.js - Ultra Secure Loader Backend
// Защита от: replay attacks, IP spoofing, token reuse, timing attacks, bruteforce
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
app.use(express.json({ limit: '64kb' }));

// === CONFIGURATION ===
const PORT = process.env.PORT || 8080;
const REPO_RAW_URL = process.env.REPO_RAW_URL || "";
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = process.env.SECRET_CHECKSUM || ""; // MD5 хеш SECRET_KEY
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || ""; // Discord webhook для алертов

if (!REPO_RAW_URL || !SECRET_KEY || !SECRET_CHECKSUM) {
  console.error("❌ Missing required env: REPO_RAW_URL, SECRET_KEY, SECRET_CHECKSUM");
  process.exit(1);
}

// === SECURITY STORES ===
const tokens = new Map();        // token -> {hwid, ip, ua, expires, used}
const nonces = new Map();        // nonce -> timestamp (защита от replay)
const failedAttempts = new Map(); // ip -> {count, lastAttempt}
const rateLimitStore = new Map(); // hwid -> {count, resetTime}

// Очистка старых данных каждые 5 секунд
setInterval(() => {
  const now = Date.now();
  
  // Удаляем просроченные токены
  for (const [token, data] of tokens.entries()) {
    if (now > data.expires) tokens.delete(token);
  }
  
  // Удаляем старые nonce (старше 30 сек)
  for (const [nonce, timestamp] of nonces.entries()) {
    if (now - timestamp > 30000) nonces.delete(nonce);
  }
  
  // Сброс failed attempts (через 5 минут)
  for (const [ip, data] of failedAttempts.entries()) {
    if (now - data.lastAttempt > 300000) failedAttempts.delete(ip);
  }
  
  // Сброс rate limits
  for (const [hwid, data] of rateLimitStore.entries()) {
    if (now > data.resetTime) rateLimitStore.delete(hwid);
  }
}, 5000);

// === RATE LIMITING ===
// Глобальный rate limit по IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15, // 15 запросов в минуту с одного IP
  standardHeaders: true,
  message: { error: 'Too many requests' }
});

app.use(globalLimiter);

// === UTILITY FUNCTIONS ===
function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function xorEncrypt(text, key) {
  const textBuf = Buffer.from(text, 'utf8');
  const keyBuf = Buffer.from(key, 'utf8');
  const result = Buffer.alloc(textBuf.length);
  
  for (let i = 0; i < textBuf.length; i++) {
    result[i] = textBuf[i] ^ keyBuf[i % keyBuf.length];
  }
  
  return result.toString('base64');
}

function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || 
          req.headers['x-real-ip'] || 
          req.socket.remoteAddress || 
          'unknown').split(',')[0].trim();
}

// Защита от timing attacks
function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// Проверка fingerprint клиента
function verifyClientFingerprint(req, hwid, nonce) {
  const xClientFp = req.headers['x-client-fp'] || '';
  
  // Ожидаемый fingerprint: MD5(hwid:nonce:SECRET_CHECKSUM)
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  
  return constantTimeCompare(xClientFp, expectedFp);
}

// Rate limit по HWID (защита от bruteforce)
function checkHwidRateLimit(hwid) {
  const now = Date.now();
  const limit = rateLimitStore.get(hwid);
  
  if (!limit) {
    rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 });
    return true;
  }
  
  if (now > limit.resetTime) {
    rateLimitStore.set(hwid, { count: 1, resetTime: now + 60000 });
    return true;
  }
  
  if (limit.count >= 5) { // Максимум 5 попыток в минуту с одного HWID
    return false;
  }
  
  limit.count++;
  return true;
}

// Отправка алертов в Discord
async function sendAlert(message, level = 'warning') {
  if (!ALERT_WEBHOOK) return;
  
  const color = level === 'critical' ? 15158332 : (level === 'warning' ? 16776960 : 3447003);
  
  try {
    await fetch(ALERT_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `🔒 Loader Security Alert [${level.toUpperCase()}]`,
          description: message,
          color: color,
          timestamp: new Date().toISOString()
        }]
      })
    });
  } catch (err) {
    console.error('Alert webhook failed:', err.message);
  }
}

// Логирование подозрительной активности
function logSuspiciousActivity(ip, hwid, reason) {
  const key = ip;
  const attempt = failedAttempts.get(key) || { count: 0, lastAttempt: 0 };
  
  attempt.count++;
  attempt.lastAttempt = Date.now();
  failedAttempts.set(key, attempt);
  
  console.warn(`⚠️  Suspicious: ${reason} | IP: ${ip} | HWID: ${hwid?.substring(0,8)}... | Attempts: ${attempt.count}`);
  
  // Алерт после 5 неудачных попыток
  if (attempt.count >= 5) {
    sendAlert(`**Possible attack detected!**\nIP: \`${ip}\`\nHWID: \`${hwid?.substring(0,12)}...\`\nReason: ${reason}\nAttempts: ${attempt.count}`, 'critical');
  }
}

// === HEALTH CHECK ===
app.get('/health', (req, res) => {
  res.json({
    status: 'online',
    tokens_active: tokens.size,
    nonces_cached: nonces.size,
    config_ok: Boolean(REPO_RAW_URL && SECRET_KEY)
  });
});

// === AUTHENTICATION ENDPOINT ===
app.post('/auth', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  
  try {
    const { hwid, timestamp, nonce, signature } = req.body;
    
    // 1. Проверка наличия всех параметров
    if (!hwid || !timestamp || !nonce || !signature) {
      logSuspiciousActivity(ip, hwid, 'Missing parameters');
      return res.status(400).json({ error: 'Missing required parameters' });
    }
    
    // 2. Проверка HWID rate limit
    if (!checkHwidRateLimit(hwid)) {
      logSuspiciousActivity(ip, hwid, 'HWID rate limit exceeded');
      return res.status(429).json({ error: 'Too many requests from this HWID' });
    }
    
    // 3. Проверка timestamp (окно 30 секунд)
    const reqTime = parseInt(timestamp);
    const now = Date.now();
    
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 30000) {
      logSuspiciousActivity(ip, hwid, 'Invalid/expired timestamp');
      return res.status(403).json({ error: 'Timestamp invalid or expired' });
    }
    
    // 4. Защита от replay атак через nonce
    const nonceKey = `${hwid}:${timestamp}:${nonce}`;
    if (nonces.has(nonceKey)) {
      logSuspiciousActivity(ip, hwid, 'Replay attack detected (duplicate nonce)');
      await sendAlert(`**Replay attack!**\nIP: \`${ip}\`\nHWID: \`${hwid.substring(0,12)}...\``, 'critical');
      return res.status(403).json({ error: 'Replay detected' });
    }
    nonces.set(nonceKey, now);
    
    // 5. Проверка client fingerprint
    if (!verifyClientFingerprint(req, hwid, nonce)) {
      logSuspiciousActivity(ip, hwid, 'Invalid client fingerprint');
      return res.status(403).json({ error: 'Invalid client fingerprint' });
    }
    
    // 6. Проверка подписи (MD5 для совместимости с Lua)
    const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
    
    if (!constantTimeCompare(signature, expectedSig)) {
      logSuspiciousActivity(ip, hwid, 'Invalid signature');
      return res.status(403).json({ error: 'Invalid signature' });
    }
    
    // 7. Генерация одноразового токена
    const token = crypto.randomBytes(32).toString('hex');
    const tokenData = {
      hwid,
      ip,
      ua,
      expires: now + 10000, // 10 секунд
      used: false,
      created: now
    };
    
    tokens.set(token, tokenData);
    
    console.log(`✅ Token issued: ${token.substring(0,8)}... | HWID: ${hwid.substring(0,8)}... | IP: ${ip}`);
    
    res.json({
      token,
      expires_in: 10
    });
    
  } catch (err) {
    console.error('❌ AUTH ERROR:', err);
    logSuspiciousActivity(ip, null, 'Server error during auth');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// === SCRIPT LOADING ENDPOINT ===
app.post('/load', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  
  try {
    const { token } = req.body;
    
    // 1. Проверка токена
    if (!token) {
      logSuspiciousActivity(ip, null, 'Missing token in /load');
      return res.status(400).json({ error: 'Missing token' });
    }
    
    const tokenData = tokens.get(token);
    
    if (!tokenData) {
      logSuspiciousActivity(ip, null, 'Invalid/unknown token');
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // 2. Проверка срока действия
    if (Date.now() > tokenData.expires) {
      tokens.delete(token);
      logSuspiciousActivity(ip, tokenData.hwid, 'Expired token used');
      return res.status(403).json({ error: 'Token expired' });
    }
    
    // 3. Проверка что токен не использован (одноразовый!)
    if (tokenData.used) {
      logSuspiciousActivity(ip, tokenData.hwid, 'Token reuse attempt');
      await sendAlert(`**Token reuse!**\nIP: \`${ip}\`\nHWID: \`${tokenData.hwid.substring(0,12)}...\``, 'critical');
      return res.status(403).json({ error: 'Token already used' });
    }
    
    // 4. IP binding (защита от token stealing)
    if (tokenData.ip !== ip) {
      logSuspiciousActivity(ip, tokenData.hwid, `IP mismatch (expected: ${tokenData.ip})`);
      await sendAlert(`**Token stolen?**\nExpected IP: \`${tokenData.ip}\`\nActual IP: \`${ip}\`\nHWID: \`${tokenData.hwid.substring(0,12)}...\``, 'critical');
      return res.status(403).json({ error: 'IP mismatch' });
    }
    
    // 5. User-Agent consistency check
    if (tokenData.ua !== ua) {
      console.warn(`⚠️  UA changed: ${tokenData.ua} -> ${ua} for HWID ${tokenData.hwid.substring(0,8)}`);
    }
    
    // 6. Помечаем токен как использованный СРАЗУ
    tokenData.used = true;
    
    // 7. Загружаем скрипт с GitLab
    const headers = {};
    if (GITLAB_TOKEN) {
      headers['PRIVATE-TOKEN'] = GITLAB_TOKEN;
    }
    
    const scriptResponse = await fetch(REPO_RAW_URL, { headers });
    
    if (!scriptResponse.ok) {
      console.error(`❌ GitLab fetch failed: ${scriptResponse.status}`);
      tokens.delete(token);
      return res.status(502).json({ error: 'Upstream error' });
    }
    
    const script = await scriptResponse.text();
    
    // 8. Шифруем скрипт с использованием HWID как ключа
    const encrypted = xorEncrypt(script, tokenData.hwid);
    
    // 9. Удаляем использованный токен
    tokens.delete(token);
    
    console.log(`✅ Script delivered: HWID ${tokenData.hwid.substring(0,8)}... | IP: ${ip} | Size: ${encrypted.length} bytes`);
    
    res.type('text/plain').send(encrypted);
    
  } catch (err) {
    console.error('❌ LOAD ERROR:', err);
    logSuspiciousActivity(ip, null, 'Server error during load');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// === FORBIDDEN ENDPOINTS (защита от direct access) ===
app.get('/auth', (req, res) => {
  logSuspiciousActivity(getClientIP(req), null, 'GET request to /auth');
  res.status(405).json({ error: 'Method not allowed. Use POST.' });
});

app.get('/load', (req, res) => {
  logSuspiciousActivity(getClientIP(req), null, 'GET request to /load');
  res.status(405).json({ error: 'Method not allowed. Use POST.' });
});

// Fallback для старого эндпоинта
app.all('/get_main', (req, res) => {
  logSuspiciousActivity(getClientIP(req), null, 'Attempt to access deprecated /get_main');
  res.status(410).json({ error: 'Endpoint deprecated. Update your loader.' });
});

// === 404 для всех остальных путей ===
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// === STARTUP ===
app.listen(PORT, () => {
  console.log(`\n🔒 ============================================`);
  console.log(`   SECURE LOADER PROXY - MAXIMUM PROTECTION`);
  console.log(`   ============================================`);
  console.log(`   ✅ Server running on port ${PORT}`);
  console.log(`   ✅ GitLab configured: ${Boolean(GITLAB_TOKEN)}`);
  console.log(`   ✅ Alerts enabled: ${Boolean(ALERT_WEBHOOK)}`);
  console.log(`   🔐 Security features:`);
  console.log(`      - Token-based auth (10s TTL)`);
  console.log(`      - IP binding`);
  console.log(`      - Replay attack protection`);
  console.log(`      - Rate limiting (IP + HWID)`);
  console.log(`      - Client fingerprinting`);
  console.log(`      - XOR encryption with HWID`);
  console.log(`      - Timing attack protection`);
  console.log(`      - Suspicious activity monitoring`);
  console.log(`============================================\n`);
});
