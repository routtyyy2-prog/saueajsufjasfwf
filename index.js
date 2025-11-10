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
const INIT_MODE = (process.env.INIT_MODE || "migrate").toLowerCase(); // "migrate" | "reset"
const BOT_ADMIN_TOKEN = process.env.BOT_ADMIN_TOKEN || "";
function requireBotAdmin(req, res) {
  const tok = String(req.body?.admin_token || '');
  if (!BOT_ADMIN_TOKEN || tok !== BOT_ADMIN_TOKEN) {
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  return true;
}
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
async function hardResetPublicSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Самый простой и чистый способ снести всё
    await client.query('DROP SCHEMA IF EXISTS public CASCADE;');
    await client.query('CREATE SCHEMA public;');
    // (опционально) вернуть дефолтные права
    await client.query('GRANT ALL ON SCHEMA public TO public;');
    await client.query('COMMIT');
    console.log('✅ Dropped & recreated schema "public"');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ hardResetPublicSchema failed:', e.message);
    throw e;
  } finally {
    client.release();
  }
}

// Фолбэк, если DROP SCHEMA запрещён (хостинг урезал права)
async function dropAllObjectsFallback() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Сгенерим DROP для всех объектов в public (таблицы/вьюхи/последовательности/типы)
    const q = `
      DO $$
      DECLARE r RECORD;
      BEGIN
        -- drop views first
        FOR r IN (SELECT 'DROP VIEW IF EXISTS public.' || quote_ident(table_name) || ' CASCADE;' AS q
                  FROM information_schema.views WHERE table_schema='public')
        LOOP EXECUTE r.q; END LOOP;

        -- drop tables
        FOR r IN (SELECT 'DROP TABLE IF EXISTS public.' || quote_ident(tablename) || ' CASCADE;' AS q
                  FROM pg_tables WHERE schemaname='public')
        LOOP EXECUTE r.q; END LOOP;

        -- drop sequences
        FOR r IN (SELECT 'DROP SEQUENCE IF EXISTS public.' || quote_ident(sequence_name) || ' CASCADE;' AS q
                  FROM information_schema.sequences WHERE sequence_schema='public')
        LOOP EXECUTE r.q; END LOOP;

        -- drop types
        FOR r IN (
          SELECT 'DROP TYPE IF EXISTS public.' || quote_ident(t.typname) || ' CASCADE;' AS q
          FROM pg_type t
          JOIN pg_namespace n ON n.oid = t.typnamespace
          WHERE n.nspname='public' AND t.typcategory NOT IN ('A','P') AND t.typtype IN ('e','c','d') -- enum/composite/domain
        )
        LOOP EXECUTE r.q; END LOOP;
      END$$;`;
    await client.query(q);
    await client.query('COMMIT');
    console.log('✅ Dropped all objects in schema "public" (fallback)');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ dropAllObjectsFallback failed:', e.message);
    throw e;
  } finally {
    client.release();
  }
}

async function createNeededTables() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // === только то, что нужно серверу ===
    await client.query(`
      CREATE TABLE IF NOT EXISTS keys (
        key_name    TEXT PRIMARY KEY,
        hwid        TEXT DEFAULT NULL,
        expires     BIGINT NOT NULL,
        scripts     JSONB DEFAULT '[]',
        banned      BOOLEAN DEFAULT FALSE,
        ban_reason  TEXT,
        banned_at   BIGINT,
        banned_hwid TEXT,
        banned_ip   TEXT,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS banned_hwids (
        hwid          TEXT PRIMARY KEY,
        reason        TEXT,
        banned_at     BIGINT,
        banned_by_key TEXT,
        banned_ip     TEXT
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS activity_log (
        id         BIGSERIAL PRIMARY KEY,
        event_type TEXT,
        ip         TEXT,
        hwid       TEXT,
        key_name   TEXT,
        details    TEXT,
        timestamp  BIGINT
      );
    `);

    // Для Discord-бота (ключи/пользователи). Удали, если бот сейчас не нужен:
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        discord_id           TEXT PRIMARY KEY,
        discord_username     TEXT,
        subscription_expires BIGINT DEFAULT 0,
        hwid                 TEXT,
        banned               BOOLEAN DEFAULT FALSE,
        ban_reason           TEXT,
        resets_left          INT DEFAULT 3,
        scripts              JSONB DEFAULT '[]',
        last_login           BIGINT,
        created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS invite_keys (
        key         TEXT PRIMARY KEY,
        days        INT NOT NULL,
        uses_left   INT NOT NULL,
        expires_at  BIGINT,
        scripts     JSONB DEFAULT '[]',
        note        TEXT,
        revoked     BOOLEAN DEFAULT FALSE,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Индексы
    await client.query(`CREATE INDEX IF NOT EXISTS idx_keys_expires  ON keys(expires);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_keys_banned   ON keys(banned);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_log_ts        ON activity_log(timestamp);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_exp     ON users(subscription_expires);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_banned  ON users(banned);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_inv_keys_exp  ON invite_keys(expires_at);`);

    await client.query('COMMIT');
    console.log('✅ Created ONLY required tables');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ createNeededTables failed:', e.message);
    throw e;
  } finally {
    client.release();
  }
}

async function initializeSchema() {
  console.log(`ℹ INIT_MODE=${INIT_MODE}`);

  if (INIT_MODE === 'reset') {
    // Жёсткий сброс схемы с фолбэком
    try {
      await hardResetPublicSchema();
    } catch {
      console.warn('⚠ hardResetPublicSchema unavailable, trying fallback…');
      await dropAllObjectsFallback();
    }
    await createNeededTables();
    return;
  }

  // migrate (по умолчанию) — просто ensure
  await createNeededTables();
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
function sealForHWID(hwid, obj) {
  const json = JSON.stringify(obj);
  const blob = xorEncrypt(json, hwid);                // уже есть xorEncrypt
  const sig  = hmacMd5LuaCompat(SECRET_KEY, blob);    // уже есть hmacMd5LuaCompat
  return { blob, sig };
}

// Распаковать, зная токен → получаем hwid из tokens
function unsealFromToken(token, blob, sig) {
  const tokenHash = sha256(token);
  const tdata = tokens.get(tokenHash);
  if (!tdata) return { error: 'Bad token' };
  if (!blob || !sig) return { error: 'Missing blob/sig' };
  const expSig = hmacMd5LuaCompat(SECRET_KEY, blob);
  if (expSig !== sig) return { error: 'Bad sig' };
  try {
    const json = Buffer.from(blob, 'base64').toString('utf8'); // xorEncrypt отдаёт base64
    // но xorEncrypt → base64 от XOR-буфера. Дешифровать надо как на клиенте (см. ниже).
    // Мы не можем просто base64→utf8: нужно обратный XOR. Сделаем XOR-расшифровку:
    // Реализация зеркальная xorEncrypt:
    const tb = Buffer.from(blob, 'base64'); // это зашифрованный буфер
    const kb = Buffer.from(tdata.hwid, 'utf8');
    const res = Buffer.alloc(tb.length);
    for (let i = 0; i < tb.length; i++) {
      res[i] = tb[i] ^ kb[i % kb.length] ^ (i & 0xFF);
    }
    const fullText = res.toString('utf8');
    // с обеих сторон у нас паддинг (см. xorEncrypt) — снимаем его:
    const padLen = 32; // 16 байт в hex = 32 символа
    const plain = fullText.slice(padLen, fullText.length - padLen);
    return { tdata, obj: JSON.parse(plain) };
  } catch (e) {
    return { error: 'Decrypt fail' };
  }
}
function sealAuth(hwid, obj) {
  const json = JSON.stringify(obj);
  const blob = xorEncrypt(json, hwid);                  // шифруем от HWID
  const sig  = hmacMd5LuaCompat(SECRET_KEY, hwid + blob); // подпись от сервера
  return { blob, sig };
}

function unsealAuth(hwid, blob, sig) {
  if (!blob || !sig) return { error: 'Missing blob/sig' };
  const expSig = hmacMd5LuaCompat(SECRET_KEY, hwid + blob);
  if (expSig !== sig) return { error: 'Bad sig' };

  // расшифровка «зеркалом» xorEncrypt
  try {
    const tb = Buffer.from(blob, 'base64');
    const kb = Buffer.from(hwid, 'utf8');
    const res = Buffer.alloc(tb.length);
    for (let i = 0; i < tb.length; i++) res[i] = tb[i] ^ kb[i % kb.length] ^ (i & 0xFF);
    const fullText = res.toString('utf8');
    const padLen = 32; // 16 байт hex = 32 символа
    const plain = fullText.slice(padLen, fullText.length - padLen);
    return { obj: JSON.parse(plain) };
  } catch { return { error: 'Decrypt fail' }; }
}

// === RATE LIMIT ===
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  message: { error: 'Rate limit' },
  skip: (req) => (
    req.path === '/load_manifest' ||
    req.path === '/load_chunk'   ||
    req.path === '/x/manifest'   ||
    req.path === '/x/chunk_next'
  )
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
app.post('/auth_x', async (req, res) => {
  const ip = getClientIP(req);
  const ua = req.headers['user-agent'] || 'unknown';
  const { hwid, blob, sig, client_cert_fp } = req.body || {};

  // анти-MITM/пининги как в /auth
  const mitmIndicators = detectMITM(req);
  if (mitmIndicators.length > 0) return res.status(403).json({ error: 'Proxy detected' });
  if (client_cert_fp && EXPECTED_CERT_FINGERPRINT && !constantTimeCompare(client_cert_fp, EXPECTED_CERT_FINGERPRINT)) {
    await logSuspiciousActivity(ip, hwid, null, 'Certificate mismatch', true);
    return res.status(403).json({ error: 'Invalid certificate' });
  }

  try {
    if (!hwid || !blob || !sig) return res.status(400).json({ error: 'Missing params' });

    const un = unsealAuth(hwid, blob, sig);
    if (un.error) return res.status(403).json({ error: un.error });

    const { key, script_name, timestamp, nonce, fp } = un.obj || {};
    if (!key || !script_name || !timestamp || !nonce) return res.status(400).json({ error: 'Missing fields' });

    // опционально сверить client fp из payload
    const expectedFp = md5(`${hwid}:${nonce}:${SECRET_CHECKSUM}`);
    if (!constantTimeCompare(expectedFp, fp || expectedFp)) {
      await logSuspiciousActivity(ip, hwid, key, 'Bad FP (blob)', true);
      return res.status(403).json({ error: 'Bad FP' });
    }

    // остальная логика — 1:1 как в /auth (бан, рейтлимит, таймстамп/реплей)
    if (await isHwidBanned(hwid)) return res.status(403).json({ error: 'Banned' });
    if (!checkHwidRateLimit(hwid)) return res.status(429).json({ error: 'Too many requests' });

    const reqTime = parseInt(timestamp);
    const now = Date.now();
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 30000) return res.status(403).json({ error: 'Timestamp' });

    const nonceKey = `${hwid}:${timestamp}:${nonce}`;
    if (nonces.has(nonceKey)) {
      await logSuspiciousActivity(ip, hwid, key, 'Replay attack', true);
      return res.status(403).json({ error: 'Replay' });
    }
    nonces.set(nonceKey, now);

    // подпись как раньше
    const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
    if (!constantTimeCompare(un.obj.signature || '', expectedSig)) {
      await logSuspiciousActivity(ip, hwid, key, 'Bad sig');
      return res.status(403).json({ error: 'Bad sig' });
    }

    // проверка ключа/скрипта/срока/привязка HWID (тож самое что в /auth)
    const keyEntry = await getKeyByName(key);
    if (!keyEntry) return res.status(403).json({ error: 'Invalid key' });
    if (keyEntry.banned) return res.status(403).json({ error: 'Banned key' });

    const keyExpiry = parseInt(keyEntry.expires) || 0;
    if (keyExpiry === 0 || Math.floor(now / 1000) >= keyExpiry) return res.status(403).json({ error: 'Expired' });

    const keyHwid = String(keyEntry.hwid || "*");
    if (keyHwid === "*" || keyHwid === "" || keyHwid === null) await updateKeyHwid(keyEntry.key_name, hwid);
    else if (keyHwid !== hwid) return res.status(403).json({ error: 'HWID mismatch' });

    if (!checkScriptAllowed(keyEntry, script_name)) return res.status(403).json({ error: 'Script not allowed' });

    // выдаём токен (как в /auth)
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = sha256(token);
    const tokenData = { hwid, ip, ua, key: keyEntry.key_name, script_name, expires: now + 15000, used: false, created: now };
    tokens.set(tokenHash, tokenData);

    // но ответ - тоже «запечатанный»
    const out = sealAuth(hwid, {
      token: xorEncrypt(token, hwid),  // можешь и прямо token, но так совместимо
      expires_in: 5,
      server_fp: (EXPECTED_CERT_FINGERPRINT || '').trim()
    });
    return signedJson(res, out);

  } catch (e) {
    await logSuspiciousActivity(ip, hwid, null, 'Server error');
    return res.status(500).json({ error: 'Internal error' });
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

app.post('/x/manifest', async (req, res) => {
  const ip = getClientIP(req);
  const { token, blob, sig } = req.body || {};
  if (!token) return res.status(400).json({ error: 'No token' });

  // Распаковать вход (parts и любые метаданные внутри blob)
  const un = unsealFromToken(token, blob, sig);
  if (un.error) return res.status(403).json({ error: un.error });
  const { tdata, obj } = un;
  if (Date.now() > tdata.expires) return res.status(403).json({ error: 'Expired' });
  // мягкая IP-проверка (не режем)
  if (tdata.ip !== ip) console.warn(`⚠ IP changed on /x/manifest: expected=${tdata.ip}, got=${ip}`);

  try {
    const scriptPath = SCRIPT_REGISTRY[tdata.script_name];
    if (!scriptPath) return res.status(404).json({ error: 'Script not found' });

    const scriptCode = await fetchGitLabScript(scriptPath);
    if (!scriptCode) return res.status(502).json({ error: 'Upstream error' });

    const wanted = Number(obj?.parts || 50) || 50;
    const slices = splitTextDeterministic(scriptCode, wanted);
    // заранее шифруем и подписываем
    const items = slices.map((plain, i) => {
      const enc = xorEncrypt(plain, tdata.hwid);
      return { idx: i + 1, data: enc, sig: hmacMd5LuaCompat(SECRET_KEY, enc) };
    });
    shuffleInPlace(items);

    chunkStores.set(sha256(token), {
      items,
      served: new Set(),
      hwid: tdata.hwid,
      key: tdata.key,
      ip,
      created: Date.now()
    });

    // продлим TTL, чтобы успеть скачать всё
    tdata.expires = Date.now() + 120000;

    // ответ только в зашифрованном виде — снаружи ничего лишнего
    const out = sealForHWID(tdata.hwid, { count: items.length });
    return signedJson(res, out);
  } catch (e) {
    console.error('X_MANIFEST ERROR:', e);
    return res.status(500).json({ error: 'Internal error' });
  }
});
app.post('/x/chunk_next', async (req, res) => {
  const ip = getClientIP(req);
  const { token, blob, sig } = req.body || {};
  if (!token) return res.status(400).json({ error: 'No token' });

  const un = unsealFromToken(token, blob, sig);
  if (un.error) return res.status(403).json({ error: un.error });
  const { tdata } = un;

  if (Date.now() > tdata.expires) return res.status(403).json({ error: 'Expired' });
  if (tdata.ip !== ip) console.warn(`⚠ IP changed on /x/chunk_next: expected=${tdata.ip}, got=${ip}`);

  const store = chunkStores.get(sha256(token));
  if (!store) return res.status(404).json({ error: 'No manifest' });

  try {
    // найдём любой неотданный кусок
    const candidates = store.items.filter(x => !store.served.has(x.idx));
    if (candidates.length === 0) {
      // всё отдали — чистим и гасим токен
      chunkStores.delete(sha256(token));
      tokens.delete(sha256(token));
      const outDone = sealForHWID(tdata.hwid, { done: true });
      return signedJson(res, outDone);
    }

    const pick = candidates[Math.floor(Math.random() * candidates.length)];
    store.served.add(pick.idx);

    // Запечатаем ответ: спрячем и idx, и data, и sig
    const out = sealForHWID(tdata.hwid, {
      pos: pick.idx,       // позиция (idx) скрыта внутри blob
      data: pick.data,     // шифртекст части (ещё один уровень XOR от нас)
      sig:  pick.sig       // подпись части (HMAC от data)
    });
    return signedJson(res, out);

  } catch (e) {
    console.error('X_CHUNK_NEXT ERROR:', e);
    return res.status(500).json({ error: 'Internal error' });
  }
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
app.post('/bot/create-key', async (req, res) => {
  try {
    if (!requireBotAdmin(req, res)) return;

    const days   = parseInt(req.body?.days, 10);
    const scripts= Array.isArray(req.body?.scripts) ? req.body.scripts : [];
    const note   = req.body?.note || null;

    if (!days || days < 1 || days > 365) return res.status(400).json({ error: 'Bad days' });

    const keyName = require('crypto').randomBytes(8).toString('hex').toUpperCase();
    const expires = Math.floor(Date.now() / 1000) + days * 86400; // сек

    await pool.query(`
      INSERT INTO keys (key_name, hwid, expires, scripts, banned, ban_reason, created_at, updated_at)
      VALUES ($1, NULL, $2, $3, FALSE, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `, [keyName, expires, JSON.stringify(scripts)]);

    return res.json({
      key: keyName,
      days,
      expires_at: expires * 1000,
      scripts,
      note
    });
  } catch (e) {
    console.error('create-key error:', e);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// /bot/revoke-key — пометить ключ забаненным (лоадер перестанет пускать)
app.post('/bot/revoke-key', async (req, res) => {
  try {
    if (!requireBotAdmin(req, res)) return;
    const key = String(req.body?.key || '');
    if (!key) return res.status(400).json({ error: 'Missing key' });

    const r = await pool.query(
      `UPDATE keys SET banned = TRUE, ban_reason = COALESCE($2,'revoked'), updated_at = CURRENT_TIMESTAMP
       WHERE LOWER(key_name)=LOWER($1)`,
      [key, req.body?.reason || null]
    );

    if (r.rowCount === 0) return res.status(404).json({ error: 'Key not found' });
    return res.json({ ok: true, updated: r.rowCount });
  } catch (e) {
    console.error('revoke-key error:', e);
    return res.status(500).json({ error: 'Internal error' });
  }
});
// === BLOCK INVALID ===
app.get('/auth', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,null,'GET /auth'); res.status(405).json({error:'POST only'}); });
app.get('/load', (req,res)=>{ logSuspiciousActivity(getClientIP(req),null,null,'GET /load'); res.status(405).json({error:'POST only'}); });
app.use((req,res)=>res.status(404).json({error:'Not found'}));

// === START ===
app.listen(PORT, async () => {
  await initializeSchema();
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













