// ╔════════════════════════════════════════════════════════════════╗
// ║  ULTRA SECURE LOADER V3.0 - DISCORD AUTH + CHUNKED LOADING    ║
// ║  • Discord OAuth2 authentication                               ║
// ║  • Chunked script delivery (random order, AES encrypted)       ║
// ║  • HWID binding per Discord account                            ║
// ║  • Anti-debugging & anti-tampering                             ║
// ╚════════════════════════════════════════════════════════════════╝

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));
app.use(express.static('public')); // для OAuth callback страницы

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY || "k8Jf2mP9xLq4nR7vW3sT6yH5bN8aZ1cD";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || "";
const DATABASE_URL = process.env.DATABASE_URL;

// Discord OAuth2
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "http://localhost:8080/auth/discord/callback";
const OAUTH_STATE_SECRET = process.env.OAUTH_STATE_SECRET || crypto.randomBytes(32).toString('hex');

// ═══════════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════
function md5(s) {
  return crypto.createHash('md5').update(s, 'utf8').digest('hex');
}

function hmacMd5(key, msg) {
  const block = 64;
  if (key.length > block) key = md5(key);
  
  const kb = Buffer.from(key, 'utf8');
  let ipad = '';
  let opad = '';
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
  const sig = hmacMd5(SECRET_KEY, body);
  res.set('X-Resp-Sig', sig);
  res.type('application/json').send(body);
}

function constantTimeCompare(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ═══════════════════════════════════════════════════════════════
// AES-256-GCM ENCRYPTION (для chunks)
// ═══════════════════════════════════════════════════════════════
function aesEncrypt(text, hwid) {
  const algorithm = 'aes-256-gcm';
  
  const key = crypto.pbkdf2Sync(
    SECRET_KEY + hwid,
    'loader_v3_salt',
    100000,
    32,
    'sha256'
  );
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  // Добавляем padding для обфускации размера
  const padding = crypto.randomBytes(32).toString('hex');
  const paddedText = padding + text + padding;
  
  let encrypted = cipher.update(paddedText, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, encrypted, authTag]);
  
  return combined.toString('base64');
}

// ═══════════════════════════════════════════════════════════════
// POSTGRESQL
// ═══════════════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL error:', err);
});

async function runMigrations() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      discord_id TEXT PRIMARY KEY,
      discord_username TEXT,
      discord_avatar TEXT,
      hwid TEXT,
      subscription_expires BIGINT NOT NULL,
      max_hwid_resets INTEGER DEFAULT 3,
      hwid_resets_used INTEGER DEFAULT 0,
      scripts JSONB DEFAULT '["kaelis.gs"]',
      banned BOOLEAN DEFAULT FALSE,
      ban_reason TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login BIGINT
    );
    
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL,
      hwid TEXT NOT NULL,
      expires BIGINT NOT NULL,
      last_heartbeat BIGINT,
      active_scripts JSONB DEFAULT '[]',
      ip TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS oauth_states (
      state TEXT PRIMARY KEY,
      hwid TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      expires BIGINT NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS activity_log (
      id BIGSERIAL PRIMARY KEY,
      event_type TEXT,
      discord_id TEXT,
      hwid TEXT,
      ip TEXT,
      details TEXT,
      timestamp BIGINT
    );
    
    CREATE INDEX IF NOT EXISTS idx_users_hwid ON users(hwid);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
    CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_oauth_expires ON oauth_states(expires);
  `);
  console.log('✅ Database migrations applied');
  await pool.query(`
  -- activity_log: добавляем недостающие колонки безопасно
  ALTER TABLE activity_log
    ADD COLUMN IF NOT EXISTS discord_id TEXT,
    ADD COLUMN IF NOT EXISTS hwid       TEXT,
    ADD COLUMN IF NOT EXISTS ip         TEXT,
    ADD COLUMN IF NOT EXISTS details    TEXT,
    ADD COLUMN IF NOT EXISTS event_type TEXT,
    ADD COLUMN IF NOT EXISTS timestamp  BIGINT;

  -- на всякий случай индексы (idempotent)
  CREATE INDEX IF NOT EXISTS idx_activity_discord ON activity_log(discord_id);
  CREATE INDEX IF NOT EXISTS idx_activity_time    ON activity_log(timestamp);

  -- полезные индексы для users/sessions (быстрее проверки)
  CREATE INDEX IF NOT EXISTS idx_users_discord    ON users(discord_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_discord ON sessions(discord_id);
`);
}

// ═══════════════════════════════════════════════════════════════
// DISCORD ALERTS
// ═══════════════════════════════════════════════════════════════
async function sendAlert(message, level = 'warning') {
  if (!DISCORD_WEBHOOK) return;
  
  const colors = {
    info: 3447003,
    warning: 16776960,
    critical: 15158332,
    success: 3066993
  };
  
  try {
    await fetch(DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `🔐 Loader Alert [${level.toUpperCase()}]`,
          description: message,
          color: colors[level] || colors.warning,
          timestamp: new Date().toISOString(),
          footer: { text: 'Secure Loader V3' }
        }]
      })
    });
  } catch (e) {
    console.error('Alert error:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════
function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || 
          req.headers['x-real-ip'] || 
          req.socket.remoteAddress || 
          'unknown').split(',')[0].trim();
}

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

async function logActivity(eventType, discordId, hwid, ip, details) {
  try {
    await pool.query(
      `INSERT INTO activity_log (event_type, discord_id, hwid, ip, details, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [eventType, discordId, hwid, ip, details, Date.now()]
    );
  } catch (e) {
    console.error('❌ Log error:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// SCRIPT CHUNKING SYSTEM
// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// SCRIPT CHUNKING SYSTEM (загрузка напрямую с GitLab RAW URL)
// ═══════════════════════════════════════════════════════════════
const SCRIPT_CHUNKS = new Map();

/**
 * Загружает Lua-скрипт с GitLab RAW-ссылки и разбивает его на чанки.
 */
async function loadAndChunkFromGit(scriptId, rawUrl) {
  try {
    console.log(`📡 Fetching ${scriptId} from GitLab RAW...`);
    const res = await fetch(rawUrl);

    if (!res.ok) {
      console.error(`❌ Failed to fetch ${scriptId}: ${res.status} ${res.statusText}`);
      return false;
    }

    const scriptCode = await res.text();

    // === Разбиваем на чанки ===
    const CHUNK_SIZE = 500; // можешь менять размер
    const chunks = [];

    for (let i = 0; i < scriptCode.length; i += CHUNK_SIZE) {
      chunks.push(scriptCode.substring(i, i + CHUNK_SIZE));
    }

    const hash = crypto.createHash('sha256').update(scriptCode).digest('hex');

    SCRIPT_CHUNKS.set(scriptId, {
      chunks,
      total: chunks.length,
      hash,
      size: scriptCode.length
    });

    console.log(`✅ ${scriptId}: ${chunks.length} chunks (${scriptCode.length} bytes, sha256=${hash.slice(0, 8)}…)`);
    return true;
  } catch (e) {
    console.error(`❌ Error loading ${scriptId}:`, e.message);
    return false;
  }
}

/**
 * Подготовка всех скриптов.
 * Здесь ты указываешь URL каждого скрипта.
 */
async function prepareAllScripts() {
  console.log('\n📦 Preparing scripts (remote)...');

  // === твой скрипт ===
  await loadAndChunkFromGit(
    'kaelis.gs',
    'https://gitlab.com/fwafsjafkawf0/fwafsjafkawf0koop/-/raw/main/test12.lua'
  );

  // можешь добавить другие:
  // await loadAndChunkFromGit('another.gs', 'https://gitlab.com/.../another.lua');
}

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING
// ═══════════════════════════════════════════════════════════════
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many auth attempts' }
});

const chunkLimiter = rateLimit({
  windowMs: 1000,
  max: 30,
  message: { error: 'Slow down chunk requests' }
});

app.use('/auth/discord', authLimiter);
app.use('/script/chunk', chunkLimiter);

// ═══════════════════════════════════════════════════════════════
// CLEANUP (every 5 min)
// ═══════════════════════════════════════════════════════════════
setInterval(async () => {
  const now = Date.now();
  try {
    await pool.query('DELETE FROM sessions WHERE expires < $1', [now]);
    await pool.query('DELETE FROM oauth_states WHERE expires < $1', [now]);
    
    const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);
    await pool.query('DELETE FROM activity_log WHERE timestamp < $1', [thirtyDaysAgo]);
  } catch (e) {
    console.error('❌ Cleanup error:', e.message);
  }
}, 5 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════
app.get('/health', async (req, res) => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    
    res.json({
      status: 'online',
      database: 'connected',
      version: '3.0',
      scripts_loaded: SCRIPT_CHUNKS.size,
      auth_method: 'discord_oauth2'
    });
  } catch (e) {
    res.status(500).json({
      status: 'degraded',
      database: 'error',
      error: e.message
    });
  }
});

// ═══════════════════════════════════════════════════════════════
// DISCORD OAUTH2 - STEP 1: Initiate Login
// ═══════════════════════════════════════════════════════════════
app.post('/auth/discord/init', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Verify signature
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    await logActivity('oauth_init_failed', null, hwid, ip, 'Bad signature');
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  try {
    // Generate OAuth state
    const state = crypto.randomBytes(32).toString('hex');
    const statePayload = md5(state + hwid + OAUTH_STATE_SECRET);
    
    // Store state
    await pool.query(
      `INSERT INTO oauth_states (state, hwid, created_at, expires)
       VALUES ($1, $2, $3, $4)`,
      [statePayload, hwid, Date.now(), Date.now() + 5 * 60 * 1000] // 5 min expiry
    );
    
    // Generate Discord OAuth URL
    const params = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      redirect_uri: DISCORD_REDIRECT_URI,
      response_type: 'code',
      scope: 'identify',
      state: statePayload
    });
    
    const authUrl = `https://discord.com/api/oauth2/authorize?${params.toString()}`;
    
    await logActivity('oauth_init', null, hwid, ip, 'OAuth initiated');
    
    signedJson(res, {
      auth_url: authUrl,
      state: statePayload,
      expires_in: 300
    });
  } catch (e) {
    console.error('❌ OAuth init error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// DISCORD OAUTH2 - STEP 2: Handle Callback
// ═══════════════════════════════════════════════════════════════
app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.send('<h1>❌ Invalid callback</h1>');
  }
  
  try {
    // Verify state
    const stateResult = await pool.query(
      'SELECT hwid FROM oauth_states WHERE state = $1 AND expires > $2',
      [state, Date.now()]
    );
    
    if (stateResult.rows.length === 0) {
      return res.send('<h1>❌ Invalid or expired state</h1>');
    }
    
    const hwid = stateResult.rows[0].hwid;
    
    // Exchange code for token
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      return res.send('<h1>❌ Failed to get access token</h1>');
    }
    
    // Get user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    
    const userData = await userResponse.json();
    
    if (!userData.id) {
      return res.send('<h1>❌ Failed to get user info</h1>');
    }
    
    // Check if user exists and has subscription
    const userResult = await pool.query(
      'SELECT * FROM users WHERE discord_id = $1',
      [userData.id]
    );
    
    if (userResult.rows.length === 0) {
      return res.send(`
        <h1>❌ No subscription found</h1>
        <p>Discord: ${userData.username}</p>
        <p>Please contact an administrator to get access.</p>
      `);
    }
    
    const user = userResult.rows[0];
    
    // Check banned
    if (user.banned) {
      return res.send(`
        <h1>❌ Account banned</h1>
        <p>Reason: ${user.ban_reason || 'Unknown'}</p>
      `);
    }
    
    // Check subscription
    if (user.subscription_expires < Date.now()) {
      return res.send(`
        <h1>❌ Subscription expired</h1>
        <p>Please renew your subscription.</p>
      `);
    }
    
    // Check HWID
    if (user.hwid && user.hwid !== hwid) {
      return res.send(`
        <h1>❌ HWID Mismatch</h1>
        <p>This account is already bound to another PC.</p>
        <p>Resets left: ${user.max_hwid_resets - user.hwid_resets_used}</p>
        <p>Contact support for HWID reset.</p>
      `);
    }
    
    // Bind HWID if first time
    if (!user.hwid) {
      await pool.query(
        'UPDATE users SET hwid = $1, updated_at = CURRENT_TIMESTAMP WHERE discord_id = $2',
        [hwid, userData.id]
      );
      
      await sendAlert(
        `**New HWID Bind**\n` +
        `**User:** ${userData.username} (${userData.id})\n` +
        `**HWID:** ${hwid}`,
        'info'
      );
    }
    
    // Create session
    const sessionId = generateToken(32);
    const sessionExp = Date.now() + (24 * 60 * 60 * 1000); // 24h
    
    await pool.query(
      `INSERT INTO sessions (session_id, discord_id, hwid, expires, last_heartbeat, ip)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionId, userData.id, hwid, sessionExp, Date.now(), getClientIP(req)]
    );
    
    // Update last login
    await pool.query(
      'UPDATE users SET last_login = $1, discord_username = $2, discord_avatar = $3 WHERE discord_id = $4',
      [Date.now(), userData.username, userData.avatar, userData.id]
    );
    
    // Delete used state
    await pool.query('DELETE FROM oauth_states WHERE state = $1', [state]);
    
    await logActivity('login_success', userData.id, hwid, getClientIP(req), userData.username);
    
    // Return success page with session data (loader will poll /auth/discord/poll)
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login Success</title>
        <style>
          body { font-family: Arial; text-align: center; padding: 50px; background: #2c2f33; color: #fff; }
          h1 { color: #43b581; }
          .info { background: #23272a; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 500px; }
        </style>
      </head>
      <body>
        <h1>✅ Login Successful!</h1>
        <div class="info">
          <p><strong>Discord:</strong> ${userData.username}</p>
          <p><strong>Session:</strong> ${sessionId.substring(0, 16)}...</p>
          <p><strong>Expires:</strong> 24 hours</p>
        </div>
        <p>You can close this window now.</p>
        <script>
          // Store session for polling
          localStorage.setItem('loader_session', JSON.stringify({
            session_id: '${sessionId}',
            expires: ${sessionExp},
            discord_username: '${userData.username}',
            hwid: '${hwid}'
          }));
        </script>
      </body>
      </html>
    `);
  } catch (e) {
    console.error('❌ OAuth callback error:', e);
    res.send('<h1>❌ Internal error</h1>');
  }
});

// ═══════════════════════════════════════════════════════════════
// DISCORD OAUTH2 - STEP 3: Poll for Session
// ═══════════════════════════════════════════════════════════════
app.post('/auth/discord/poll', async (req, res) => {
  const { hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  try {
    // Check if session exists for this HWID
    const result = await pool.query(
      `SELECT s.session_id, s.expires, u.discord_username, u.subscription_expires, u.scripts
       FROM sessions s
       JOIN users u ON u.discord_id = s.discord_id
       WHERE s.hwid = $1 AND s.expires > $2
       ORDER BY s.created_at DESC
       LIMIT 1`,
      [hwid, Date.now()]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No session found' });
    }
    
    const session = result.rows[0];
    
    signedJson(res, {
      session_id: session.session_id,
      expires: session.expires,
      subscription_expires: session.subscription_expires,
      scripts: session.scripts || ['kaelis.gs'],
      user_info: {
        discord: session.discord_username
      }
    });
  } catch (e) {
    console.error('❌ Poll error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// SCRIPT META (chunk info)
// ═══════════════════════════════════════════════════════════════
app.post('/script/meta', async (req, res) => {
  const ip = getClientIP(req);
  const { session_id, script_id, hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!session_id || !script_id || !hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp)) {
    return res.status(403).json({ error: 'Invalid fingerprint' });
  }
  
  try {
    // Validate session
    const sessResult = await pool.query(
      `SELECT s.discord_id, u.scripts, u.banned
       FROM sessions s
       JOIN users u ON u.discord_id = s.discord_id
       WHERE s.session_id = $1 AND s.hwid = $2 AND s.expires > $3`,
      [session_id, hwid, Date.now()]
    );
    
    if (sessResult.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid session' });
    }
    
    const session = sessResult.rows[0];
    
    if (session.banned) {
      return res.status(403).json({ error: 'Account banned' });
    }
    
    // Check script access
    const allowedScripts = session.scripts || [];
    if (!allowedScripts.includes(script_id)) {
      return res.status(403).json({ error: 'Script not allowed' });
    }
    
    // Get chunks
    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    // Generate RANDOM chunk order (anti-Fiddler)
    const chunkOrder = [];
    for (let i = 1; i <= scriptData.total; i++) {
      chunkOrder.push(i);
    }
    
    // Fisher-Yates shuffle
    for (let i = chunkOrder.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [chunkOrder[i], chunkOrder[j]] = [chunkOrder[j], chunkOrder[i]];
    }
    
    await logActivity('script_meta', session.discord_id, hwid, ip, script_id);
    
    signedJson(res, {
      total_chunks: scriptData.total,
      chunk_order: chunkOrder.join(','),
      script_hash: scriptData.hash
    });
  } catch (e) {
    console.error('❌ Meta error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// SCRIPT CHUNK (get single chunk)
// ═══════════════════════════════════════════════════════════════
app.post('/script/chunk', async (req, res) => {
  const ip = getClientIP(req);
  const { session_id, script_id, chunk_id, hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!session_id || !script_id || !chunk_id || !hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp)) {
    return res.status(403).json({ error: 'Invalid fingerprint' });
  }
  
  try {
    // Validate session
    const sessResult = await pool.query(
      'SELECT discord_id FROM sessions WHERE session_id = $1 AND hwid = $2 AND expires > $3',
      [session_id, hwid, Date.now()]
    );
    
    if (sessResult.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid session' });
    }
    
    const discordId = sessResult.rows[0].discord_id;
    
    // Get chunk
    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    const chunkIdNum = parseInt(chunk_id);
    if (isNaN(chunkIdNum) || chunkIdNum < 1 || chunkIdNum > scriptData.total) {
      return res.status(400).json({ error: 'Invalid chunk_id' });
    }
    
    const chunkData = scriptData.chunks[chunkIdNum - 1];
    if (!chunkData) {
      return res.status(404).json({ error: 'Chunk not found' });
    }
    
    // Encrypt with AES
    const encrypted = aesEncrypt(chunkData, hwid);
    
    // Log every 10th chunk
    if (chunkIdNum % 10 === 0) {
      await logActivity('chunk_load', discordId, hwid, ip, `${script_id}:${chunk_id}`);
    }
    
    signedJson(res, {
      chunk: encrypted,
      chunk_id: chunkIdNum
    });
  } catch (e) {
    console.error('❌ Chunk error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// HEARTBEAT
// ═══════════════════════════════════════════════════════════════
app.post('/heartbeat', async (req, res) => {
  const { session_id, active_scripts } = req.body || {};
  
  if (!session_id) {
    return res.status(400).json({ error: 'Missing session_id' });
  }
  
  try {
    const result = await pool.query(
      `UPDATE sessions 
       SET last_heartbeat = $1, active_scripts = $2
       WHERE session_id = $3 AND expires > $4
       RETURNING discord_id`,
      [Date.now(), active_scripts ? JSON.parse(`["${active_scripts}"]`) : [], session_id, Date.now()]
    );
    
    if (result.rows.length === 0) {
      return signedJson(res, { action: 'terminate', reason: 'Session expired' });
    }
    
    const discordId = result.rows[0].discord_id;
    
    // Check if banned
    const userResult = await pool.query(
      'SELECT banned FROM users WHERE discord_id = $1',
      [discordId]
    );
    
    if (userResult.rows.length > 0 && userResult.rows[0].banned) {
      return signedJson(res, { action: 'terminate', reason: 'Account banned' });
    }
    
    signedJson(res, { status: 'ok' });
  } catch (e) {
    console.error('❌ Heartbeat error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// TAMPER REPORT
// ═══════════════════════════════════════════════════════════════
app.post('/report/tamper', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, session_id, reason } = req.body || {};
  
  if (!hwid || !reason) {
    return res.status(400).json({ error: 'Missing data' });
  }
  
  try {
    let discordId = null;
    
    if (session_id) {
      const result = await pool.query(
        'SELECT discord_id FROM sessions WHERE session_id = $1',
        [session_id]
      );
      if (result.rows.length > 0) {
        discordId = result.rows[0].discord_id;
      }
    }
    
    // Ban user
    if (discordId) {
      await pool.query(
        `UPDATE users 
         SET banned = TRUE, ban_reason = $1, updated_at = CURRENT_TIMESTAMP
         WHERE discord_id = $2`,
        [reason, discordId]
      );
      
      // Kill sessions
      await pool.query('DELETE FROM sessions WHERE discord_id = $1', [discordId]);
    }
    
    await logActivity('tamper_detected', discordId, hwid, ip, reason);
    
    await sendAlert(
      `**🚨 TAMPER DETECTED**\n` +
      `**Discord ID:** ${discordId || 'unknown'}\n` +
      `**HWID:** ${hwid}\n` +
      `**IP:** ${ip}\n` +
      `**Reason:** ${reason}\n` +
      `**Action:** Account banned`,
      'critical'
    );
    
    res.json({ status: 'reported' });
  } catch (e) {
    console.error('❌ Tamper error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// SESSION END
// ═══════════════════════════════════════════════════════════════
app.post('/session/end', async (req, res) => {
  const { session_id } = req.body || {};
  
  if (session_id) {
    try {
      await pool.query('DELETE FROM sessions WHERE session_id = $1', [session_id]);
    } catch (e) {
      console.error('❌ Session end error:', e);
    }
  }
  
  res.json({ status: 'ok' });
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Create User
// ═══════════════════════════════════════════════════════════════
app.post('/bot/create-user', async (req, res) => {
  const { admin_token, discord_id, discord_username, days, scripts } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!discord_id || !days) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  try {
    const expires = Date.now() + (days * 24 * 60 * 60 * 1000);
    const allowedScripts = scripts || ['kaelis.gs'];
    
    await pool.query(
      `INSERT INTO users (discord_id, discord_username, subscription_expires, scripts)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (discord_id) DO UPDATE
       SET subscription_expires = EXCLUDED.subscription_expires,
           scripts = EXCLUDED.scripts,
           banned = FALSE,
           ban_reason = NULL,
           updated_at = CURRENT_TIMESTAMP`,
      [discord_id, discord_username || 'Unknown', expires, JSON.stringify(allowedScripts)]
    );
    
    await sendAlert(
      `**New User Created**\n` +
      `**Discord:** ${discord_username} (${discord_id})\n` +
      `**Duration:** ${days} days\n` +
      `**Scripts:** ${allowedScripts.join(', ')}`,
      'success'
    );
    
    res.json({ 
      success: true,
      discord_id: discord_id,
      expires: expires
    });
  } catch (e) {
    console.error('❌ Create user error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Check User Info
// ═══════════════════════════════════════════════════════════════
app.post('/bot/check-user', async (req, res) => {
  const { admin_token, discord_id } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!discord_id) {
    return res.status(400).json({ error: 'Missing discord_id' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE discord_id = $1',
      [discord_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    
    res.json({
      discord_id: user.discord_id,
      discord_username: user.discord_username,
      hwid: user.hwid || 'Not bound',
      subscription_expires: user.subscription_expires,
      expires_in_days: Math.floor((user.subscription_expires - Date.now()) / (24 * 60 * 60 * 1000)),
      resets_left: user.max_hwid_resets - user.hwid_resets_used,
      banned: user.banned,
      ban_reason: user.ban_reason,
      last_login: user.last_login,
      scripts: user.scripts
    });
  } catch (e) {
    console.error('❌ Check user error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Reset HWID
// ═══════════════════════════════════════════════════════════════
app.post('/bot/reset-hwid', async (req, res) => {
  const { admin_token, discord_id } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!discord_id) {
    return res.status(400).json({ error: 'Missing discord_id' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE discord_id = $1',
      [discord_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    
    if (user.hwid_resets_used >= user.max_hwid_resets) {
      return res.status(403).json({ error: 'No resets left' });
    }
    
    // Reset HWID
    await pool.query(
      `UPDATE users 
       SET hwid = NULL, hwid_resets_used = hwid_resets_used + 1, updated_at = CURRENT_TIMESTAMP
       WHERE discord_id = $1`,
      [discord_id]
    );
    
    // Kill all sessions
    await pool.query('DELETE FROM sessions WHERE discord_id = $1', [discord_id]);
    
    await sendAlert(
      `**HWID Reset**\n` +
      `**User:** ${user.discord_username} (${discord_id})\n` +
      `**Resets left:** ${user.max_hwid_resets - user.hwid_resets_used - 1}`,
      'warning'
    );
    
    res.json({ 
      success: true,
      resets_left: user.max_hwid_resets - user.hwid_resets_used - 1
    });
  } catch (e) {
    console.error('❌ Reset error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Extend Subscription
// ═══════════════════════════════════════════════════════════════
app.post('/bot/extend-sub', async (req, res) => {
  const { admin_token, discord_id, days } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!discord_id || !days) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE discord_id = $1',
      [discord_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    const currentExp = user.subscription_expires;
    const newExp = Math.max(currentExp, Date.now()) + (days * 24 * 60 * 60 * 1000);
    
    await pool.query(
      'UPDATE users SET subscription_expires = $1, updated_at = CURRENT_TIMESTAMP WHERE discord_id = $2',
      [newExp, discord_id]
    );
    
    await sendAlert(
      `**Subscription Extended**\n` +
      `**User:** ${user.discord_username} (${discord_id})\n` +
      `**Added:** ${days} days`,
      'info'
    );
    
    res.json({ 
      success: true,
      new_expires: newExp
    });
  } catch (e) {
    console.error('❌ Extend sub error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Ban/Unban User
// ═══════════════════════════════════════════════════════════════
app.post('/bot/ban-user', async (req, res) => {
  const { admin_token, discord_id, ban, reason } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!discord_id || ban === undefined) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  try {
    await pool.query(
      `UPDATE users 
       SET banned = $1, ban_reason = $2, updated_at = CURRENT_TIMESTAMP
       WHERE discord_id = $3`,
      [ban, reason || null, discord_id]
    );
    
    // Kill all sessions if banning
    if (ban) {
      await pool.query('DELETE FROM sessions WHERE discord_id = $1', [discord_id]);
    }
    
    await sendAlert(
      `**User ${ban ? 'Banned' : 'Unbanned'}**\n` +
      `**Discord ID:** ${discord_id}\n` +
      (reason ? `**Reason:** ${reason}` : ''),
      ban ? 'warning' : 'info'
    );
    
    res.json({ success: true });
  } catch (e) {
    console.error('❌ Ban user error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// 404 Handler
// ═══════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, async () => {
  console.log(`\n🔐 ═══════════════════════════════════════════`);
  console.log(`   ULTRA SECURE LOADER V3.0 (Discord Auth)`);
  console.log(`   ═══════════════════════════════════════════`);
  console.log(`   ✅ Port: ${PORT}`);
  console.log(`   ✅ Database: PostgreSQL`);
  console.log(`   ✅ Auth: Discord OAuth2 (HWID lock)`);
  console.log(`   ✅ AES-256-GCM: ENABLED`);
  console.log(`   ✅ Chunked Loading: ENABLED`);
  console.log(`   ✅ Heartbeat: 3s intervals`);
  console.log(`═══════════════════════════════════════════\n`);
  
  try {
    await runMigrations();
    
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('✅ Database connection: OK');
  } catch (e) {
    console.error('❌ Database connection failed:', e.message);
    process.exit(1);
  }
  
  await prepareAllScripts();
  console.log('✅ All scripts ready!\n');
});

