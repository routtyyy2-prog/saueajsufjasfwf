// ╔════════════════════════════════════════════════════════════════╗
// ║  ULTRA SECURE LOADER V3.1 - MULTI-LAYER ENCRYPTION            ║
// ║  • Discord OAuth2 authentication                               ║
// ║  • Multi-layer obfuscation encryption                          ║
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
const zlib = require('zlib');
const http = require('http');
const https = require('https');

const AGENT_HTTP  = new http.Agent({ keepAlive: true, maxSockets: 80 });
const AGENT_HTTPS = new https.Agent({ keepAlive: true, maxSockets: 80 });

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));
app.use(express.static('public'));

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY || "k8Jf2mP9xLq4nR7vW3sT6yH5bN8aZ1cD";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const DISCORD_WEBHOOK = process.env.ALERT_WEBHOOK || "";
const DATABASE_URL = process.env.DATABASE_URL;
const CHUNK_SIZE = parseInt(process.env.CHUNK_SIZE || '16324', 10);
const CHUNK_RPS  = parseInt(process.env.CHUNK_RPS  || '120', 10);

const chunkLimiter = rateLimit({
  windowMs: 1000,
  max: CHUNK_RPS,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Slow down chunk requests' }
});

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
// MULTI-LAYER ENCRYPTION
// ═══════════════════════════════════════════════════════════════
function multiLayerEncrypt(buffer, hwid) {
  if (process.env.DISABLE_ENC === '1') {
    return Buffer.concat([Buffer.from('PLAIN0'), buffer]).toString('base64');
  }

  const key1Hash = md5(SECRET_KEY + hwid + 'layer1');
  const key2Hash = md5(SECRET_KEY + hwid + 'layer2');
  const shuffleKey = md5(SECRET_KEY + hwid + 'shuffle');
  
  // Layer 1: Add random salt
  const salt = crypto.randomBytes(16);
  let data = Buffer.concat([salt, buffer]);
  
  // Layer 2: XOR with key1
  const key1Bytes = Buffer.from(key1Hash, 'hex');
  for (let i = 0; i < data.length; i++) {
    const keyIdx = i % key1Bytes.length;
    const offset = (i % 256);
    data[i] ^= key1Bytes[keyIdx] ^ offset;
  }
  
  // Layer 3: Byte shuffle
  const shuffled = Buffer.alloc(data.length);
  const shuffleBytes = Buffer.from(shuffleKey, 'hex');
  
  for (let i = 0; i < data.length; i++) {
    const shuffleIdx = shuffleBytes[i % shuffleBytes.length];
    const newPos = (i + shuffleIdx) % data.length;
    shuffled[newPos] = data[i];
  }
  
  // Layer 4: XOR with key2
  const key2Bytes = Buffer.from(key2Hash, 'hex');
  for (let i = 0; i < shuffled.length; i++) {
    const keyIdx = (shuffled.length - i - 1) % key2Bytes.length;
    shuffled[i] ^= key2Bytes[keyIdx];
  }
  
  return shuffled.toString('base64');
}

function encryptChunk(data, hwid) {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return multiLayerEncrypt(buffer, hwid);
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
  const client = await pool.connect();
  try {
    const reset = process.env.RESET_DB === '1';
    console.log(reset ? '🧨 FULL RESET (dropping all tables)...' : '🧩 Running safe migrations...');

    await client.query('BEGIN');

    if (reset) {
      await client.query(`
        DROP TABLE IF EXISTS sessions      CASCADE;
        DROP TABLE IF EXISTS oauth_states  CASCADE;
        DROP TABLE IF EXISTS activity_log  CASCADE;
        DROP TABLE IF EXISTS invite_keys   CASCADE;
        DROP TABLE IF EXISTS users         CASCADE;
      `);
    }

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        discord_id            TEXT PRIMARY KEY,
        discord_username      TEXT,
        discord_avatar        TEXT,
        hwid                  TEXT,
        subscription_expires  BIGINT NOT NULL,
        max_hwid_resets       INTEGER DEFAULT 3,
        hwid_resets_used      INTEGER DEFAULT 0,
        scripts               JSONB   DEFAULT '["kaelis.gs"]'::jsonb,
        banned                BOOLEAN DEFAULT FALSE,
        ban_reason            TEXT,
        created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login            BIGINT
      );

      CREATE TABLE IF NOT EXISTS sessions (
        session_id      TEXT PRIMARY KEY,
        discord_id      TEXT NOT NULL,
        hwid            TEXT NOT NULL,
        expires         BIGINT NOT NULL,
        last_heartbeat  BIGINT,
        active_scripts  JSONB   DEFAULT '[]'::jsonb,
        ip              TEXT,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS oauth_states (
        state       TEXT PRIMARY KEY,
        hwid        TEXT NOT NULL,
        created_at  BIGINT NOT NULL,
        expires     BIGINT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS activity_log (
        id         BIGSERIAL PRIMARY KEY,
        event_type TEXT,
        discord_id TEXT,
        hwid       TEXT,
        ip         TEXT,
        details    TEXT,
        timestamp  BIGINT
      );

      CREATE TABLE IF NOT EXISTS invite_keys (
        key_id      TEXT PRIMARY KEY,
        days        INTEGER NOT NULL,
        scripts     JSONB   DEFAULT '["kaelis.gs"]'::jsonb,
        uses_left   INTEGER DEFAULT 1,
        created_by  TEXT,
        created_at  BIGINT NOT NULL,
        expires_at  BIGINT,
        note        TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_users_hwid            ON users(hwid);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires      ON sessions(expires);
      CREATE INDEX IF NOT EXISTS idx_activity_timestamp    ON activity_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_oauth_expires         ON oauth_states(expires);
      CREATE INDEX IF NOT EXISTS idx_activity_discord      ON activity_log(discord_id);
      CREATE INDEX IF NOT EXISTS idx_activity_time         ON activity_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_invite_expires        ON invite_keys(expires_at);
      CREATE INDEX IF NOT EXISTS idx_invite_uses           ON invite_keys(uses_left);
    `);

    await client.query('COMMIT');
    console.log(reset ? '✅ Database fully recreated' : '✅ Safe migrations applied');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ Migration failed:', e);
    throw e;
  } finally {
    client.release();
  }
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
          footer: { text: 'Secure Loader V3.1' }
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
const SCRIPT_CHUNKS = new Map();

function addGlobalPadding(code) {
  const pad = crypto.randomBytes(32).toString('hex');
  return pad + code + pad;
}

async function fetchWithRetries(url, opts = {}, attempts = 4) {
  let err;
  const agent = url.startsWith('https') ? AGENT_HTTPS : AGENT_HTTP;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        agent,
        headers: { 'User-Agent': 'secure-loader/3.1', ...(opts.headers || {}) },
        ...opts,
      });
      if (res.ok) return res;
      if (![403, 429, 500, 502, 503, 504].includes(res.status))
        throw new Error(`${res.status} ${res.statusText}`);
      err = new Error(`${res.status} ${res.statusText}`);
    } catch (e) { err = e; }
    await new Promise(r => setTimeout(r, 250 * (2 ** i)));
  }
  throw err;
}

async function getScriptCodeFromEnv() {
  const RAW_URL   = process.env.REPO_RAW_URL || '';
  const PROJ_ID   = process.env.GITLAB_PROJECT_ID || '';
  const FILE_PATH = process.env.GITLAB_FILE_PATH || 'test12.lua';
  const REF       = process.env.GITLAB_BRANCH || 'main';
  const TOKEN     = process.env.GITLAB_TOKEN || '';

  if (PROJ_ID && FILE_PATH && TOKEN) {
    const encPath = encodeURIComponent(FILE_PATH);
    const api = `https://gitlab.com/api/v4/projects/${PROJ_ID}/repository/files/${encPath}/raw?ref=${encodeURIComponent(REF)}`;
    const res = await fetchWithRetries(api, { headers: { 'PRIVATE-TOKEN': TOKEN } });
    return await res.text();
  }

  if (RAW_URL) {
    const headers = TOKEN ? { 'PRIVATE-TOKEN': TOKEN } : {};
    const res = await fetchWithRetries(RAW_URL, { headers });
    return await res.text();
  }

  throw new Error('No source configured: set GITLAB_* or REPO_RAW_URL');
}

function chunkAndStore(scriptId, code) {
  const padded = addGlobalPadding(code);
  const compressed = zlib.brotliCompressSync(Buffer.from(padded, 'utf8'));

  const chunks = [];
  for (let i = 0; i < compressed.length; i += CHUNK_SIZE) {
    chunks.push(compressed.subarray(i, i + CHUNK_SIZE));
  }

  const hash = crypto.createHash('sha256').update(code).digest('hex');

  SCRIPT_CHUNKS.set(scriptId, {
    chunks,
    total: chunks.length,
    hash,
    size: code.length,
    br_size: compressed.length
  });

  console.log(`✅ ${scriptId}: ${chunks.length} chunks (br=${compressed.length} bytes, raw=${code.length}, sha256=${hash.slice(0, 8)}…)`);
}

async function prepareAllScripts() {
  console.log('\n📦 Preparing scripts (from env)…');
  const code = await getScriptCodeFromEnv();
  chunkAndStore('kaelis.gs', code);
}

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING
// ═══════════════════════════════════════════════════════════════
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many auth attempts' }
});

app.use('/auth/discord', authLimiter);
app.use('/script/chunk', chunkLimiter);

// ═══════════════════════════════════════════════════════════════
// CLEANUP
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
// ROUTES
// ═══════════════════════════════════════════════════════════════

app.get('/health', async (req, res) => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    
    res.json({
      status: 'online',
      database: 'connected',
      version: '3.1',
      scripts_loaded: SCRIPT_CHUNKS.size,
      auth_method: 'discord_oauth2',
      encryption: 'multi-layer'
    });
  } catch (e) {
    res.status(500).json({
      status: 'degraded',
      database: 'error',
      error: e.message
    });
  }
});

app.post('/auth/discord/init', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    await logActivity('oauth_init_failed', null, hwid, ip, 'Bad signature');
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  try {
    const state = crypto.randomBytes(32).toString('hex');
    const statePayload = md5(state + hwid + OAUTH_STATE_SECRET);
    
    await pool.query(
      `INSERT INTO oauth_states (state, hwid, created_at, expires)
       VALUES ($1, $2, $3, $4)`,
      [statePayload, hwid, Date.now(), Date.now() + 5 * 60 * 1000]
    );
    
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

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.send('<h1>❌ Invalid callback</h1>');
  }
  
  try {
    const stateResult = await pool.query(
      'SELECT hwid FROM oauth_states WHERE state = $1 AND expires > $2',
      [state, Date.now()]
    );
    
    if (stateResult.rows.length === 0) {
      return res.send('<h1>❌ Invalid or expired state</h1>');
    }
    
    const hwid = stateResult.rows[0].hwid;
    
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
    
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    
    const userData = await userResponse.json();
    
    if (!userData.id) {
      return res.send('<h1>❌ Failed to get user info</h1>');
    }
    
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
    
    if (user.banned) {
      return res.send(`
        <h1>❌ Account banned</h1>
        <p>Reason: ${user.ban_reason || 'Unknown'}</p>
      `);
    }
    
    if (user.subscription_expires < Date.now()) {
      return res.send(`
        <h1>❌ Subscription expired</h1>
        <p>Please renew your subscription.</p>
      `);
    }
    
    if (user.hwid && user.hwid !== hwid) {
      return res.send(`
        <h1>❌ HWID Mismatch</h1>
        <p>This account is already bound to another PC.</p>
        <p>Resets left: ${user.max_hwid_resets - user.hwid_resets_used}</p>
        <p>Contact support for HWID reset.</p>
      `);
    }
    
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
    
    const sessionId = generateToken(32);
    const sessionExp = Date.now() + (24 * 60 * 60 * 1000);
    
    await pool.query(
      `INSERT INTO sessions (session_id, discord_id, hwid, expires, last_heartbeat, ip)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionId, userData.id, hwid, sessionExp, Date.now(), getClientIP(req)]
    );
    
    await pool.query(
      'UPDATE users SET last_login = $1, discord_username = $2, discord_avatar = $3 WHERE discord_id = $4',
      [Date.now(), userData.username, userData.avatar, userData.id]
    );
    
    await pool.query('DELETE FROM oauth_states WHERE state = $1', [state]);
    
    await logActivity('login_success', userData.id, hwid, getClientIP(req), userData.username);
    
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
    
    const allowedScripts = session.scripts || [];
    if (!allowedScripts.includes(script_id)) {
      return res.status(403).json({ error: 'Script not allowed' });
    }
    
    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    const chunkOrder = [];
    for (let i = 1; i <= scriptData.total; i++) {
      chunkOrder.push(i);
    }
    
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

app.post('/script/chunk', async (req, res) => {
  const ip = getClientIP(req);
  const { session_id, script_id, chunk_id, hwid, timestamp, nonce, signature } = req.body || {};
  if (!session_id || !script_id || !chunk_id || !hwid || !timestamp || !nonce || !signature)
    return res.status(400).json({ error: 'Missing parameters' });

  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig))
    return res.status(403).json({ error: 'Invalid signature' });

  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp))
    return res.status(403).json({ error: 'Invalid fingerprint' });

  try {
    const sessResult = await pool.query(
      'SELECT discord_id FROM sessions WHERE session_id = $1 AND hwid = $2 AND expires > $3',
      [session_id, hwid, Date.now()]
    );
    if (sessResult.rows.length === 0)
      return res.status(403).json({ error: 'Invalid session' });

    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) return res.status(404).json({ error: 'Script not found' });

    const idx = parseInt(chunk_id, 10) - 1;
    if (isNaN(idx) || idx < 0 || idx >= scriptData.total)
      return res.status(400).json({ error: 'Invalid chunk_id' });

    const part = scriptData.chunks[idx];
    const b64  = encryptChunk(part, hwid);

    if ((idx + 1) % 16 === 0) {
      await logActivity('chunk_load', sessResult.rows[0].discord_id, hwid, ip, `${script_id}:${idx+1}`);
    }

    res.set('Cache-Control', 'no-store');
    res.set('X-Chunk-Id', String(idx+1));

    signedJson(res, {
      chunk: b64,
      chunk_id: idx + 1,
      encoding: 'base64',
      compression: 'br',
      cipher: process.env.DISABLE_ENC === '1' ? 'plain' : 'multi-layer'
    });
  } catch (e) {
    console.error('❌ Chunk error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/script/bundle', async (req, res) => {
  const ip = getClientIP(req);
  const { session_id, script_id, hwid, timestamp, nonce, signature } = req.body || {};
  if (!session_id || !script_id || !hwid || !timestamp || !nonce || !signature)
    return res.status(400).json({ error: 'Missing parameters' });

  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) return res.status(403).json({ error: 'Invalid signature' });

  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp)) return res.status(403).json({ error: 'Invalid fingerprint' });

  try {
    const sessResult = await pool.query(
      `SELECT s.discord_id, u.scripts, u.banned
       FROM sessions s JOIN users u ON u.discord_id = s.discord_id
       WHERE s.session_id = $1 AND s.hwid = $2 AND s.expires > $3`,
      [session_id, hwid, Date.now()]
    );
    if (sessResult.rows.length === 0) return res.status(403).json({ error: 'Invalid session' });
    const session = sessResult.rows[0];
    if (session.banned) return res.status(403).json({ error: 'Account banned' });
    if (!session.scripts.includes(script_id)) return res.status(403).json({ error: 'Script not allowed' });

    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) return res.status(404).json({ error: 'Script not found' });

    const fullBr = Buffer.concat(scriptData.chunks);
    const encryptedB64 = encryptChunk(fullBr, hwid);

    await logActivity('bundle_load', session.discord_id, hwid, ip, `${script_id}:${scriptData.size}`);

    signedJson(res, {
      bundle: encryptedB64,
      encoding: 'base64',
      compression: 'br',
      cipher: process.env.DISABLE_ENC === '1' ? 'plain' : 'multi-layer',
      script_hash: scriptData.hash,
      total_size: scriptData.size
    });
  } catch (e) {
    console.error('❌ Bundle error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

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
    
    if (discordId) {
      await pool.query(
        `UPDATE users 
         SET banned = TRUE, ban_reason = $1, updated_at = CURRENT_TIMESTAMP
         WHERE discord_id = $2`,
        [reason, discordId]
      );
      
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
// BOT API
// ═══════════════════════════════════════════════════════════════

app.post('/bot/create-key', async (req, res) => {
  const { admin_token, days, scripts, uses, expires_in_days, note } = req.body || {};
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  if (!days || days <= 0) {
    return res.status(400).json({ error: 'days required' });
  }
  try {
    const keyId = crypto.randomBytes(16).toString('hex');
    const usesLeft = Math.max(1, parseInt(uses || 1, 10));
    const expiresAt = expires_in_days ? (Date.now() + expires_in_days * 24 * 60 * 60 * 1000) : null;
    const scriptsList = Array.isArray(scripts) && scripts.length ? scripts : ['kaelis.gs'];

    await pool.query(
      `INSERT INTO invite_keys (key_id, days, scripts, uses_left, created_by, created_at, expires_at, note)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [keyId, days, JSON.stringify(scriptsList), usesLeft, 'bot', Date.now(), expiresAt, note || null]
    );

    res.json({
      success: true,
      key: keyId,
      days,
      uses_left: usesLeft,
      expires_at: expiresAt,
      scripts: scriptsList
    });
  } catch (e) {
    console.error('❌ create-key error:', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/bot/revoke-key', async (req, res) => {
  const { admin_token, key } = req.body || {};
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  if (!key) return res.status(400).json({ error: 'key required' });

  try {
    const r = await pool.query('UPDATE invite_keys SET uses_left = 0 WHERE key_id = $1', [key]);
    res.json({ success: true, updated: r.rowCount });
  } catch (e) {
    console.error('❌ revoke-key error:', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/bot/redeem-key', async (req, res) => {
  const { admin_token, discord_id, discord_username, key } = req.body || {};
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  if (!discord_id || !key) {
    return res.status(400).json({ error: 'discord_id and key required' });
  }

  try {
    const now = Date.now();
    const k = await pool.query(
      `SELECT * FROM invite_keys WHERE key_id = $1`, [key]
    );
    if (k.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    const keyRow = k.rows[0];
    if (keyRow.uses_left <= 0) {
      return res.status(400).json({ error: 'Key exhausted' });
    }
    if (keyRow.expires_at && keyRow.expires_at < now) {
      return res.status(400).json({ error: 'Key expired' });
    }

    const days = keyRow.days;
    const scripts = keyRow.scripts || ['kaelis.gs'];

    const u = await pool.query('SELECT * FROM users WHERE discord_id = $1', [discord_id]);

    let newExpires;
    if (u.rows.length > 0) {
      const user = u.rows[0];
      const base = Math.max(user.subscription_expires || 0, now);
      newExpires = base + days * 24 * 60 * 60 * 1000;

      await pool.query(
        `UPDATE users
         SET subscription_expires = $1,
             scripts = $2,
             banned = FALSE,
             ban_reason = NULL,
             discord_username = COALESCE($3, discord_username),
             updated_at = CURRENT_TIMESTAMP
         WHERE discord_id = $4`,
        [newExpires, JSON.stringify(scripts), discord_username || null, discord_id]
      );
    } else {
      newExpires = now + days * 24 * 60 * 60 * 1000;
      await pool.query(
        `INSERT INTO users (discord_id, discord_username, subscription_expires, scripts, created_at, updated_at, banned)
         VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,FALSE)`,
        [discord_id, discord_username || 'Unknown', newExpires, JSON.stringify(scripts)]
      );
    }

    await pool.query(
      `UPDATE invite_keys
       SET uses_left = uses_left - 1
       WHERE key_id = $1`,
      [key]
    );

    res.json({
      success: true,
      new_expires: newExpires,
      days_added: days,
      scripts
    });
  } catch (e) {
    console.error('❌ redeem-key error:', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

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
    
    await pool.query(
      `UPDATE users 
       SET hwid = NULL, hwid_resets_used = hwid_resets_used + 1, updated_at = CURRENT_TIMESTAMP
       WHERE discord_id = $1`,
      [discord_id]
    );
    
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

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, async () => {
  console.log(`\n🔐 ═══════════════════════════════════════════`);
  console.log(`   ULTRA SECURE LOADER V3.1`);
  console.log(`   ═══════════════════════════════════════════`);
  console.log(`   ✅ Port: ${PORT}`);
  console.log(`   ✅ Database: PostgreSQL`);
  console.log(`   ✅ Auth: Discord OAuth2 (HWID lock)`);
  console.log(`   ✅ Encryption: Multi-Layer`);
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
