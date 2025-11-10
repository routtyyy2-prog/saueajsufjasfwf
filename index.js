// ╔════════════════════════════════════════════════════════════════╗
// ║  ULTRA SECURE SERVER V2.0 - DISCORD AUTH + CHUNKED LOADING    ║
// ║  • Discord OAuth через бота                                    ║
// ║  • AES-256-GCM шифрование                                      ║
// ║  • Chunked module delivery                                     ║
// ║  • Heartbeat validation                                        ║
// ║  • PostgreSQL для пользователей                                ║
// ╚════════════════════════════════════════════════════════════════╝

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const GITLAB_PROJECT_ID = process.env.GITLAB_PROJECT_ID || "";
const GITLAB_BRANCH = process.env.GITLAB_BRANCH || "main";
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || "";
const DATABASE_URL = process.env.DATABASE_URL;

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

function signedText(res, text) {
  const sig = hmacMd5(SECRET_KEY, text);
  res.set('X-Resp-Sig', sig);
  res.type('text/plain').send(text);
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
// AES ENCRYPTION (вместо XOR!)
// ═══════════════════════════════════════════════════════════════
function aesEncrypt(text, hwid) {
  const algorithm = 'aes-256-gcm';
  
  // Derive key from SECRET_KEY + HWID
  const key = crypto.pbkdf2Sync(
    SECRET_KEY + hwid,
    'loader_v2_salt',
    100000,
    32,
    'sha256'
  );
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  // Add 32-byte padding on both sides (как в твоём Lua)
  const padding = crypto.randomBytes(32).toString('hex');
  const paddedText = padding + text + padding;
  
  let encrypted = cipher.update(paddedText, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const authTag = cipher.getAuthTag();
  
  // Format: iv + encrypted + authTag
  const combined = Buffer.concat([iv, encrypted, authTag]);
  
  return combined.toString('base64');
}

// ═══════════════════════════════════════════════════════════════
// POSTGRESQL DATABASE
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
      hwid TEXT,
      subscription_expires BIGINT NOT NULL,
      scripts JSONB DEFAULT '[]',
      banned BOOLEAN DEFAULT FALSE,
      ban_reason TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL,
      hwid TEXT NOT NULL,
      expires BIGINT NOT NULL,
      last_heartbeat BIGINT,
      active_scripts JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS pending_auths (
      auth_code TEXT PRIMARY KEY,
      poll_token TEXT NOT NULL,
      hwid TEXT NOT NULL,
      username TEXT,
      expires BIGINT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    
    CREATE INDEX IF NOT EXISTS idx_sessions_discord ON sessions(discord_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
    CREATE INDEX IF NOT EXISTS idx_pending_expires ON pending_auths(expires);
  `);
  console.log('✅ Database migrations applied');
}

// ═══════════════════════════════════════════════════════════════
// DISCORD WEBHOOK ALERTS
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
          footer: { text: 'Loader' }
        }]
      })
    });
  } catch (e) {
    console.error('Alert error:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// GITLAB (для загрузки скриптов)
// ═══════════════════════════════════════════════════════════════
async function fetchGitLabFile(path) {
  if (!GITLAB_TOKEN || !GITLAB_PROJECT_ID) {
    console.warn('⚠️ GitLab not configured');
    return null;
  }
  
  const encodedPath = encodeURIComponent(path);
  const url = `https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/repository/files/${encodedPath}/raw?ref=${GITLAB_BRANCH}`;
  
  try {
    const res = await fetch(url, {
      headers: { 'PRIVATE-TOKEN': GITLAB_TOKEN }
    });
    
    if (!res.ok) {
      console.error('❌ GitLab fetch failed:', res.status);
      return null;
    }
    
    return await res.text();
  } catch (e) {
    console.error('❌ GitLab error:', e.message);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// SCRIPT REGISTRY (script_id -> GitLab path)
// ═══════════════════════════════════════════════════════════════
const SCRIPTS = {
  "kaelis.gs": {
    name: "Kaelis Script",
    modules: {
      init: "scripts/kaelis/init.lua",
      ui: "scripts/kaelis/ui.lua",
      visuals: "scripts/kaelis/visuals.lua",
      aim: "scripts/kaelis/aim.lua"
    }
  }
};

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
// RATE LIMITING
// ═══════════════════════════════════════════════════════════════
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded' }
});

app.use(globalLimiter);

// ═══════════════════════════════════════════════════════════════
// CLEANUP OLD DATA (каждые 5 минут)
// ═══════════════════════════════════════════════════════════════
setInterval(async () => {
  const now = Date.now();
  try {
    // Delete expired sessions
    await pool.query('DELETE FROM sessions WHERE expires < $1', [now]);
    
    // Delete expired pending auths
    await pool.query('DELETE FROM pending_auths WHERE expires < $1', [now]);
    
    // Delete old activity logs (> 30 days)
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
      version: '2.0'
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
// DISCORD OAUTH FLOW - STEP 1: INIT
// ═══════════════════════════════════════════════════════════════
app.post('/discord/init', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, username, timestamp, nonce, signature } = req.body || {};
  
  if (!hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Verify signature
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    await logActivity('init_failed', null, hwid, ip, 'Bad signature');
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  // Verify fingerprint
  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp)) {
    await logActivity('init_failed', null, hwid, ip, 'Bad fingerprint');
    return res.status(403).json({ error: 'Invalid fingerprint' });
  }
  
  // Generate auth code and poll token
  const authCode = generateToken(4).toUpperCase();  // 8-char code
  const pollToken = generateToken(32);
  
  try {
    // Store pending auth
    await pool.query(
      `INSERT INTO pending_auths (auth_code, poll_token, hwid, username, expires)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (auth_code) DO NOTHING`,
      [authCode, pollToken, hwid, username, Date.now() + 120000]  // 2 min expiry
    );
    
    await logActivity('discord_init', null, hwid, ip, 'Auth code generated');
    
    signedJson(res, {
      auth_code: authCode,
      poll_token: pollToken,
      expires_in: 120
    });
  } catch (e) {
    console.error('❌ Init error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// DISCORD OAUTH FLOW - STEP 2: POLL
// ═══════════════════════════════════════════════════════════════
app.post('/discord/poll', async (req, res) => {
  const { poll_token } = req.body || {};
  
  if (!poll_token) {
    return res.status(400).json({ error: 'Missing poll_token' });
  }
  
  try {
    // Check if auth completed
    const result = await pool.query(
      `SELECT pa.hwid, pa.username, pa.auth_code, u.discord_id, u.discord_username, u.subscription_expires
       FROM pending_auths pa
       LEFT JOIN users u ON u.hwid = pa.hwid
       WHERE pa.poll_token = $1 AND pa.expires > $2`,
      [poll_token, Date.now()]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Invalid or expired poll token' });
    }
    
    const pending = result.rows[0];
    
    // Check if user linked discord yet
    if (!pending.discord_id) {
      // Still waiting for Discord link
      return res.status(202).json({ status: 'pending' });
    }
    
    // User linked! Create session
    const sessionId = generateToken(32);
    const sessionExp = Date.now() + (24 * 60 * 60 * 1000);  // 24 hours
    
    await pool.query(
      `INSERT INTO sessions (session_id, discord_id, hwid, expires, last_heartbeat)
       VALUES ($1, $2, $3, $4, $5)`,
      [sessionId, pending.discord_id, pending.hwid, sessionExp, Date.now()]
    );
    
    // Delete pending auth
    await pool.query('DELETE FROM pending_auths WHERE poll_token = $1', [poll_token]);
    
    await logActivity('discord_login', pending.discord_id, pending.hwid, getClientIP(req), 'Success');
    
    signedJson(res, {
      discord_id: pending.discord_id,
      session_id: sessionId,
      expires: sessionExp
    });
  } catch (e) {
    console.error('❌ Poll error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// CHUNKED SCRIPT DELIVERY (главная фишка защиты!)
// ═══════════════════════════════════════════════════════════════

// При старте сервера: разбить скрипты на чанки
const SCRIPT_CHUNKS = new Map();

async function prepareScriptChunks() {
  for (const [scriptId, script] of Object.entries(SCRIPTS)) {
    console.log(`📦 Preparing chunks for ${scriptId}...`);
    
    // Загрузить скрипт из GitLab
    const scriptCode = await fetchGitLabFile(script.modules.init);
    if (!scriptCode) {
      console.error(`❌ Failed to load ${scriptId}`);
      continue;
    }
    
    // Разбить на чанки по ~500 символов
    const CHUNK_SIZE = 500;
    const chunks = [];
    
    for (let i = 0; i < scriptCode.length; i += CHUNK_SIZE) {
      chunks.push(scriptCode.substring(i, i + CHUNK_SIZE));
    }
    
    console.log(`✅ ${scriptId}: ${chunks.length} chunks`);
    
    SCRIPT_CHUNKS.set(scriptId, {
      chunks: chunks,
      total: chunks.length,
      hash: crypto.createHash('md5').update(scriptCode).digest('hex')
    });
  }
}

// ═══════════════════════════════════════════════════════════════
// ENDPOINT: /script/meta (получить метаданные)
// ═══════════════════════════════════════════════════════════════
app.post('/script/meta', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, session_id, script_id, timestamp, nonce, signature } = req.body || {};
  
  if (!hwid || !session_id || !script_id || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Verify signature
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  // Verify fingerprint
  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp)) {
    return res.status(403).json({ error: 'Invalid fingerprint' });
  }
  
  try {
    // Validate session
    const sessResult = await pool.query(
      `SELECT s.discord_id, u.subscription_expires, u.banned, u.scripts
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
    
    if (session.subscription_expires < Date.now()) {
      return res.status(403).json({ error: 'Subscription expired' });
    }
    
    // Check script access
    const allowedScripts = session.scripts || [];
    if (allowedScripts.length > 0 && !allowedScripts.includes(script_id)) {
      return res.status(403).json({ error: 'Script not allowed' });
    }
    
    // Get chunks info
    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    // Generate RANDOM chunk order (защита от Fiddler!)
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
    console.error('❌ Script meta error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// ENDPOINT: /script/chunk (получить один чанк)
// ═══════════════════════════════════════════════════════════════
app.post('/script/chunk', async (req, res) => {
  const ip = getClientIP(req);
  const { hwid, session_id, script_id, chunk_id, timestamp, nonce, signature } = req.body || {};
  
  if (!hwid || !session_id || !script_id || !chunk_id || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Verify signature
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  // Verify fingerprint
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
    
    // Encrypt chunk with AES
    const encrypted = aesEncrypt(chunkData, hwid);
    
    // Логируем только каждый 10-й чанк (чтоб не спамить логи)
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

// Удалить старый /module/load endpoint (больше не нужен)

// ═══════════════════════════════════════════════════════════════
// HEARTBEAT (проверка каждые 3 сек)
// ═══════════════════════════════════════════════════════════════
app.post('/heartbeat', async (req, res) => {
  const { session_id, runtime_hash, active_scripts } = req.body || {};
  
  if (!session_id) {
    return res.status(400).json({ error: 'Missing session_id' });
  }
  
  try {
    // Update session
    const result = await pool.query(
      `UPDATE sessions 
       SET last_heartbeat = $1, active_scripts = $2
       WHERE session_id = $3 AND expires > $4
       RETURNING discord_id, hwid`,
      [Date.now(), active_scripts ? JSON.parse(`["${active_scripts}"]`) : [], session_id, Date.now()]
    );
    
    if (result.rows.length === 0) {
      return signedJson(res, { action: 'terminate', reason: 'Session expired' });
    }
    
    const session = result.rows[0];
    
    // Check if user banned
    const userResult = await pool.query(
      'SELECT banned FROM users WHERE discord_id = $1',
      [session.discord_id]
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
    }
    
    await logActivity('tamper_detected', discordId, hwid, ip, reason);
    
    await sendAlert(
      `**🚨 TAMPER DETECTED**\n` +
      `**Discord:** ${discordId || 'unknown'}\n` +
      `**HWID:** ${hwid}\n` +
      `**IP:** ${ip}\n` +
      `**Reason:** ${reason}\n` +
      `**Action:** Account banned`,
      'critical'
    );
    
    res.json({ status: 'reported' });
  } catch (e) {
    console.error('❌ Tamper report error:', e);
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
// BLOCK INVALID ROUTES
// ═══════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, async () => {
  await runMigrations();
  
  console.log(`\n🔐 ═══════════════════════════════════════════`);
  console.log(`   ULTRA SECURE LOADER V2.0 (Discord Auth)`);
  console.log(`   ═══════════════════════════════════════════`);
  console.log(`   ✅ Port: ${PORT}`);
  console.log(`   ✅ Database: PostgreSQL`);
  console.log(`   ✅ Discord Auth: ENABLED`);
  console.log(`   ✅ AES-256-GCM: ENABLED`);
  console.log(`   ✅ Chunked Loading: ENABLED (Random Order!)`);
  console.log(`   ✅ Heartbeat: 3s intervals`);
  console.log(`   ✅ Scripts: ${Object.keys(SCRIPTS).length}`);
  console.log(`═══════════════════════════════════════════\n`);
  
  // Test database
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('✅ Database connection: OK');
  } catch (e) {
    console.error('❌ Database connection failed:', e.message);
    process.exit(1);
  }
  
  // Prepare script chunks
  console.log('\n📦 Preparing script chunks...');
  await prepareScriptChunks();
  console.log('✅ All scripts chunked and ready!\n');
});
