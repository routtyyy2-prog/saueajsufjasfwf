// ╔════════════════════════════════════════════════════════════════╗
// ║  ULTRA SECURE LOADER V2.0 - KEY AUTH + CHUNKED LOADING        ║
// ║  • Unique key authentication (1 key = 1 HWID)                  ║
// ║  • Single file chunked delivery (random order)                 ║
// ║  • Discord bot for key management                              ║
// ║  • AES-256-GCM encryption                                      ║
// ║  • Anti-debugging protection                                   ║
// ╚════════════════════════════════════════════════════════════════╝

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY || "";
const SECRET_CHECKSUM = crypto.createHash('md5').update(SECRET_KEY).digest('hex');
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || "";
const DATABASE_URL = process.env.DATABASE_URL;
const SCRIPTS_DIR = process.env.SCRIPTS_DIR || './scripts';

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
// AES ENCRYPTION
// ═══════════════════════════════════════════════════════════════
function aesEncrypt(text, hwid) {
  const algorithm = 'aes-256-gcm';
  
  const key = crypto.pbkdf2Sync(
    SECRET_KEY + hwid,
    'loader_v2_salt',
    100000,
    32,
    'sha256'
  );
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  // Add padding
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
    CREATE TABLE IF NOT EXISTS keys (
      key_id TEXT PRIMARY KEY,
      hwid TEXT,
      discord_id TEXT,
      discord_username TEXT,
      subscription_expires BIGINT NOT NULL,
      max_resets INTEGER DEFAULT 3,
      resets_used INTEGER DEFAULT 0,
      scripts JSONB DEFAULT '["kaelis.gs"]',
      banned BOOLEAN DEFAULT FALSE,
      ban_reason TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login BIGINT
    );
    
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      key_id TEXT NOT NULL,
      hwid TEXT NOT NULL,
      expires BIGINT NOT NULL,
      last_heartbeat BIGINT,
      active_scripts JSONB DEFAULT '[]',
      ip TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS activity_log (
      id BIGSERIAL PRIMARY KEY,
      event_type TEXT,
      key_id TEXT,
      hwid TEXT,
      ip TEXT,
      details TEXT,
      timestamp BIGINT
    );
    
    CREATE INDEX IF NOT EXISTS idx_keys_hwid ON keys(hwid);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
    CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp);
  `);
  console.log('✅ Database migrations applied');
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
          footer: { text: 'Loader' }
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

function generateKey() {
  // Format: XXXX-XXXX-XXXX-XXXX
  const parts = [];
  for (let i = 0; i < 4; i++) {
    parts.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  }
  return parts.join('-');
}

async function logActivity(eventType, keyId, hwid, ip, details) {
  try {
    await pool.query(
      `INSERT INTO activity_log (event_type, key_id, hwid, ip, details, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [eventType, keyId, hwid, ip, details, Date.now()]
    );
  } catch (e) {
    console.error('❌ Log error:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// SCRIPT CHUNKING SYSTEM
// ═══════════════════════════════════════════════════════════════
const SCRIPT_CHUNKS = new Map();

async function loadAndChunkScript(scriptId, filePath) {
  try {
    const scriptCode = await fs.readFile(filePath, 'utf8');
    
    // Chunk size: 500 chars
    const CHUNK_SIZE = 500;
    const chunks = [];
    
    for (let i = 0; i < scriptCode.length; i += CHUNK_SIZE) {
      chunks.push(scriptCode.substring(i, i + CHUNK_SIZE));
    }
    
    const hash = crypto.createHash('md5').update(scriptCode).digest('hex');
    
    SCRIPT_CHUNKS.set(scriptId, {
      chunks: chunks,
      total: chunks.length,
      hash: hash,
      size: scriptCode.length
    });
    
    console.log(`✅ ${scriptId}: ${chunks.length} chunks (${scriptCode.length} bytes)`);
    return true;
  } catch (e) {
    console.error(`❌ Failed to load ${scriptId}:`, e.message);
    return false;
  }
}

async function prepareAllScripts() {
  console.log('\n📦 Loading scripts...');
  
  // Load kaelis.gs (test12.lua)
  await loadAndChunkScript('kaelis.gs', path.join(SCRIPTS_DIR, 'test12.lua'));
  
  // Add more scripts here if needed
  // await loadAndChunkScript('other.gs', path.join(SCRIPTS_DIR, 'other.lua'));
}

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING
// ═══════════════════════════════════════════════════════════════
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many auth attempts' }
});

const chunkLimiter = rateLimit({
  windowMs: 1000,
  max: 20,
  message: { error: 'Slow down chunk requests' }
});

app.use('/auth/login', authLimiter);
app.use('/script/chunk', chunkLimiter);

// ═══════════════════════════════════════════════════════════════
// CLEANUP (every 5 min)
// ═══════════════════════════════════════════════════════════════
setInterval(async () => {
  const now = Date.now();
  try {
    await pool.query('DELETE FROM sessions WHERE expires < $1', [now]);
    
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
      version: '2.0',
      scripts_loaded: SCRIPT_CHUNKS.size
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
// KEY AUTH - LOGIN
// ═══════════════════════════════════════════════════════════════
app.post('/auth/login', async (req, res) => {
  const ip = getClientIP(req);
  const { key, hwid, username, timestamp, nonce, signature } = req.body || {};
  
  if (!key || !hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  // Verify signature
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    await logActivity('login_failed', key, hwid, ip, 'Bad signature');
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  // Verify fingerprint
  const clientFp = req.headers['x-client-fp'];
  const expectedFp = md5(hwid + ':' + nonce + ':' + SECRET_CHECKSUM);
  if (!constantTimeCompare(clientFp, expectedFp)) {
    await logActivity('login_failed', key, hwid, ip, 'Bad fingerprint');
    return res.status(403).json({ error: 'Invalid fingerprint' });
  }
  
  try {
    // Check key
    const result = await pool.query(
      'SELECT * FROM keys WHERE key_id = $1',
      [key]
    );
    
    if (result.rows.length === 0) {
      await logActivity('login_failed', key, hwid, ip, 'Invalid key');
      return res.status(403).json({ error: 'Invalid key' });
    }
    
    const keyData = result.rows[0];
    
    // Check banned
    if (keyData.banned) {
      await logActivity('login_failed', key, hwid, ip, 'Banned');
      return res.status(403).json({ error: 'Key banned: ' + (keyData.ban_reason || 'Unknown') });
    }
    
    // Check subscription
    if (keyData.subscription_expires < Date.now()) {
      await logActivity('login_failed', key, hwid, ip, 'Expired');
      return res.status(403).json({ error: 'Subscription expired' });
    }
    
    // Check HWID
    if (keyData.hwid && keyData.hwid !== hwid) {
      await logActivity('login_failed', key, hwid, ip, 'HWID mismatch');
      return res.status(403).json({ 
        error: 'Key already bound to another PC',
        can_reset: keyData.resets_used < keyData.max_resets
      });
    }
    
    // Bind HWID if first time
    if (!keyData.hwid) {
      await pool.query(
        'UPDATE keys SET hwid = $1, updated_at = CURRENT_TIMESTAMP WHERE key_id = $2',
        [hwid, key]
      );
      
      await sendAlert(
        `**New HWID Bind**\n` +
        `**Key:** ${key}\n` +
        `**HWID:** ${hwid}\n` +
        `**User:** ${username}\n` +
        `**IP:** ${ip}`,
        'info'
      );
    }
    
    // Create session
    const sessionId = generateToken(32);
    const sessionExp = Date.now() + (24 * 60 * 60 * 1000); // 24h
    
    await pool.query(
      `INSERT INTO sessions (session_id, key_id, hwid, expires, last_heartbeat, ip)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionId, key, hwid, sessionExp, Date.now(), ip]
    );
    
    // Update last login
    await pool.query(
      'UPDATE keys SET last_login = $1 WHERE key_id = $2',
      [Date.now(), key]
    );
    
    await logActivity('login_success', key, hwid, ip, username);
    
    signedJson(res, {
      session_id: sessionId,
      expires: sessionExp,
      subscription_expires: keyData.subscription_expires,
      scripts: keyData.scripts || ['kaelis.gs'],
      user_info: {
        discord: keyData.discord_username || 'Unknown',
        resets_left: keyData.max_resets - keyData.resets_used
      }
    });
  } catch (e) {
    console.error('❌ Login error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// HWID RESET (через Discord бота)
// ═══════════════════════════════════════════════════════════════
app.post('/auth/reset-hwid', async (req, res) => {
  const { key, admin_token } = req.body || {};
  
  // Only bot can call this
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM keys WHERE key_id = $1',
      [key]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    const keyData = result.rows[0];
    
    if (keyData.resets_used >= keyData.max_resets) {
      return res.status(403).json({ error: 'No resets left' });
    }
    
    // Reset HWID
    await pool.query(
      `UPDATE keys 
       SET hwid = NULL, resets_used = resets_used + 1, updated_at = CURRENT_TIMESTAMP
       WHERE key_id = $1`,
      [key]
    );
    
    // Kill all sessions
    await pool.query('DELETE FROM sessions WHERE key_id = $1', [key]);
    
    await sendAlert(
      `**HWID Reset**\n` +
      `**Key:** ${key}\n` +
      `**User:** ${keyData.discord_username}\n` +
      `**Resets left:** ${keyData.max_resets - keyData.resets_used - 1}`,
      'warning'
    );
    
    res.json({ 
      success: true,
      resets_left: keyData.max_resets - keyData.resets_used - 1
    });
  } catch (e) {
    console.error('❌ Reset error:', e);
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
  
  // Verify signature
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
      `SELECT s.key_id, k.scripts, k.banned
       FROM sessions s
       JOIN keys k ON k.key_id = s.key_id
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
    
    await logActivity('script_meta', session.key_id, hwid, ip, script_id);
    
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
      'SELECT key_id FROM sessions WHERE session_id = $1 AND hwid = $2 AND expires > $3',
      [session_id, hwid, Date.now()]
    );
    
    if (sessResult.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid session' });
    }
    
    const keyId = sessResult.rows[0].key_id;
    
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
      await logActivity('chunk_load', keyId, hwid, ip, `${script_id}:${chunk_id}`);
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
       RETURNING key_id`,
      [Date.now(), active_scripts ? JSON.parse(`["${active_scripts}"]`) : [], session_id, Date.now()]
    );
    
    if (result.rows.length === 0) {
      return signedJson(res, { action: 'terminate', reason: 'Session expired' });
    }
    
    const keyId = result.rows[0].key_id;
    
    // Check if banned
    const keyResult = await pool.query(
      'SELECT banned FROM keys WHERE key_id = $1',
      [keyId]
    );
    
    if (keyResult.rows.length > 0 && keyResult.rows[0].banned) {
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
    let keyId = null;
    
    if (session_id) {
      const result = await pool.query(
        'SELECT key_id FROM sessions WHERE session_id = $1',
        [session_id]
      );
      if (result.rows.length > 0) {
        keyId = result.rows[0].key_id;
      }
    }
    
    // Ban key
    if (keyId) {
      await pool.query(
        `UPDATE keys 
         SET banned = TRUE, ban_reason = $1, updated_at = CURRENT_TIMESTAMP
         WHERE key_id = $2`,
        [reason, keyId]
      );
      
      // Kill sessions
      await pool.query('DELETE FROM sessions WHERE key_id = $1', [keyId]);
    }
    
    await logActivity('tamper_detected', keyId, hwid, ip, reason);
    
    await sendAlert(
      `**🚨 TAMPER DETECTED**\n` +
      `**Key:** ${keyId || 'unknown'}\n` +
      `**HWID:** ${hwid}\n` +
      `**IP:** ${ip}\n` +
      `**Reason:** ${reason}\n` +
      `**Action:** Key banned`,
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
// BOT API - Generate Key
// ═══════════════════════════════════════════════════════════════
app.post('/bot/generate-key', async (req, res) => {
  const { admin_token, discord_id, discord_username, days } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!discord_id || !days) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  try {
    const key = generateKey();
    const expires = Date.now() + (days * 24 * 60 * 60 * 1000);
    
    await pool.query(
      `INSERT INTO keys (key_id, discord_id, discord_username, subscription_expires, scripts)
       VALUES ($1, $2, $3, $4, $5)`,
      [key, discord_id, discord_username || 'Unknown', expires, JSON.stringify(['kaelis.gs'])]
    );
    
    await sendAlert(
      `**New Key Generated**\n` +
      `**Key:** \`${key}\`\n` +
      `**User:** ${discord_username} (${discord_id})\n` +
      `**Duration:** ${days} days`,
      'success'
    );
    
    res.json({ 
      success: true,
      key: key,
      expires: expires
    });
  } catch (e) {
    console.error('❌ Generate key error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Check Key Info
// ═══════════════════════════════════════════════════════════════
app.post('/bot/check-key', async (req, res) => {
  const { admin_token, key } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!key) {
    return res.status(400).json({ error: 'Missing key' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM keys WHERE key_id = $1',
      [key]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    const keyData = result.rows[0];
    
    res.json({
      key: keyData.key_id,
      discord_id: keyData.discord_id,
      discord_username: keyData.discord_username,
      hwid: keyData.hwid || 'Not bound',
      subscription_expires: keyData.subscription_expires,
      expires_in_days: Math.floor((keyData.subscription_expires - Date.now()) / (24 * 60 * 60 * 1000)),
      resets_left: keyData.max_resets - keyData.resets_used,
      banned: keyData.banned,
      ban_reason: keyData.ban_reason,
      last_login: keyData.last_login,
      scripts: keyData.scripts
    });
  } catch (e) {
    console.error('❌ Check key error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BOT API - Extend Subscription
// ═══════════════════════════════════════════════════════════════
app.post('/bot/extend-sub', async (req, res) => {
  const { admin_token, key, days } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!key || !days) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM keys WHERE key_id = $1',
      [key]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    const keyData = result.rows[0];
    const currentExp = keyData.subscription_expires;
    const newExp = Math.max(currentExp, Date.now()) + (days * 24 * 60 * 60 * 1000);
    
    await pool.query(
      'UPDATE keys SET subscription_expires = $1, updated_at = CURRENT_TIMESTAMP WHERE key_id = $2',
      [newExp, key]
    );
    
    await sendAlert(
      `**Subscription Extended**\n` +
      `**Key:** ${key}\n` +
      `**User:** ${keyData.discord_username}\n` +
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
// BOT API - Ban/Unban Key
// ═══════════════════════════════════════════════════════════════
app.post('/bot/ban-key', async (req, res) => {
  const { admin_token, key, ban, reason } = req.body || {};
  
  if (!admin_token || admin_token !== process.env.BOT_ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!key || ban === undefined) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  try {
    await pool.query(
      `UPDATE keys 
       SET banned = $1, ban_reason = $2, updated_at = CURRENT_TIMESTAMP
       WHERE key_id = $3`,
      [ban, reason || null, key]
    );
    
    // Kill all sessions if banning
    if (ban) {
      await pool.query('DELETE FROM sessions WHERE key_id = $1', [key]);
    }
    
    await sendAlert(
      `**Key ${ban ? 'Banned' : 'Unbanned'}**\n` +
      `**Key:** ${key}\n` +
      (reason ? `**Reason:** ${reason}` : ''),
      ban ? 'warning' : 'info'
    );
    
    res.json({ success: true });
  } catch (e) {
    console.error('❌ Ban key error:', e);
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
  console.log(`   ULTRA SECURE LOADER V2.0 (Key Auth)`);
  console.log(`   ═══════════════════════════════════════════`);
  console.log(`   ✅ Port: ${PORT}`);
  console.log(`   ✅ Database: PostgreSQL`);
  console.log(`   ✅ Auth: Key-based (HWID lock)`);
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
