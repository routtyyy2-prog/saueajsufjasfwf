// ╔════════════════════════════════════════════════════════════════╗
// ║       SECURE LOADER V4.1 - ChaCha20-Poly1305 ENCRYPTION       ║
// ║  • ChaCha20-Poly1305 authenticated encryption                  ║
// ║  • Per-chunk unique keys derived from HWID                     ║
// ║  • HMAC-SHA256 response signing                                ║
// ║  • PostgreSQL session management                               ║
// ╚════════════════════════════════════════════════════════════════╝

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { Pool } = require('pg');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 8080;
const SECRET_KEY = process.env.SECRET_KEY || "k8Jf2mP9xLq4nR7vW3sT6yH5bN8aZ1cD";
const DISCORD_WEBHOOK = process.env.ALERT_WEBHOOK || "";
const DATABASE_URL = process.env.DATABASE_URL;
const CHUNK_SIZE = parseInt(process.env.CHUNK_SIZE || '8192', 10);

// Discord OAuth2
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "http://localhost:8080/auth/discord/callback";

// Script source
const GITLAB_PROJECT_ID = process.env.GITLAB_PROJECT_ID || '';
const GITLAB_FILE_PATH = process.env.GITLAB_FILE_PATH || 'test12.lua';
const GITLAB_BRANCH = process.env.GITLAB_BRANCH || 'main';
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || '';
const REPO_RAW_URL = process.env.REPO_RAW_URL || '';

// ═══════════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════
function md5(str) {
  return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function deriveKey(hwid, chunkIndex) {
  const material = SECRET_KEY + String(hwid) + String(chunkIndex);
  return crypto.createHash('sha256').update(material).digest();
}

function encryptChunk(buffer, hwid, chunkIndex) {
  const key = deriveKey(hwid, chunkIndex);
  const nonce = crypto.randomBytes(12);
  
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16
  });
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // Format: [nonce(12)][authTag(16)][encrypted]
  return Buffer.concat([nonce, authTag, encrypted]).toString('base64');
}

function signedJson(res, obj) {
  const body = JSON.stringify(obj);
  const sig = hmacSha256(SECRET_KEY, body);
  res.set('X-Resp-Sig', sig);
  res.type('application/json').send(body);
}

function constantTimeCompare(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ═══════════════════════════════════════════════════════════════
// POSTGRESQL
// ═══════════════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
});

async function runMigrations() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        discord_id TEXT PRIMARY KEY,
        discord_username TEXT,
        discord_avatar TEXT,
        hwid TEXT,
        subscription_expires BIGINT NOT NULL,
        max_hwid_resets INTEGER DEFAULT 3,
        hwid_resets_used INTEGER DEFAULT 0,
        scripts JSONB DEFAULT '["kaelis.gs"]'::jsonb,
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
      CREATE INDEX IF NOT EXISTS idx_oauth_expires ON oauth_states(expires);
    `);
    
    await client.query('COMMIT');
    console.log('✅ Database migrations completed');
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
  const colors = { info: 3447003, warning: 16776960, critical: 15158332, success: 3066993 };
  try {
    await fetch(DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `🔐 Loader Alert [${level.toUpperCase()}]`,
          description: message,
          color: colors[level] || colors.warning,
          timestamp: new Date().toISOString()
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
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

async function logActivity(eventType, discordId, hwid, ip, details) {
  try {
    await pool.query(
      `INSERT INTO activity_log (event_type, discord_id, hwid, ip, details, timestamp) VALUES ($1, $2, $3, $4, $5, $6)`,
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

async function fetchScriptCode() {
  if (GITLAB_PROJECT_ID && GITLAB_FILE_PATH && GITLAB_TOKEN) {
    const encPath = encodeURIComponent(GITLAB_FILE_PATH);
    const api = `https://gitlab.com/api/v4/projects/${GITLAB_PROJECT_ID}/repository/files/${encPath}/raw?ref=${encodeURIComponent(GITLAB_BRANCH)}`;
    const res = await fetch(api, {
      headers: { 'PRIVATE-TOKEN': GITLAB_TOKEN }
    });
    if (!res.ok) throw new Error(`GitLab API error: ${res.status}`);
    return await res.text();
  }
  
  if (REPO_RAW_URL) {
    const headers = GITLAB_TOKEN ? { 'PRIVATE-TOKEN': GITLAB_TOKEN } : {};
    const res = await fetch(REPO_RAW_URL, { headers });
    if (!res.ok) throw new Error(`URL fetch error: ${res.status}`);
    return await res.text();
  }
  
  throw new Error('No source configured: set GITLAB_* or REPO_RAW_URL');
}

function chunkAndStore(scriptId, code) {
  const buffer = Buffer.from(code, 'utf8');
  const chunks = [];
  
  for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
    chunks.push(buffer.subarray(i, i + CHUNK_SIZE));
  }
  
  const hash = crypto.createHash('sha256').update(code).digest('hex');
  const assembly_md5 = md5(code);
  
  SCRIPT_CHUNKS.set(scriptId, {
    chunks,
    totalChunks: chunks.length,
    hash,
    size: code.length,
    assembly_md5
  });
  
  console.log(`✅ ${scriptId}: ${chunks.length} chunks (${code.length} bytes, md5=${assembly_md5.substring(0, 8)}...)`);
}

async function prepareAllScripts() {
  console.log('\n📦 Preparing scripts...');
  const code = await fetchScriptCode();
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

const chunkLimiter = rateLimit({
  windowMs: 1000,
  max: 100,
  message: { error: 'Slow down chunk requests' }
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
    await pool.query('DELETE FROM activity_log WHERE timestamp < $1', [now - (30 * 24 * 60 * 60 * 1000)]);
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
      version: '4.1',
      scripts_loaded: SCRIPT_CHUNKS.size,
      encryption: 'chacha20-poly1305'
    });
  } catch (e) {
    res.status(500).json({ status: 'degraded', error: e.message });
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
    const statePayload = md5(state + hwid + SECRET_KEY);
    
    await pool.query(
      `INSERT INTO oauth_states (state, hwid, created_at, expires) VALUES ($1, $2, $3, $4)`,
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
    signedJson(res, { auth_url: authUrl, state: statePayload, expires_in: 300 });
  } catch (e) {
    console.error('❌ OAuth init error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.send('<h1>❌ Error</h1><p>Missing code or state</p>');
  }
  
  try {
    const stateResult = await pool.query(
      'SELECT hwid, expires FROM oauth_states WHERE state = $1',
      [state]
    );
    
    if (stateResult.rows.length === 0) {
      return res.send('<h1>❌ Error</h1><p>Invalid or expired state</p>');
    }
    
    const { hwid, expires } = stateResult.rows[0];
    
    if (Date.now() > expires) {
      await pool.query('DELETE FROM oauth_states WHERE state = $1', [state]);
      return res.send('<h1>❌ Error</h1><p>State expired</p>');
    }
    
    // Exchange code for access token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
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
    
    if (!tokenRes.ok) {
      return res.send('<h1>❌ Error</h1><p>Failed to get Discord token</p>');
    }
    
    const tokenData = await tokenRes.json();
    
    // Get user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    
    if (!userRes.ok) {
      return res.send('<h1>❌ Error</h1><p>Failed to get Discord user info</p>');
    }
    
    const userData = await userRes.json();
    
    // Check if user exists
    const userResult = await pool.query(
      'SELECT * FROM users WHERE discord_id = $1',
      [userData.id]
    );
    
    if (userResult.rows.length === 0) {
      return res.send(`<h1>⛔ Access Denied</h1><p>Discord: ${userData.username}</p><p>Please contact an administrator to get access.</p>`);
    }
    
    const user = userResult.rows[0];
    
    if (user.banned) {
      return res.send(`<h1>🚫 Banned</h1><p>Reason: ${user.ban_reason || 'Unknown'}</p>`);
    }
    
    if (user.subscription_expires < Date.now()) {
      return res.send(`<h1>⏰ Subscription Expired</h1><p>Please renew your subscription.</p>`);
    }
    
    if (user.hwid && user.hwid !== hwid) {
      return res.send(`<h1>🔒 HWID Mismatch</h1><p>This account is bound to another PC.</p><p>Resets left: ${user.max_hwid_resets - user.hwid_resets_used}</p>`);
    }
    
    if (!user.hwid) {
      await pool.query(
        'UPDATE users SET hwid = $1, updated_at = CURRENT_TIMESTAMP WHERE discord_id = $2',
        [hwid, userData.id]
      );
      await sendAlert(`**New HWID Bind**\n**User:** ${userData.username} (${userData.id})\n**HWID:** ${hwid}`, 'info');
    }
    
    const sessionId = generateToken(32);
    const sessionExp = Date.now() + (24 * 60 * 60 * 1000);
    
    await pool.query(
      `INSERT INTO sessions (session_id, discord_id, hwid, expires, last_heartbeat, ip) VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionId, userData.id, hwid, sessionExp, Date.now(), getClientIP(req)]
    );
    
    await pool.query(
      'UPDATE users SET last_login = $1, discord_username = $2, discord_avatar = $3 WHERE discord_id = $4',
      [Date.now(), userData.username, userData.avatar, userData.id]
    );
    
    await pool.query('DELETE FROM oauth_states WHERE state = $1', [state]);
    await logActivity('login_success', userData.id, hwid, getClientIP(req), userData.username);
    
    res.send(`<h1>✅ Login Successful</h1><p><strong>Discord:</strong> ${userData.username}</p><p><strong>Session:</strong> ${sessionId.substring(0, 16)}...</p><p><strong>Expires:</strong> 24 hours</p><p>You can close this window now.</p>`);
  } catch (e) {
    console.error('❌ OAuth callback error:', e);
    res.send('<h1>❌ Error</h1><p>Internal server error</p>');
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
    const sessionResult = await pool.query(
      'SELECT s.session_id, s.expires, u.subscription_expires FROM sessions s JOIN users u ON s.discord_id = u.discord_id WHERE s.hwid = $1 AND s.expires > $2 ORDER BY s.created_at DESC LIMIT 1',
      [hwid, Date.now()]
    );
    
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'No session found' });
    }
    
    const { session_id, expires, subscription_expires } = sessionResult.rows[0];
    
    signedJson(res, {
      session_id,
      expires,
      subscription_expires
    });
  } catch (e) {
    console.error('❌ Poll error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/script/meta', async (req, res) => {
  const { session_id, script_id, hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!session_id || !script_id || !hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  try {
    const sessionResult = await pool.query(
      'SELECT s.discord_id, u.subscription_expires, u.banned FROM sessions s JOIN users u ON s.discord_id = u.discord_id WHERE s.session_id = $1 AND s.hwid = $2 AND s.expires > $3',
      [session_id, hwid, Date.now()]
    );
    
    if (sessionResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    const { subscription_expires, banned } = sessionResult.rows[0];
    
    if (banned) {
      return res.status(403).json({ error: 'Account banned' });
    }
    
    if (subscription_expires < Date.now()) {
      return res.status(403).json({ error: 'Subscription expired' });
    }
    
    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    signedJson(res, {
      total_chunks: scriptData.totalChunks,
      assembly_md5: scriptData.assembly_md5,
      size: scriptData.size
    });
  } catch (e) {
    console.error('❌ Meta error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/script/chunk', async (req, res) => {
  const { session_id, script_id, chunk_id, hwid, timestamp, nonce, signature } = req.body || {};
  
  if (!session_id || !script_id || chunk_id === undefined || !hwid || !timestamp || !nonce || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  
  const expectedSig = md5(SECRET_KEY + hwid + timestamp + nonce);
  if (!constantTimeCompare(signature, expectedSig)) {
    return res.status(403).json({ error: 'Invalid signature' });
  }
  
  try {
    const sessionResult = await pool.query(
      'SELECT s.discord_id FROM sessions s WHERE s.session_id = $1 AND s.hwid = $2 AND s.expires > $3',
      [session_id, hwid, Date.now()]
    );
    
    if (sessionResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    const scriptData = SCRIPT_CHUNKS.get(script_id);
    if (!scriptData) {
      return res.status(404).json({ error: 'Script not found' });
    }
    
    const chunkIndex = parseInt(chunk_id);
    if (isNaN(chunkIndex) || chunkIndex < 0 || chunkIndex >= scriptData.totalChunks) {
      return res.status(400).json({ error: 'Invalid chunk_id' });
    }
    
    const chunkBuffer = scriptData.chunks[chunkIndex];
    const encrypted = encryptChunk(chunkBuffer, hwid, chunkIndex);
    
    signedJson(res, { chunk: encrypted });
  } catch (e) {
    console.error('❌ Chunk error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/heartbeat', async (req, res) => {
  const { session_id } = req.body || {};
  
  if (!session_id) {
    return res.status(400).json({ error: 'Missing session_id' });
  }
  
  try {
    const result = await pool.query(
      'UPDATE sessions SET last_heartbeat = $1 WHERE session_id = $2 AND expires > $3 RETURNING discord_id',
      [Date.now(), session_id, Date.now()]
    );
    
    if (result.rows.length === 0) {
      return signedJson(res, { action: 'terminate' });
    }
    
    signedJson(res, { action: 'ok' });
  } catch (e) {
    console.error('❌ Heartbeat error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// STARTUP
// ═══════════════════════════════════════════════════════════════
(async () => {
  try {
    await runMigrations();
    await prepareAllScripts();
    
    app.listen(PORT, () => {
      console.log(`\n🚀 Secure Loader V4.1 running on port ${PORT}`);
      console.log(`📊 Encryption: ChaCha20-Poly1305`);
      console.log(`🔑 SECRET_KEY: ${SECRET_KEY.substring(0, 8)}...`);
    });
  } catch (e) {
    console.error('❌ Startup failed:', e);
    process.exit(1);
  }
})();
