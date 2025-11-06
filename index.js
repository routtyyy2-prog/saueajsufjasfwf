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
app.use(express.json());

const PORT = process.env.PORT || 8080;
const GITLAB_TOKEN = process.env.GITLAB_TOKEN || "";
const REPO_RAW_URL = process.env.REPO_RAW_URL || "";
const SECRET_KEY = process.env.SECRET_KEY || "";

if (!REPO_RAW_URL) {
  console.error("❌ Missing REPO_RAW_URL in environment");
  process.exit(1);
}

// Rate limiting - более строгий для безопасности
const limiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 10, // Снизили до 10 запросов в минуту
  message: 'Too many requests'
});

// Хранилище одноразовых токенов
const tokens = new Map();

// Очистка просроченных токенов каждую минуту
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokens.entries()) {
    if (now > data.expires) {
      tokens.delete(token);
    }
  }
}, 60000);

// XOR шифрование ПО БАЙТАМ
function xorEncrypt(text, key) {
  const buf = Buffer.from(text, 'utf8');   // исходный скрипт как байты
  const kb  = Buffer.from(key,  'utf8');   // ключ как байты (строка hwid)

  for (let i = 0; i < buf.length; i++) {
    buf[i] = buf[i] ^ kb[i % kb.length];
  }
  return buf.toString('base64');           // отдаем base64 зашифрованных БАЙТОВ
}


// Health check
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    has_repo_url: Boolean(REPO_RAW_URL),
    has_token: Boolean(GITLAB_TOKEN),
    active_tokens: tokens.size
  });
});

// ШАГ 1: Получение одноразового токена
app.post('/auth', limiter, (req, res) => {
  try {
    const { hwid, timestamp, signature } = req.body;

    // Проверка наличия всех параметров
    if (!hwid || !timestamp || !signature) {
      console.log('❌ Missing parameters');
      return res.status(400).json({ error: 'Missing required parameters' });
    }

    // Проверка timestamp (защита от replay атак)
    const now = Date.now();
    const reqTime = parseInt(timestamp);
    
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 30000) {
      console.log(`❌ Invalid/expired timestamp: ${timestamp}`);
      return res.status(403).json({ error: 'Request expired or invalid timestamp' });
    }

    // Проверка подписи (используем MD5 вместо HMAC SHA256 для совместимости с Lua)
    const expectedSig = crypto
      .createHash('md5')
      .update(SECRET_KEY + hwid + timestamp)
      .digest('hex');

    if (signature !== expectedSig) {
      console.log(`❌ Invalid signature for HWID: ${hwid.substring(0, 8)}...`);
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // Генерация одноразового токена
    const token = crypto.randomBytes(32).toString('hex');
    
    // Токен живёт 10 секунд
    tokens.set(token, {
      hwid,
      expires: Date.now() + 10000,
      used: false
    });

    console.log(`✅ Token issued for HWID: ${hwid.substring(0, 8)}...`);
    
    res.json({ 
      token,
      expires_in: 10
    });
  } catch (err) {
    console.error("AUTH ERROR:", err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ШАГ 2: Загрузка скрипта с токеном
app.post('/load', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Missing token' });
    }

    const tokenData = tokens.get(token);

    // Проверка существования токена
    if (!tokenData) {
      console.log(`❌ Token not found: ${token.substring(0, 8)}...`);
      return res.status(403).json({ error: 'Invalid token' });
    }

    // Проверка срока действия
    if (Date.now() > tokenData.expires) {
      tokens.delete(token);
      console.log(`❌ Token expired: ${token.substring(0, 8)}...`);
      return res.status(403).json({ error: 'Token expired' });
    }

    // Проверка что токен не использован (одноразовый!)
    if (tokenData.used) {
      console.log(`❌ Token already used: ${token.substring(0, 8)}...`);
      return res.status(403).json({ error: 'Token already used' });
    }

    // Помечаем токен как использованный
    tokenData.used = true;

    // Загружаем скрипт из GitLab
    const headers = {};
    if (GITLAB_TOKEN) {
      headers['PRIVATE-TOKEN'] = GITLAB_TOKEN;
    }

    const r = await fetch(REPO_RAW_URL, { headers });
    
    if (!r.ok) {
      const errorText = await r.text().catch(() => "");
      console.error(`❌ GitLab error: ${r.status}`);
      return res.status(502).json({ 
        error: 'Upstream error',
        status: r.status 
      });
    }

    const script = await r.text();

    // Шифруем скрипт с использованием HWID как ключа
    const encrypted = xorEncrypt(script, tokenData.hwid);

    // Удаляем использованный токен
    tokens.delete(token);

    console.log(`✅ Script delivered to HWID: ${tokenData.hwid.substring(0, 8)}...`);
    
    // Отдаём зашифрованный скрипт
    res.type('text/plain').send(encrypted);
  } catch (err) {
    console.error("LOAD ERROR:", err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fallback для GET запросов - отказываем в доступе
app.get('/get_main', (req, res) => {
  res.status(403).json({ 
    error: 'Direct access forbidden. Use the loader.' 
  });
});

app.get('/load', (req, res) => {
  res.status(405).json({ 
    error: 'Method not allowed. Use POST.' 
  });
});

// 404 для всех остальных путей
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`✅ Secure loader proxy running on port ${PORT}`);
  console.log(`✅ Secret key: ${SECRET_KEY.substring(0, 4)}...`);
  console.log(`✅ GitLab configured: ${Boolean(GITLAB_TOKEN)}`);
});