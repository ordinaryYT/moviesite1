require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

// Render Node 18 has fetch built in, fallback if not
const fetch = global.fetch || ((...args) => import('node-fetch').then(({ default: f }) => f(...args)));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'boughton5';
const EMBED_BASE_MOVIE = 'https://vidsrc.me/embed/movie/';
const EMBED_BASE_TV = 'https://vidsrc.me/embed/tv/';

// --- PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- Password disable state ---
let passwordsDisabled = false;

// --- Auto-create table and ensure schema ---
async function ensureTable() {
  try {
    // Create content table with type field
    await pool.query(`
      CREATE TABLE IF NOT EXISTS content (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        imdb_id TEXT,
        type TEXT NOT NULL CHECK (type IN ('movie', 'tv_show')),
        password_hashes JSONB DEFAULT '[]',
        one_time_password_hashes JSONB DEFAULT '[]',
        year TEXT,
        image TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Content table ready');

    // Create global_passwords table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS global_passwords (
        id SERIAL PRIMARY KEY,
        password_hash TEXT NOT NULL,
        is_one_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Global passwords table ready');

    // Drop old movies table if it exists (for migration)
    await pool.query(`
      DO $$
      BEGIN
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'movies') THEN
          DROP TABLE movies;
        END IF;
      END $$;
    `);
    console.log('✅ Legacy movies table dropped if existed');

  } catch (err) {
    console.error('Error ensuring table schema:', err);
    throw err;
  }
}
ensureTable().catch(console.error);

// --- IMDb Search Helper ---
async function searchImdb(title) {
  const q = encodeURIComponent(title);
  const url = `https://search.imdbot.workers.dev/?q=${q}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('IMDb search failed');
  const data = await res.json();
  const hit = (data.description || []).find(h => h['#IMDB_ID']);
  if (!hit) return null;
  const imdb_id = hit['#IMDB_ID'].startsWith('tt') ? hit['#IMDB_ID'] : 'tt' + hit['#IMDB_ID'];
  return {
    imdb_id,
    title: hit['#TITLE'] || title,
    year: hit['#YEAR'] || null,
    image: hit.image || null
  };
}

// --- Public: list content ---
app.get('/api/content', async (_, res) => {
  try {
    const result = await pool.query('SELECT id, title, type, year, image FROM content ORDER BY created_at DESC');
    res.json({ ok: true, items: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Admin login ---
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ ok: false, error: 'Invalid admin password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ ok: true, token });
});

// --- Admin middleware ---
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ ok: false, error: 'Missing auth' });
  const [type, token] = auth.split(' ');
  if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Bad header' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

// --- Add Content ---
app.post('/api/content', requireAdmin, async (req, res) => {
  try {
    const { name, imdbId, type, contentPasswords, oneTimePasswords } = req.body;
    if (!name && !imdbId) {
      return res.status(400).json({ ok: false, error: 'Provide title or IMDb ID' });
    }
    if (!['movie', 'tv_show'].includes(type)) {
      return res.status(400).json({ ok: false, error: 'Invalid content type' });
    }

    let contentData;
    if (imdbId) {
      contentData = {
        imdb_id: imdbId.startsWith('tt') ? imdbId : 'tt' + imdbId,
        title: name || imdbId,
        year: null,
        image: null
      };
    } else {
      const search = await searchImdb(name);
      if (!search) return res.status(404).json({ ok: false, error: 'No IMDb match found' });
      contentData = search;
    }

    // Hash multiple passwords
    const passwordHashes = contentPasswords && contentPasswords.length
      ? await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)))
      : [];
    const oneTimePasswordHashes = oneTimePasswords && oneTimePasswords.length
      ? await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)))
      : [];

    const result = await pool.query(
      'INSERT INTO content (title, imdb_id, type, password_hashes, one_time_password_hashes, year, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [contentData.title, contentData.imdb_id, type, JSON.stringify(passwordHashes), JSON.stringify(oneTimePasswordHashes), contentData.year, contentData.image]
    );

    res.json({ ok: true, contentId: result.rows[0].id });
  } catch (err) {
    console.error('Add content error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Delete content ---
app.delete('/api/content/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('DELETE FROM content WHERE id=$1 RETURNING id', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Content not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Add Global Password ---
app.post('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  try {
    const { password, isOneTime } = req.body;
    if (!password) {
      return res.status(400).json({ ok: false, error: 'Password required' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, $2) RETURNING id',
      [passwordHash, !!isOneTime]
    );
    res.json({ ok: true, passwordId: result.rows[0].id });
  } catch (err) {
    console.error('Add global password error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- List Global Passwords ---
app.get('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, is_one_time, created_at FROM global_passwords ORDER BY created_at DESC');
    res.json({ ok: true, passwords: result.rows });
  } catch (err) {
    console.error('List global passwords error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Delete Global Password ---
app.delete('/api/admin/global-passwords/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const result = await pool.query('DELETE FROM global_passwords WHERE id=$1 RETURNING id', [id]);
    if (!result.rowCount) {
      return res.status(404).json({ ok: false, error: 'Global password not found' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete global password error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Toggle Password Disable ---
app.post('/api/admin/toggle-passwords', requireAdmin, async (req, res) => {
  try {
    passwordsDisabled = !passwordsDisabled;
    res.json({ ok: true, disabled: passwordsDisabled });
  } catch (err) {
    console.error('Toggle password error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Get Password Disable Status ---
app.get('/api/admin/password-status', requireAdmin, async (req, res) => {
  try {
    res.json({ ok: true, disabled: passwordsDisabled });
  } catch (err) {
    console.error('Get password status error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Authorize viewer ---
app.post('/api/content/:id/authorize', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ ok: false, error: 'Password required' });
    }

    // Check admin password if passwords are disabled
    if (passwordsDisabled) {
      if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ ok: false, error: 'Wrong password' });
      }
      const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
      return res.json({ ok: true, token });
    }

    // Fetch content passwords
    const contentResult = await pool.query(
      'SELECT password_hashes, one_time_password_hashes FROM content WHERE id=$1',
      [id]
    );
    if (!contentResult.rowCount) {
      return res.status(404).json({ ok: false, error: 'Content not found' });
    }

    const { password_hashes, one_time_password_hashes } = contentResult.rows[0];

    // Fetch global passwords
    const globalResult = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');

    // Check one-time passwords (content-specific)
    const oneTimeHashes = JSON.parse(one_time_password_hashes || '[]');
    for (let i = 0; i < oneTimeHashes.length; i++) {
      if (await bcrypt.compare(password, oneTimeHashes[i])) {
        // Remove used one-time password
        oneTimeHashes.splice(i, 1);
        await pool.query(
          'UPDATE content SET one_time_password_hashes = $1 WHERE id = $2',
          [JSON.stringify(oneTimeHashes), id]
        );
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        return res.json({ ok: true, token });
      }
    }

    // Check global one-time passwords
    for (const global of globalResult.rows) {
      if (global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
        // Remove used global one-time password
        await pool.query('DELETE FROM global_passwords WHERE id = $1', [global.id]);
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        return res.json({ ok: true, token });
      }
    }

    // Check regular content passwords
    const regularHashes = JSON.parse(password_hashes || '[]');
    for (const hash of regularHashes) {
      if (await bcrypt.compare(password, hash)) {
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        return res.json({ ok: true, token });
      }
    }

    // Check regular global passwords
    for (const global of globalResult.rows) {
      if (!global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        return res.json({ ok: true, token });
      }
    }

    return res.status(401).json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error('Authorization error:', err);
    res.status(500).json({ ok: false, error: 'Authorization failed' });
  }
});

// --- Get embed ---
app.get('/api/content/:id/embed', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Missing token' });
    const data = jwt.verify(token, JWT_SECRET);
    const contentId = data.contentId;
    const r = await pool.query('SELECT imdb_id, type AS contentType FROM content WHERE id=$1', [contentId]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Content not found' });
    const { imdb_id, contentType } = r.rows[0];
    const baseUrl = contentType === 'movie' ? EMBED_BASE_MOVIE : EMBED_BASE_TV;
    res.json({ ok: true, url: baseUrl + imdb_id });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// Serve HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
