require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

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

let passwordsDisabled = false;

// --- Auto-create tables ---
async function ensureTable() {
  try {
    // Create movies table with JSONB password fields and type
    await pool.query(`
      CREATE TABLE IF NOT EXISTS movies (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        imdb_id TEXT,
        type TEXT NOT NULL DEFAULT 'movie' CHECK (type IN ('movie', 'tv_show')),
        password_hashes JSONB DEFAULT '[]',
        one_time_password_hashes JSONB DEFAULT '[]',
        year TEXT,
        image TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Movies table ready');

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

    // Migrate old password_hash and one_time_password_hash to JSONB if they exist
    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'movies'
    `);
    const columns = columnsResult.rows.map(row => row.column_name);

    if (columns.includes('password_hash') || columns.includes('one_time_password_hash')) {
      console.log('ℹ️ Migrating old password fields to JSONB...');
      await pool.query(`
        UPDATE movies 
        SET 
          password_hashes = CASE 
            WHEN password_hash IS NOT NULL THEN jsonb_build_array(password_hash) 
            ELSE '[]'::jsonb 
          END,
          one_time_password_hashes = CASE 
            WHEN one_time_password_hash IS NOT NULL THEN jsonb_build_array(one_time_password_hash) 
            ELSE '[]'::jsonb 
          END
      `);
      // Drop old columns after migration
      if (columns.includes('password_hash')) {
        await pool.query('ALTER TABLE movies DROP COLUMN IF EXISTS password_hash');
      }
      if (columns.includes('one_time_password_hash')) {
        await pool.query('ALTER TABLE movies DROP COLUMN IF EXISTS one_time_password_hash');
      }
      console.log('✅ Migrated password fields to JSONB');
    }

    // Add type column if it doesn't exist
    if (!columns.includes('type')) {
      await pool.query('ALTER TABLE movies ADD COLUMN type TEXT NOT NULL DEFAULT \'movie\' CHECK (type IN (\'movie\', \'tv_show\'))');
      console.log('✅ Added type column to movies table');
    }
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
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`IMDb search failed: ${res.status}`);
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
  } catch (err) {
    console.error('IMDb search error:', err);
    return null;
  }
}

// --- Public: list movies ---
app.get('/api/movies', async (_, res) => {
  try {
    const result = await pool.query('SELECT id, title, type, year, image FROM movies ORDER BY created_at DESC');
    console.log(`ℹ️ /api/movies queried movies table, found ${result.rowCount} items`);
    res.json({ ok: true, movies: result.rows });
  } catch (err) {
    console.error('Error in /api/movies:', err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Admin login ---
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ ok: false, error: 'Invalid admin password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ ok: true, token });
});

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

// --- Add Movie or TV Show ---
app.post('/api/movies', requireAdmin, async (req, res) => {
  try {
    const { name, imdbId, contentPasswords, oneTimePasswords, type } = req.body;
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

    const passwordHashes = contentPasswords && contentPasswords.length
      ? await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)))
      : [];
    const oneTimePasswordHashes = oneTimePasswords && oneTimePasswords.length
      ? await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)))
      : [];

    const result = await pool.query(
      'INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes, year, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [contentData.title, contentData.imdb_id, type, JSON.stringify(passwordHashes), JSON.stringify(oneTimePasswordHashes), contentData.year, contentData.image]
    );

    console.log(`ℹ️ Added content ID ${result.rows[0].id}: ${contentData.title} (${type})`);
    res.json({ ok: true, movieId: result.rows[0].id });
  } catch (err) {
    console.error('Add content error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Delete movie ---
app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('DELETE FROM movies WHERE id=$1 RETURNING id', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Content not found' });
    console.log(`ℹ️ Deleted content ID ${id}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete content error:', err);
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
    console.log(`ℹ️ Added global password ID ${result.rows[0].id}`);
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
    console.log(`ℹ️ /api/admin/global-passwords returned ${result.rowCount} passwords`);
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
    console.log(`ℹ️ Deleted global password ID ${id}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete global password error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Toggle Password Protection ---
app.post('/api/admin/toggle-passwords', requireAdmin, async (req, res) => {
  try {
    passwordsDisabled = !passwordsDisabled;
    console.log(`ℹ️ Passwords ${passwordsDisabled ? 'disabled' : 'enabled'}`);
    res.json({ ok: true, disabled: passwordsDisabled });
  } catch (err) {
    console.error('Toggle password error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Get Password Status ---
app.get('/api/admin/password-status', requireAdmin, async (req, res) => {
  try {
    res.json({ ok: true, disabled: passwordsDisabled });
  } catch (err) {
    console.error('Get password status error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Authorize viewer ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ ok: false, error: 'Password required' });
    }

    if (passwordsDisabled) {
      if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ ok: false, error: 'Wrong password' });
      }
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      console.log(`ℹ️ Authorized content ID ${id} with admin password`);
      return res.json({ ok: true, token });
    }

    const r = await pool.query('SELECT password_hashes, one_time_password_hashes, type FROM movies WHERE id=$1', [id]);
    if (!r.rowCount) {
      console.log(`ℹ️ Content ID ${id} not found`);
      return res.status(404).json({ ok: false, error: 'Content not found' });
    }

    const { password_hashes, one_time_password_hashes, type } = r.rows[0];
    let regularHashes = [];
    let oneTimeHashes = [];
    try {
      regularHashes = (typeof password_hashes === 'string' && password_hashes)
        ? JSON.parse(password_hashes)
        : (password_hashes || []);
      oneTimeHashes = (typeof one_time_password_hashes === 'string' && one_time_password_hashes)
        ? JSON.parse(one_time_password_hashes)
        : (one_time_password_hashes || []);
    } catch (parseErr) {
      console.error(`JSON parse error for content ID ${id}:`, parseErr);
      console.log(`ℹ️ password_hashes: ${JSON.stringify(password_hashes)}`);
      console.log(`ℹ️ one_time_password_hashes: ${JSON.stringify(one_time_password_hashes)}`);
      regularHashes = [];
      oneTimeHashes = [];
    }
    if (!Array.isArray(regularHashes)) {
      console.warn(`ℹ️ password_hashes for content ID ${id} is not an array, resetting to []`);
      regularHashes = [];
    }
    if (!Array.isArray(oneTimeHashes)) {
      console.warn(`ℹ️ one_time_password_hashes for content ID ${id} is not an array, resetting to []`);
      oneTimeHashes = [];
    }

    const globalResult = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');

    for (let i = 0; i < oneTimeHashes.length; i++) {
      if (await bcrypt.compare(password, oneTimeHashes[i])) {
        oneTimeHashes.splice(i, 1);
        await pool.query(
          'UPDATE movies SET one_time_password_hashes = $1 WHERE id = $2',
          [JSON.stringify(oneTimeHashes), id]
        );
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with one-time password`);
        return res.json({ ok: true, token });
      }
    }

    for (const global of globalResult.rows) {
      if (global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
        await pool.query('DELETE FROM global_passwords WHERE id = $1', [global.id]);
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with global one-time password`);
        return res.json({ ok: true, token });
      }
    }

    for (const hash of regularHashes) {
      if (await bcrypt.compare(password, hash)) {
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with regular password`);
        return res.json({ ok: true, token });
      }
    }

    for (const global of globalResult.rows) {
      if (!global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with global password`);
        return res.json({ ok: true, token });
      }
    }

    console.log(`ℹ️ Failed to authorize content ID ${id}: Wrong password`);
    return res.status(401).json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error(`Authorization error for content ID ${id}:`, err);
    res.status(500).json({ ok: false, error: 'Authorization failed' });
  }
});

// --- Get embed ---
app.get('/api/movies/:id/embed', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Missing token' });
    const data = jwt.verify(token, JWT_SECRET);
    const movieId = data.movieId;
    const r = await pool.query('SELECT imdb_id, type FROM movies WHERE id=$1', [movieId]);
    if (!r.rowCount) {
      console.log(`ℹ️ Content ID ${movieId} not found for embed`);
      return res.status(404).json({ ok: false, error: 'Content not found' });
    }
    const { imdb_id, type } = r.rows[0];
    const baseUrl = type === 'movie' ? EMBED_BASE_MOVIE : EMBED_BASE_TV;
    const url = baseUrl + imdb_id;
    console.log(`ℹ️ Serving embed URL for content ID ${movieId}: ${url}`);
    res.json({ ok: true, url });
  } catch (err) {
    console.error('Embed error:', err);
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// Serve HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
