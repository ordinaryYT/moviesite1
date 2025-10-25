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
const EMBED_BASE = 'https://vidsrc.me/embed/movie/';

// --- PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- Auto-create table and ensure one_time_password_hash column ---
async function ensureTable() {
  try {
    await pool.query(
      'CREATE TABLE IF NOT EXISTS movies (\n' +
      '  id SERIAL PRIMARY KEY,\n' +
      '  title TEXT NOT NULL,\n' +
      '  imdb_id TEXT,\n' +
      '  password_hash TEXT,\n' +
      '  one_time_password_hash TEXT,\n' +
      '  year TEXT,\n' +
      '  image TEXT,\n' +
      '  created_at TIMESTAMP DEFAULT NOW()\n' +
      ')'
    );
    console.log('✅ Movies table ready');

    await pool.query(
      'DO $$\n' +
      'BEGIN\n' +
      '  IF NOT EXISTS (\n' +
      '    SELECT FROM pg_attribute\n' +
      '    WHERE attrelid = \'movies\'::regclass\n' +
      '    AND attname = \'one_time_password_hash\'\n' +
      '  ) THEN\n' +
      '    ALTER TABLE movies\n' +
      '    ADD COLUMN one_time_password_hash TEXT;\n' +
      '  END IF;\n' +
      'END $$;'
    );
    console.log('✅ one_time_password_hash column ensured');
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

// --- Public: list movies ---
app.get('/api/movies', async (_, res) => {
  try {
    const result = await pool.query('SELECT id, title, year, image FROM movies ORDER BY created_at DESC');
    res.json({ ok: true, movies: result.rows });
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

// --- Add Movie ---
app.post('/api/movies', requireAdmin, async (req, res) => {
  try {
    const { name, imdbId, moviePassword, oneTimePassword } = req.body;
    if ((!name && !imdbId) || !moviePassword)
      return res.status(400).json({ ok: false, error: 'Provide movie name or IMDb ID and password' });

    let movieData;
    if (imdbId) {
      movieData = {
        imdb_id: imdbId.startsWith('tt') ? imdbId : 'tt' + imdbId,
        title: name || imdbId,
        year: null,
        image: null
      };
    } else {
      const search = await searchImdb(name);
      if (!search) return res.status(404).json({ ok: false, error: 'No IMDb match found' });
      movieData = search;
    }

    const passwordHash = await bcrypt.hash(moviePassword, 10);
    const oneTimePasswordHash = oneTimePassword ? await bcrypt.hash(oneTimePassword, 10) : null;

    const result = await pool.query(
      'INSERT INTO movies (title, imdb_id, password_hash, one_time_password_hash, year, image) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [movieData.title, movieData.imdb_id, passwordHash, oneTimePasswordHash, movieData.year, movieData.image]
    );

    res.json({ ok: true, movieId: result.rows[0].id });
  } catch (err) {
    console.error('Add movie error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Delete movie ---
app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('DELETE FROM movies WHERE id=$1 RETURNING id', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Authorize viewer ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    const r = await pool.query('SELECT password_hash, one_time_password_hash FROM movies WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });

    const { password_hash, one_time_password_hash } = r.rows[0];

    if (one_time_password_hash && await bcrypt.compare(password, one_time_password_hash)) {
      await pool.query('UPDATE movies SET one_time_password_hash = NULL WHERE id = $1', [id]);
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      return res.json({ ok: true, token });
    }

    if (password_hash && await bcrypt.compare(password, password_hash)) {
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      return res.json({ ok: true, token });
    }

    return res.status(401).json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error('Authorization error:', err);
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
    const r = await pool.query('SELECT imdb_id FROM movies WHERE id=$1', [movieId]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
    res.json({ ok: true, url: EMBED_BASE + r.rows[0].imdb_id });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// --- Serve static index.html ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
