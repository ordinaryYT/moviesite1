// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

// If fetch isn't globally available (Render Node 18 usually has it)
const fetch = global.fetch || ((...args) => import('node-fetch').then(({ default: f }) => f(...args)));

const app = express();
app.use(cors());
app.use(express.json());

// Serve static frontend (index.html, etc.)
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'boughton5';
const EMBED_BASE = 'https://multiembed.mov/?video_id=';

// Connect to PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- AUTO MIGRATION ---
async function ensureTable() {
  const sql = `
  CREATE TABLE IF NOT EXISTS movies (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    imdb_id TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    year TEXT,
    image TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
  `;
  await pool.query(sql);
  console.log('✅ Ensured movies table exists');
}
ensureTable().catch(console.error);

// --- Helper: IMDb Search ---
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

// --- Public: List Movies ---
app.get('/api/movies', async (_, res) => {
  try {
    const result = await pool.query('SELECT id, title, year, image FROM movies ORDER BY created_at DESC');
    res.json({ ok: true, movies: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Admin Login ---
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ ok: false, error: 'Invalid admin password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ ok: true, token });
});

// --- Middleware: Require Admin ---
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ ok: false, error: 'Missing auth' });
  const [type, token] = auth.split(' ');
  if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Bad auth header' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

// --- Add Movie (Admin Only) ---
app.post('/api/movies', requireAdmin, async (req, res) => {
  try {
    const { name, moviePassword } = req.body;
    if (!name || !moviePassword)
      return res.status(400).json({ ok: false, error: 'Missing fields' });

    const search = await searchImdb(name);
    if (!search) return res.status(404).json({ ok: false, error: 'No IMDb match' });

    const hash = await bcrypt.hash(moviePassword, 10);
    const result = await pool.query(
      `INSERT INTO movies (title, imdb_id, password_hash, year, image)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (imdb_id) DO UPDATE SET title=EXCLUDED.title
       RETURNING *`,
      [search.title, search.imdb_id, hash, search.year, search.image]
    );
    res.json({ ok: true, movie: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Delete Movie (Admin Only) ---
app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('DELETE FROM movies WHERE id = $1 RETURNING id', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Authorize Viewer for Movie ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  const id = req.params.id;
  const { password } = req.body;
  const r = await pool.query('SELECT password_hash FROM movies WHERE id=$1', [id]);
  if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
  const match = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!match) return res.status(401).json({ ok: false, error: 'Wrong password' });
  const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '10m' });
  res.json({ ok: true, token });
});

// --- Get Embed URL (Authorized) ---
app.get('/api/movies/:id/embed', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Missing token' });
    const data = jwt.verify(token, JWT_SECRET);
    const movieId = data.movieId;
    const r = await pool.query('SELECT imdb_id FROM movies WHERE id=$1', [movieId]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
    const url = EMBED_BASE + r.rows[0].imdb_id;
    res.json({ ok: true, url });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
