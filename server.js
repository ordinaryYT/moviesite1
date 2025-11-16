// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const {
  Client,
  GatewayIntentBits,
  SlashCommandBuilder,
  EmbedBuilder,
  REST,
  Routes
} = require('discord.js');

const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const OMDb_KEY = '7f93c41d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// === NON-EXPIRING ROOMS ===
const activeRooms = new Map(); // code → { title, year, isPrivate }

function generateCode() {
  return Math.random().toString(36).substr(2, 8).toUpperCase();
}

// === DISCORD BOT (keep your existing) ===
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS movies (
      id SERIAL PRIMARY KEY,
      title TEXT,
      imdb_id TEXT,
      type TEXT DEFAULT 'movie',
      password_hashes JSONB DEFAULT '[]',
      one_time_password_hashes JSONB DEFAULT '[]',
      year TEXT,
      image TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // ... add other tables as needed
}
ensureTables();

// === MOVIE ROUTES ===
app.get('/api/movies', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, title, type, year, image, imdb_id FROM movies ORDER BY created_at DESC'
  );
  res.json({ ok: true, movies: rows });
});

// === WATCH-TOGETHER API ===
app.post('/api/wt-rooms', (req, res) => {
  let { title, year, isPrivate } = req.body;
  const code = generateCode();

  activeRooms.set(code, {
    title: title || 'Watch Party',
    year: year || new Date().getFullYear(),
    isPrivate: !!isPrivate
  });

  res.json({ ok: true, code });
});

app.get('/api/wt-rooms', (req, res) => {
  const rooms = Array.from(activeRooms.entries())
    .map(([code, data]) => ({ ...data, code }))
    .slice(0, 10);
  res.json({ ok: true, rooms });
});

app.delete('/api/wt-rooms/:code', (req, res) => {
  const { code } = req.params;
  const existed = activeRooms.delete(code);
  res.json({ ok: existed });
});

// === SERVE WEBSITE ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
