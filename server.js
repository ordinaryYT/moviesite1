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

const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

function generateCode() {
  return 'om-' + Math.random().toString(36).substr(2, 12).toUpperCase();
}

//
// Ensure tables exist and migrations
//
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS movies (
      id SERIAL PRIMARY KEY,
      title TEXT,
      imdb_id TEXT,
      type TEXT DEFAULT 'movie',
      genre TEXT DEFAULT 'Unknown',
      password_hashes JSONB DEFAULT '[]',
      one_time_password_hashes JSONB DEFAULT '[]',
      year TEXT,
      image TEXT,
      subtitles_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS global_passwords (
      id SERIAL PRIMARY KEY,
      password_hash TEXT,
      is_one_time BOOLEAN DEFAULT FALSE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS om_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE,
      global_password_id INTEGER,
      used BOOLEAN DEFAULT FALSE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bot_config (
      key TEXT PRIMARY KEY,
      value BOOLEAN DEFAULT TRUE
    )
  `);

  await pool.query(`
    INSERT INTO bot_config (key, value) VALUES ('codes_enabled', TRUE)
    ON CONFLICT (key) DO NOTHING
  `);

  // user_favorites table for per-user favorites
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_favorites (
      id SERIAL PRIMARY KEY,
      user_token TEXT,
      movie_id INTEGER REFERENCES movies(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // make sure columns exist if upgrading older schema
  const cols = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'movies'`);
  const colNames = cols.rows.map(r => r.column_name);
  if (!colNames.includes('subtitles_enabled')) {
    await pool.query(`ALTER TABLE movies ADD COLUMN subtitles_enabled BOOLEAN DEFAULT FALSE`);
  }
  if (!colNames.includes('genre')) {
    await pool.query(`ALTER TABLE movies ADD COLUMN genre TEXT DEFAULT 'Unknown'`);
  }
}

//
// Auto-detect genre from TVMaze (using imdb id or title fallback)
//
async function getGenreFromSource(title, imdbId) {
  try {
    if (imdbId) {
      const r = await fetch(`https://api.tvmaze.com/lookup/shows?imdb=${imdbId}`);
      if (r.ok) {
        const data = await r.json();
        if (data.genres && data.genres.length > 0) return data.genres[0];
      }
    }
    const r2 = await fetch(`https://api.tvmaze.com/search/shows?q=${encodeURIComponent(title)}`);
    if (r2.ok) {
      const data = await r2.json();
      if (data.length > 0 && data[0].show.genres && data[0].show.genres.length > 0) {
        return data[0].show.genres[0];
      }
    }
  } catch (e) {
    console.error('Genre fetch error:', e.message || e);
  }
  return 'Unknown';
}

//
// Discord bot & code helpers (preserve original behavior)
//
async function getCodesEnabled() {
  const { rows } = await pool.query('SELECT value FROM bot_config WHERE key = $1', ['codes_enabled']);
  return rows[0] ? rows[0].value : true;
}
async function setCodesEnabled(enabled) {
  await pool.query(
    'INSERT INTO bot_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2',
    ['codes_enabled', enabled]
  );
}
async function deleteAllOMCodes() {
  try {
    await pool.query('DELETE FROM om_codes');
    await pool.query('DELETE FROM global_passwords WHERE is_one_time = TRUE');
    console.log('DELETED ALL OM CODES & ONE-TIME GLOBAL PASSWORDS');
  } catch (err) {
    console.error('Failed to delete OM codes:', err);
  }
}

client.once('ready', async () => {
  console.log('Discord bot ready');
  await deleteAllOMCodes();

  const commands = [
    new SlashCommandBuilder()
      .setName('gencode')
      .setDescription('Generate 1 OM code'),
    new SlashCommandBuilder()
      .setName('toggle-codes')
      .setDescription('Toggle code generation')
      .addStringOption(o => o.setName('state').setRequired(true).addChoices({ name: 'on', value: 'on' }, { name: 'off', value: 'off' }))
  ];

  try {
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_BOT_TOKEN);
    await rest.put(Routes.applicationCommands(client.user.id), {
      body: commands.map(c => c.toJSON())
    });
  } catch (e) {}
});

client.on('interactionCreate', async i => {
  if (!i.isCommand()) return;

  if (i.commandName === 'gencode') {
    const enabled = await getCodesEnabled();
    if (!enabled) {
      return i.reply({ content: 'Code generation is **DISABLED** by admin.', ephemeral: true });
    }

    const code = generateCode();
    const hash = await bcrypt.hash(code, 10);

    const { rows: [gp] } = await pool.query(
      'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, true) RETURNING id',
      [hash]
    );

    await pool.query(
      'INSERT INTO om_codes (code, global_password_id, used) VALUES ($1, $2, FALSE)',
      [code, gp.id]
    );

    const embed = new EmbedBuilder()
      .setColor('#e50914')
      .setTitle('OM One-Time Code')
      .setDescription(`\`\`\`${code}\`\`\``)
      .setFooter({ text: 'One-time use only!' });

    await i.reply({ embeds: [embed] });
  }

  if (i.commandName === 'toggle-codes') {
    if (!i.member.roles.cache.has(process.env.DISCORD_CODE_MANAGER_ROLE_ID))
      return i.reply({ content: 'No permission', ephemeral: true });

    const state = i.options.getString('state');
    const enabled = state === 'on';
    await setCodesEnabled(enabled);

    await i.reply(`Code generation: **${enabled ? 'ENABLED' : 'DISABLED'}**`);
  }
});

if (process.env.DISCORD_BOT_TOKEN) {
  client.login(process.env.DISCORD_BOT_TOKEN).catch(console.error);
}

//
// Initialize DB
//
ensureTables();

// ----------------- API ROUTES -----------------

// GET /api/movies - returns movies with genre
app.get('/api/movies', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, title, type, year, image, subtitles_enabled, genre FROM movies ORDER BY created_at DESC');
    res.json({ ok: true, movies: rows });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, movies: [] });
  }
});

// GET /api/genres - distinct genres present in DB
app.get('/api/genres', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT DISTINCT genre FROM movies WHERE genre IS NOT NULL ORDER BY genre");
    const genres = rows.map(r => r.genre || 'Unknown');
    res.json({ ok: true, genres });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, genres: [] });
  }
});

// --- Admin Login ---
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ ok: true, token });
  } else {
    res.json({ ok: false, error: 'Wrong password' });
  }
});

const requireAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
};

// --- Add Movie (auto-fetch genre)
app.post('/api/movies', requireAdmin, async (req, res) => {
  try {
    const {
      name,
      imdbId,
      contentPasswords = [],
      oneTimePasswords = [],
      type = 'movie',
      subtitlesEnabled = false
    } = req.body;

    if (!name && !imdbId) return res.status(400).json({ ok: false, error: 'Title or IMDb ID required' });

    const genre = await getGenreFromSource(name || imdbId, imdbId);

    const hashes = await Promise.all((contentPasswords || []).map(p => bcrypt.hash(p, 10)));
    const otHashes = await Promise.all((oneTimePasswords || []).map(p => bcrypt.hash(p, 10)));

    const { rows } = await pool.query(
      `INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes, subtitles_enabled, genre)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [name || imdbId, imdbId, type, JSON.stringify(hashes), JSON.stringify(otHashes), subtitlesEnabled, genre]
    );

    res.json({ ok: true, movieId: rows[0].id, genre });
  } catch (err) {
    console.error('Add movie error:', err);
    res.json({ ok: false, error: 'Failed to add movie' });
  }
});

// --- Update subtitles toggle ---
app.patch('/api/movies/:id/subtitles', requireAdmin, async (req, res) => {
  const { subtitlesEnabled } = req.body;
  if (typeof subtitlesEnabled !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'subtitlesEnabled must be boolean' });
  }
  try {
    const { rowCount } = await pool.query('UPDATE movies SET subtitles_enabled = $1 WHERE id = $2', [subtitlesEnabled, req.params.id]);
    res.json({ ok: rowCount > 0 });
  } catch (err) {
    res.json({ ok: false });
  }
});

// --- Delete movie ---
app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM movies WHERE id = $1', [req.params.id]);
    res.json({ ok: rowCount > 0 });
  } catch (err) {
    res.json({ ok: false });
  }
});

// --- Global Passwords management ---
app.post('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  const { password, isOneTime } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query('INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, $2) RETURNING id', [hash, !!isOneTime]);
  res.json({ ok: true, id: rows[0].id });
});

app.get('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, is_one_time, created_at FROM global_passwords');
  res.json({ ok: true, passwords: rows });
});

app.delete('/api/admin/global-passwords/:id', requireAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM global_passwords WHERE id = $1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

// --- Episodes (TV show) ---
app.get('/api/movies/:id/episodes', async (req, res) => {
  const id = req.params.id;
  try {
    const { rows } = await pool.query('SELECT imdb_id, type FROM movies WHERE id = $1', [id]);
    if (!rows[0] || rows[0].type !== 'tv_show') {
      return res.json({ ok: false, error: 'Not a TV show' });
    }

    const imdbId = rows[0].imdb_id;
    const showRes = await fetch(`https://api.tvmaze.com/lookup/shows?imdb=${imdbId}`);
    if (!showRes.ok) throw new Error();
    const show = await showRes.json();

    const epRes = await fetch(`https://api.tvmaze.com/shows/${show.id}/episodes`);
    if (!epRes.ok) throw new Error();
    const eps = await epRes.json();

    const seasons = {};
    eps.forEach(ep => {
      const s = ep.season.toString();
      if (!seasons[s]) seasons[s] = [];
      seasons[s].push({
        episode: ep.number,
        name: ep.name || `Episode ${ep.number}`
      });
    });

    res.json({ ok: true, seasons });
  } catch (err) {
    res.json({ ok: false, error: 'Failed to load episodes' });
  }
});

// --- Authorize password for movie ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.json({ ok: false, error: 'Password required' });

  try {
    const { rows } = await pool.query('SELECT password_hashes, one_time_password_hashes FROM movies WHERE id = $1', [req.params.id]);
    if (!rows[0]) return res.json({ ok: false, error: 'Movie not found' });

    let regular = [], ot = [];
    try { regular = JSON.parse(rows[0].password_hashes || '[]'); } catch { regular = []; }
    try { ot = JSON.parse(rows[0].one_time_password_hashes || '[]'); } catch { ot = []; }

    for (let i = 0; i < ot.length; i++) {
      if (await bcrypt.compare(password, ot[i])) {
        ot.splice(i, 1);
        await pool.query('UPDATE movies SET one_time_password_hashes = $1 WHERE id = $2', [JSON.stringify(ot), req.params.id]);
        return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
      }
    }

    for (const h of regular) {
      if (await bcrypt.compare(password, h)) {
        return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
      }
    }

    const { rows: globals } = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');
    for (const g of globals) {
      if (g.is_one_time && await bcrypt.compare(password, g.password_hash)) {
        await pool.query('DELETE FROM global_passwords WHERE id = $1', [g.id]);
        return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
      }
    }
    for (const g of globals) {
      if (!g.is_one_time && await bcrypt.compare(password, g.password_hash)) {
        return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
      }
    }

    res.json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: 'Error during authorization' });
  }
});

// --- Embed endpoint (subtitles respected) ---
app.get('/api/movies/:id/embed', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { movieId } = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT imdb_id, type, subtitles_enabled FROM movies WHERE id = $1', [movieId]);
    if (!rows[0]) return res.json({ ok: false, error: 'Not found' });

    const { imdb_id, type, subtitles_enabled } = rows[0];
    let url = type === 'movie'
      ? `https://vidsrc.me/embed/movie/${imdb_id}`
      : `https://vidsrc.me/embed/tv/${imdb_id}`;

    if (subtitles_enabled) url += '?sub=en';
    res.json({ ok: true, url });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// ---------------- User Favorites Endpoints ----------------

// GET /api/favorites?user=token  -> returns list of movie ids favorited by user
app.get('/api/favorites', async (req, res) => {
  const token = req.query.user;
  if (!token) return res.json({ ok: false, favorites: [] });
  try {
    const { rows } = await pool.query('SELECT movie_id FROM user_favorites WHERE user_token = $1', [token]);
    res.json({ ok: true, favorites: rows.map(r => r.movie_id) });
  } catch (err) {
    console.error('Favorites fetch error:', err);
    res.json({ ok: false, favorites: [] });
  }
});

// POST /api/favorites/:id  with { user: token }  -> toggles favorite, returns { ok, favorited }
app.post('/api/favorites/:id', async (req, res) => {
  const token = req.body.user;
  const id = parseInt(req.params.id, 10);
  if (!token || !id) return res.json({ ok: false });

  try {
    const exists = await pool.query('SELECT id FROM user_favorites WHERE user_token = $1 AND movie_id = $2', [token, id]);
    if (exists.rows.length > 0) {
      await pool.query('DELETE FROM user_favorites WHERE user_token = $1 AND movie_id = $2', [token, id]);
      return res.json({ ok: true, favorited: false });
    } else {
      await pool.query('INSERT INTO user_favorites (user_token, movie_id) VALUES ($1, $2)', [token, id]);
      return res.json({ ok: true, favorited: true });
    }
  } catch (err) {
    console.error('Toggle favorite error:', err);
    res.json({ ok: false });
  }
});

// ---------------- Serve front-end ----------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
