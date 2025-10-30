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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// --- Generate ONE OM Code ---
function generateCode() {
  return 'om-' + Math.random().toString(36).substr(2, 12).toUpperCase();
}

// --- Ensure Tables ---
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
}

// --- DELETE ALL OM CODES + GLOBAL ONE-TIME PASSWORDS ---
async function deleteAllOMCodes() {
  try {
    await pool.query('DELETE FROM om_codes');
    await pool.query('DELETE FROM global_passwords WHERE is_one_time = TRUE');
    console.log('DELETED ALL OM CODES & ONE-TIME GLOBAL PASSWORDS');
  } catch (err) {
    console.error('Failed to delete OM codes:', err);
  }
}

// --- Discord Bot ---
client.once('ready', async () => {
  console.log('Discord bot ready');

  // DELETE ALL OM CODES ON START — AFTER TABLES ARE READY
  await deleteAllOMCodes();

  const commands = [
    new SlashCommandBuilder()
      .setName('gencode')
      .setDescription('Generate 1 OM code'),
    new SlashCommandBuilder()
      .setName('toggle-codes')
      .setDescription('Toggle code gen')
      .addStringOption(o => o.setName('state').setRequired(true).addChoices({name:'on',value:'on'},{name:'off',value:'off'}))
  ];

  try {
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_BOT_TOKEN);
    await rest.put(Routes.applicationCommands(client.user.id), {
      body: commands.map(c => c.toJSON())
    });
    console.log('Commands registered');
  } catch (e) {
    console.error('Command registration failed:', e);
  }
});

client.on('interactionCreate', async i => {
  if (!i.isCommand()) return;

  if (i.commandName === 'gencode') {
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
    console.log(`Generated: ${code}`);
  }

  if (i.commandName === 'toggle-codes') {
    if (!i.member.roles.cache.has(process.env.DISCORD_CODE_MANAGER_ROLE_ID))
      return i.reply({ content: 'No permission', ephemeral: true });
    const state = i.options.getString('state');
    await i.reply(`Code generation: ${state === 'on' ? 'ENABLED' : 'DISABLED'}`);
  }
});

if (process.env.DISCORD_BOT_TOKEN) {
  client.login(process.env.DISCORD_BOT_TOKEN).catch(console.error);
}

// --- Start: Setup Tables First ---
ensureTables();

// --- API: Get Movies ---
app.get('/api/movies', async (req, res) => {
  const { rows } = await pool.query('SELECT id, title, type, year, image FROM movies ORDER BY created_at DESC');
  res.json({ ok: true, movies: rows });
});

// --- API: Admin Login ---
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

// --- API: Add Movie ---
app.post('/api/movies', requireAdmin, async (req, res) => {
  const { name, imdbId, contentPasswords = [], oneTimePasswords = [], type = 'movie' } = req.body;
  if (!name && !imdbId) return res.status(400).json({ ok: false, error: 'Title or IMDb ID required' });

  const hashes = await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)));
  const otHashes = await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)));

  const { rows } = await pool.query(
    `INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [name || imdbId, imdbId, type, JSON.stringify(hashes), JSON.stringify(otHashes)]
  );

  res.json({ ok: true, movieId: rows[0].id });
});

// --- API: Delete Movie ---
app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM movies WHERE id = $1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

// --- API: Global Passwords ---
app.post('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  const { password, isOneTime } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, $2) RETURNING id',
    [hash, !!isOneTime]
  );
  res.json({ ok: true, id: rows[0].id });
});

app.get('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, is_one_time FROM global_passwords');
  res.json({ ok: true, passwords: rows });
});

app.delete('/api/admin/global-passwords/:id', requireAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM global_passwords WHERE id = $1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

// --- FIXED: /authorize (SAFE JSON PARSING) ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.json({ ok: false, error: 'Password required' });

  const { rows } = await pool.query(
    'SELECT password_hashes, one_time_password_hashes FROM movies WHERE id = $1',
    [req.params.id]
  );
  if (!rows[0]) return res.json({ ok: false, error: 'Movie not found' });

  let regular = [];
  let ot = [];

  try {
    if (rows[0].password_hashes && typeof rows[0].password_hashes === 'string' && rows[0].password_hashes.trim() !== '') {
      regular = JSON.parse(rows[0].password_hashes);
      if (!Array.isArray(regular)) regular = [];
    }
  } catch (e) {
    console.error('Corrupted password_hashes:', rows[0].password_hashes);
    regular = [];
  }

  try {
    if (rows[0].one_time_password_hashes && typeof rows[0].one_time_password_hashes === 'string' && rows[0].one_time_password_hashes.trim() !== '') {
      ot = JSON.parse(rows[0].one_time_password_hashes);
      if (!Array.isArray(ot)) ot = [];
    }
  } catch (e) {
    console.error('Corrupted one_time_password_hashes:', rows[0].one_time_password_hashes);
    ot = [];
  }

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
});

// --- API: Embed ---
app.get('/api/movies/:id/embed', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { movieId } = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT imdb_id, type FROM movies WHERE id = $1', [movieId]);
    if (!rows[0]) return res.json({ ok: false, error: 'Not found' });
    const base = rows[0].type === 'movie' ? 'https://vidsrc.me/embed/movie/' : 'https://vidsrc.me/embed/tv/';
    res.json({ ok: true, url: base + rows[0].imdb_id });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// --- Serve HTML ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
