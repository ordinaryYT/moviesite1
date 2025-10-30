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
  PermissionFlagsBits,
  EmbedBuilder,
  REST,
  Routes
} = require('discord.js');

const fetch = global.fetch || ((...args) => import('node-fetch').then(({default: f}) => f(...args)));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'boughton5';
const EMBED_BASE_MOVIE = 'https://vidsrc.me/embed/movie/';
const EMBED_BASE_TV = 'https://vidsrc.me/embed/tv/';

// --- Discord Config ---
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const DISCORD_CODE_MANAGER_ROLE_ID = process.env.DISCORD_CODE_MANAGER_ROLE_ID;
let codesEnabled = true;

// --- PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

let passwordsDisabled = false;

// --- Discord Client ---
const discordClient = new Client({ intents: [GatewayIntentBits.Guilds] });

// --- Generate 12-char random suffix ---
function generateCodeSuffix() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 12; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// --- Generate 100 unique OM codes on startup ---
async function generateStartupCodes() {
  console.log('Generating 100 unique OM one-time codes...');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS om_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      global_password_id INTEGER REFERENCES global_passwords(id) ON DELETE CASCADE,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  const { rows } = await pool.query(`SELECT COUNT(*) FROM om_codes WHERE used = FALSE`);
  const existing = parseInt(rows[0].count, 10);
  if (existing >= 100) {
    console.log(`Already have ${existing} unused codes. Skipping.`);
    return;
  }

  const target = 100 - existing;
  const used = new Set();
  let count = 0;

  while (count < target) {
    const code = `om-${generateCodeSuffix()}`;
    if (used.has(code)) continue;

    const exists = await pool.query('SELECT 1 FROM om_codes WHERE code = $1', [code]);
    if (exists.rowCount > 0) continue;

    const hash = await bcrypt.hash(code, 10);
    const { rows: [global] } = await pool.query(
      'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, true) RETURNING id',
      [hash]
    );

    await pool.query(
      'INSERT INTO om_codes (code, global_password_id) VALUES ($1, $2)',
      [code, global.id]
    );

    used.add(code);
    count++;
    console.log(`Generated [${count}/${target}]: ${code}`);
  }

  console.log('100 OM codes ready!');
}

// --- Get one unused OM code ---
async function getOneUnusedOMCode() {
  const { rows } = await pool.query(`
    SELECT id, code FROM om_codes WHERE used = FALSE ORDER BY created_at LIMIT 1
  `);
  return rows[0] || null;
}

// --- Discord Slash Commands ---
const discordCommands = [
  new SlashCommandBuilder()
    .setName('gencode')
    .setDescription('Get one OM one-time access code')
    .setDefaultMemberPermissions(PermissionFlagsBits.SendMessages),

  new SlashCommandBuilder()
    .setName('toggle-codes')
    .setDescription('Enable/disable code generation (Code Manager only)')
    .addStringOption(opt =>
      opt.setName('state')
        .setDescription('on or off')
        .setRequired(true)
        .addChoices({ name: 'Enable', value: 'enable' }, { name: 'Disable', value: 'disable' })
    )
];

// --- Register Commands ---
async function registerCommands() {
  if (!DISCORD_BOT_TOKEN) return console.log('No bot token → skipping commands');

  const rest = new REST().setToken(DISCORD_BOT_TOKEN);
  const clientId = discordClient.user?.id;
  if (!clientId) return;

  const cmds = discordCommands.map(c => c.toJSON());

  try {
    if (DISCORD_GUILD_ID) {
      await rest.put(Routes.applicationGuildCommands(clientId, DISCORD_GUILD_ID), { body: cmds });
      console.log(`Guild commands registered in ${DISCORD_GUILD_ID}`);
    }
    await rest.put(Routes.applicationCommands(clientId), { body: cmds });
    console.log('Global commands registered');
  } catch (err) {
    console.error('Command registration failed:', err);
  }
}

// --- Discord Ready ---
discordClient.once('ready', () => {
  console.log(`Discord bot online: ${discordClient.user.tag}`);
  registerCommands();
});

// --- Discord Interaction Handler ---
discordClient.on('interactionCreate', async (i) => {
  if (!i.isChatInputCommand()) return;

  if (i.commandName === 'gencode') {
    if (!codesEnabled) {
      return i.reply({ content: 'Code generation is **disabled**.', ephemeral: true });
    }

    const code = await getOneUnusedOMCode();
    if (!code) {
      return i.reply({ content: 'No codes left! Contact admin.', ephemeral: true });
    }

    await pool.query('UPDATE om_codes SET used = TRUE WHERE id = $1', [code.id]);

    const embed = new EmbedBuilder()
      .setTitle('OM One-Time Code')
      .setDescription(`\`\`\`${code.code}\`\`\``)
      .setColor('#e50914')
      .setFooter({ text: 'One-time use only!' });

    // FIXED: Show to everyone
    await i.reply({ embeds: [embed] });
    console.log(`Code issued: ${code.code} → ${i.user.tag}`);
  }

  if (i.commandName === 'toggle-codes') {
    if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) {
      return i.reply({ content: 'You need **Code Manager** role!', ephemeral: true });
    }

    const state = i.options.getString('state');
    codesEnabled = state === 'enable';

    await i.reply({ content: `Code generation: **${codesEnabled ? 'ENABLED' : 'DISABLED'}**` });
    console.log(`Toggled by ${i.user.tag}: ${codesEnabled}`);
  }
});

// --- Start Discord Bot ---
if (DISCORD_BOT_TOKEN) {
  discordClient.login(DISCORD_BOT_TOKEN).catch(console.error);
}

// --- Table Setup ---
async function ensureTable() {
  try {
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
    await pool.query(`
      CREATE TABLE IF NOT EXISTS global_passwords (
        id SERIAL PRIMARY KEY,
        password_hash TEXT NOT NULL,
        is_one_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    const cols = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'movies'`);
    const columns = cols.rows.map(r => r.column_name);

    if (!columns.includes('password_hashes')) {
      await pool.query(`ALTER TABLE movies ADD COLUMN password_hashes JSONB DEFAULT '[]'`);
    }
    if (!columns.includes('one_time_password_hashes')) {
      await pool.query(`ALTER TABLE movies ADD COLUMN one_time_password_hashes JSONB DEFAULT '[]'`);
    }
    if (!columns.includes('type')) {
      await pool.query(`ALTER TABLE movies ADD COLUMN type TEXT NOT NULL DEFAULT 'movie' CHECK (type IN ('movie', 'tv_show'))`);
    }

    if (columns.includes('password_hash') || columns.includes('one_time_password_hash')) {
      await pool.query(`
        UPDATE movies 
        SET password_hashes = COALESCE(jsonb_build_array(password_hash), '[]'),
            one_time_password_hashes = COALESCE(jsonb_build_array(one_time_password_hash), '[]')
        WHERE password_hash IS NOT NULL OR one_time_password_hash IS NOT NULL
      `);
      if (columns.includes('password_hash')) await pool.query(`ALTER TABLE movies DROP COLUMN IF EXISTS password_hash`);
      if (columns.includes('one_time_password_hash')) await pool.query(`ALTER TABLE movies DROP COLUMN IF EXISTS one_time_password_hash`);
    }
  } catch (err) {
    console.error('Table setup error:', err);
    throw err;
  }
}

// --- Startup ---
async function startup() {
  await ensureTable();
  await generateStartupCodes();
}
startup().catch(console.error);

// --- IMDb Search ---
async function searchImdb(title) {
  const q = encodeURIComponent(title);
  const url = `https://search.imdbot.workers.dev/?q=${q}`;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`IMDb failed: ${res.status}`);
    const data = await res.json();
    const hit = (data.description || []).find(h => h['#IMDB_ID']);
    if (!hit) return null;
    const imdb_id = hit['#IMDB_ID'].startsWith('tt') ? hit['#IMDB_ID'] : 'tt' + hit['#IMDB_ID'];
    return { imdb_id, title: hit['#TITLE'] || title, year: hit['#YEAR'], image: hit.image };
  } catch (err) {
    console.error('IMDb error:', err);
    return null;
  }
}

// --- TV Episodes ---
async function fetchEpisodes(imdbId) {
  try {
    const res = await fetch(`https://api.tvmaze.com/lookup/shows?imdb=${imdbId}`);
    if (!res.ok) throw new Error(`TVmaze lookup failed`);
    const show = await res.json();
    const epRes = await fetch(`https://api.tvmaze.com/shows/${show.id}/episodes`);
    if (!epRes.ok) throw new Error(`Episodes failed`);
    const eps = await epRes.json();
    const seasons = {};
    eps.forEach(ep => {
      const s = ep.season.toString();
      if (!seasons[s]) seasons[s] = [];
      seasons[s].push({ episode: ep.number, name: ep.name || `Episode ${ep.number}`, id: ep.id });
    });
    return { ok: true, seasons };
  } catch (err) {
    console.error('Episode fetch error:', err);
    return { ok: false, error: 'Failed to fetch episodes' };
  }
}

// --- API Routes ---
app.get('/api/movies/:id/episodes', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT imdb_id, type FROM movies WHERE id=$1', [req.params.id]);
    if (!rows.length || rows[0].type !== 'tv_show') return res.status(404).json({ ok: false, error: 'Not a TV show' });
    const data = await fetchEpisodes(rows[0].imdb_id);
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/movies', async (_, res) => {
  const { rows } = await pool.query('SELECT id, title, type, year, image FROM movies ORDER BY created_at DESC');
  res.json({ ok: true, movies: rows });
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ ok: true, token });
  } else {
    res.status(401).json({ ok: false, error: 'Invalid password' });
  }
});

function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'Missing token' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

app.post('/api/movies', requireAdmin, async (req, res) => {
  const { name, imdbId, contentPasswords, oneTimePasswords, type } = req.body;
  if (!name && !imdbId) return res.status(400).json({ ok: false, error: 'Title or IMDb ID required' });
  if (!['movie', 'tv_show'].includes(type)) return res.status(400).json({ ok: false, error: 'Invalid type' });

  let movieData = imdbId
    ? { imdb_id: imdbId.startsWith('tt') ? imdbId : 'tt' + imdbId, title: name || imdbId }
    : await searchImdb(name);

  if (!movieData) return res.status(404).json({ ok: false, error: 'Not found on IMDb' });

  const hashes = contentPasswords ? await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10))) : [];
  const otHashes = oneTimePasswords ? await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10))) : [];

  const { rows } = await pool.query(
    `INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes, year, image)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [movieData.title, movieData.imdb_id, type, JSON.stringify(hashes), JSON.stringify(otHashes), movieData.year, movieData.image]
  );

  res.json({ ok: true, movieId: rows[0].id });
});

app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM movies WHERE id=$1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

app.post('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  const { password, isOneTime } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, $2) RETURNING id',
    [hash, !!isOneTime]
  );
  res.json({ ok: true, passwordId: rows[0].id });
});

app.get('/api/admin/global-passwords', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, is_one_time, created_at FROM global_passwords ORDER BY created_at DESC');
  res.json({ ok: true, passwords: rows });
});

app.delete('/api/admin/global-passwords/:id', requireAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM global_passwords WHERE id=$1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

app.post('/api/admin/toggle-passwords', requireAdmin, async (req, res) => {
  passwordsDisabled = !passwordsDisabled;
  res.json({ ok: true, disabled: passwordsDisabled });
});

app.get('/api/admin/password-status', requireAdmin, async (req, res) => {
  res.json({ ok: true, disabled: passwordsDisabled });
});

// --- FIXED: /authorize (safe JSON parsing) ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) return res.status(400).json({ ok: false, error: 'Password required' });

    if (passwordsDisabled) {
      if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ ok: false, error: 'Wrong password' });
      }
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      console.log(`Authorized content ID ${id} with admin password`);
      return res.json({ ok: true, token });
    }

    const r = await pool.query('SELECT password_hashes, one_time_password_hashes, type FROM movies WHERE id=$1', [id]);
    if (!r.rowCount) {
      console.log(`Content ID ${id} not found`);
      return res.status(404).json({ ok: false, error: 'Movie not found' });
    }

    const { password_hashes, one_time_password_hashes } = r.rows[0];

    // FIXED: Safe JSON parsing
    let regularHashes = [];
    let oneTimeHashes = [];

    try {
      if (password_hashes) {
        const parsed = JSON.parse(password_hashes);
        regularHashes = Array.isArray(parsed) ? parsed : [];
      }
    } catch (err) {
      console.error(`Invalid JSON in password_hashes for content ID ${id}:`, err);
      regularHashes = [];
    }

    try {
      if (one_time_password_hashes) {
        const parsed = JSON.parse(one_time_password_hashes);
        oneTimeHashes = Array.isArray(parsed) ? parsed : [];
      }
    } catch (err) {
      console.error(`Invalid JSON in one_time_password_hashes for content ID ${id}:`, err);
      oneTimeHashes = [];
    }

    // Check per-movie one-time passwords
    for (let i = 0; i < oneTimeHashes.length; i++) {
      if (await bcrypt.compare(password, oneTimeHashes[i])) {
        oneTimeHashes.splice(i, 1);
        await pool.query(
          'UPDATE movies SET one_time_password_hashes = $1 WHERE id = $2',
          [JSON.stringify(oneTimeHashes), id]
        );
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`Authorized content ID ${id} with per-movie one-time password`);
        return res.json({ ok: true, token });
      }
    }

    // Check per-movie regular passwords
    for (const hash of regularHashes) {
      if (await bcrypt.compare(password, hash)) {
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`Authorized content ID ${id} with per-movie regular password`);
        return res.json({ ok: true, token });
      }
    }

    // Only check global passwords if no per-movie passwords
    if (regularHashes.length === 0 && oneTimeHashes.length === 0) {
      const globalResult = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');
      for (const global of globalResult.rows) {
        if (global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
          await pool.query('DELETE FROM global_passwords WHERE id = $1', [global.id]);
          const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
          console.log(`Authorized content ID ${id} with global one-time password`);
          return res.json({ ok: true, token });
        }
      }
      for (const global of globalResult.rows) {
        if (!global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
          const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
          console.log(`Authorized content ID ${id} with global regular password`);
          return res.json({ ok: true, token });
        }
      }
    }

    console.log(`Failed to authorize content ID ${id}: Wrong password`);
    return res.status(401).json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error(`Authorization error for content ID ${id}:`, err);
    res.status(500).json({ ok: false, error: 'Authorization failed' });
  }
});

app.get('/api/movies/:id/embed', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [, token] = auth.split(' ');
    const data = jwt.verify(token, JWT_SECRET);
    const movieId = data.movieId;
    const r = await pool.query('SELECT imdb_id, type FROM movies WHERE id=$1', [movieId]);
    if (!r.rowCount) {
      console.log(`Content ID ${movieId} not found for embed`);
      return res.status(404).json({ ok: false, error: 'Movie not found' });
    }
    const { imdb_id, type } = r.rows[0];
    const baseUrl = type === 'movie' ? EMBED_BASE_MOVIE : EMBED_BASE_TV;
    const url = baseUrl + imdb_id;
    console.log(`Serving embed URL for content ID ${movieId}: ${url}`);
    res.json({ ok: true, url });
  } catch (err) {
    console.error('Embed error:', err);
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
