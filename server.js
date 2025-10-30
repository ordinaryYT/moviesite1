require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Client, GatewayIntentBits, SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');

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

// --- Discord Bot Config ---
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

// --- Discord Bot Client ---
const discordClient = new Client({ 
  intents: [GatewayIntentBits.Guilds] 
});

// --- Generate 12-digit random alphanumeric suffix ---
function generateCodeSuffix() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 12; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// --- Generate 100 unique one-time codes ---
async function generateStartupCodes() {
  console.log('🔄 Generating 100 unique one-time OM codes...');
  
  // Ensure code lookup table exists
  await pool.query(`
    CREATE TABLE IF NOT EXISTS om_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      global_password_id INTEGER REFERENCES global_passwords(id) ON DELETE CASCADE,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  const target = 100;
  const usedCodes = new Set();
  let generated = 0;

  while (generated < target) {
    const suffix = generateCodeSuffix();
    const code = `om-${suffix}`;

    if (usedCodes.has(code)) continue;

    // Check if code already exists in DB
    const existsCheck = await pool.query('SELECT 1 FROM om_codes WHERE code = $1', [code]);
    if (existsCheck.rowCount > 0) continue;

    // Generate hash and insert to global_passwords
    const hash = await bcrypt.hash(code, 10);
    const globalRes = await pool.query(
      'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, true) RETURNING id',
      [hash]
    );

    // Insert to lookup table
    await pool.query(
      'INSERT INTO om_codes (code, global_password_id) VALUES ($1, $2)',
      [code, globalRes.rows[0].id]
    );

    usedCodes.add(code);
    generated++;
    console.log(`✅ Generated ${generated}/${target}: ${code}`);
  }

  console.log('🎉 100 unique OM one-time codes generated successfully!');
}

// --- Get one unused OM code ---
async function getOneUnusedOMCode() {
  const res = await pool.query(`
    SELECT oc.id, oc.code, gp.id as global_id
    FROM om_codes oc
    JOIN global_passwords gp ON oc.global_password_id = gp.id
    WHERE oc.used = FALSE AND gp.is_one_time = true
    ORDER BY oc.created_at ASC
    LIMIT 1
  `);

  if (!res.rowCount) return null;
  return res.rows[0];
}

// --- Discord Bot Commands ---
const discordCommands = [
  new SlashCommandBuilder()
    .setName('gencode')
    .setDescription('Get one unused OM one-time code')
    .setDefaultMemberPermissions(PermissionFlagsBits.SendMessages),

  new SlashCommandBuilder()
    .setName('toggle-codes')
    .setDescription('Enable/disable code generation (Code Manager only)')
    .addStringOption(option =>
      option.setName('state')
        .setDescription('Enable or disable')
        .setRequired(true)
        .addChoices(
          { name: 'enable', value: 'enable' },
          { name: 'disable', value: 'disable' }
        )
    )
];

// --- Discord Bot Ready Event ---
discordClient.once('ready', async () => {
  console.log(`🤖 Discord bot logged in as ${discordClient.user.tag}`);

  if (DISCORD_GUILD_ID) {
    const guild = discordClient.guilds.cache.get(DISCORD_GUILD_ID);
    if (guild) {
      await guild.commands.set(discordCommands);
      console.log(`✅ Discord slash commands registered in guild ${DISCORD_GUILD_ID}`);
    }
  }
});

// --- Discord Slash Command Handler ---
discordClient.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  const { commandName, options } = interaction;

  if (commandName === 'gencode') {
    if (!codesEnabled) {
      return interaction.reply({ 
        content: '❌ **Code generation is currently DISABLED** by admins.', 
        ephemeral: true 
      });
    }

    const codeData = await getOneUnusedOMCode();
    if (!codeData) {
      return interaction.reply({ 
        content: '❌ **No unused OM codes available!** Contact an admin.', 
        ephemeral: true 
      });
    }

    // Mark as used
    await pool.query('UPDATE om_codes SET used = TRUE WHERE id = $1', [codeData.id]);

    const embed = new EmbedBuilder()
      .setTitle('🎬 OM One-Time Access Code')
      .setDescription(`**Use this code on the website to watch movies:**\n\`\`\`${codeData.code}\`\`\``)
      .setColor('#e50914')
      .setFooter({ text: 'Code is one-time use only!' })
      .setTimestamp();

    await interaction.reply({ embeds: [embed], ephemeral: true });
    console.log(`🎫 OM Code issued to ${interaction.user.tag}: ${codeData.code}`);
  }

  else if (commandName === 'toggle-codes') {
    // Check if user has Code Manager role
    if (!interaction.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) {
      return interaction.reply({ 
        content: '❌ **You need the "Code Manager" role to use this command!**', 
        ephemeral: true 
      });
    }

    const state = options.getString('state');
    codesEnabled = state === 'enable';
    
    const status = codesEnabled ? '✅ ENABLED' : '❌ DISABLED';
    await interaction.reply({ 
      content: `**Code generation is now ${status}** - ${interaction.user}`, 
      ephemeral: false 
    });
    
    console.log(`🔧 Code generation ${status.toLowerCase()} by ${interaction.user.tag}`);
  }
});

// --- Auto-create tables ---
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
    console.log('✅ Movies table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS global_passwords (
        id SERIAL PRIMARY KEY,
        password_hash TEXT NOT NULL,
        is_one_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Global passwords table ready');

    // ... rest of existing table migration code (unchanged) ...
    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'movies'
    `);
    const columns = columnsResult.rows.map(row => row.column_name);
    console.log('ℹ️ Existing columns in movies table:', columns);

    if (!columns.includes('password_hashes')) {
      await pool.query('ALTER TABLE movies ADD COLUMN password_hashes JSONB DEFAULT \'[]\'');
      console.log('✅ Added password_hashes column');
    }
    if (!columns.includes('one_time_password_hashes')) {
      await pool.query('ALTER TABLE movies ADD COLUMN one_time_password_hashes JSONB DEFAULT \'[]\'');
      console.log('✅ Added one_time_password_hashes column');
    }

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
        WHERE password_hash IS NOT NULL OR one_time_password_hash IS NOT NULL
      `);
      console.log('✅ Migrated data to JSONB fields');
      if (columns.includes('password_hash')) {
        await pool.query('ALTER TABLE movies DROP COLUMN IF EXISTS password_hash');
        console.log('✅ Dropped password_hash column');
      }
      if (columns.includes('one_time_password_hash')) {
        await pool.query('ALTER TABLE movies DROP COLUMN IF EXISTS one_time_password_hash');
        console.log('✅ Dropped one_time_password_hash column');
      }
    }

    if (!columns.includes('type')) {
      await pool.query('ALTER TABLE movies ADD COLUMN type TEXT NOT NULL DEFAULT \'movie\' CHECK (type IN (\'movie\', \'tv_show\'))');
      console.log('✅ Added type column to movies table');
    }
  } catch (err) {
    console.error('Error ensuring table schema:', err);
    throw err;
  }
}

// --- Startup sequence ---
async function startup() {
  await ensureTable();
  
  // Generate 100 OM codes on first launch
  await generateStartupCodes();
  
  // Start Discord bot if token provided
  if (DISCORD_BOT_TOKEN) {
    discordClient.login(DISCORD_BOT_TOKEN).catch(console.error);
  }
}

startup().catch(console.error);

// --- [ALL EXISTING ENDPOINTS REMAIN EXACTLY THE SAME - COPIED HERE FOR COMPLETENESS] ---

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

// --- Fetch TV Show Episodes ---
async function fetchEpisodes(imdbId) {
  try {
    const res = await fetch(`https://api.tvmaze.com/lookup/shows?imdb=${imdbId}`);
    if (!res.ok) throw new Error(`TVmaze lookup failed: ${res.status}`);
    const show = await res.json();
    const showId = show.id;
    const episodesRes = await fetch(`https://api.tvmaze.com/shows/${showId}/episodes`);
    if (!episodesRes.ok) throw new Error(`TVmaze episodes failed: ${episodesRes.status}`);
    const episodes = await episodesRes.json();
    const seasons = {};
    episodes.forEach(ep => {
      const season = ep.season.toString();
      if (!seasons[season]) seasons[season] = [];
      seasons[season].push({
        episode: ep.number,
        name: ep.name || `Episode ${ep.number}`,
        id: ep.id
      });
    });
    return { ok: true, seasons };
  } catch (err) {
    console.error('Episode fetch error:', err);
    return { ok: false, error: 'Failed to fetch episodes' };
  }
}

// --- ALL OTHER ENDPOINTS (unchanged) ---
app.get('/api/movies/:id/episodes', async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('SELECT imdb_id, type FROM movies WHERE id=$1', [id]);
    if (!r.rowCount || r.rows[0].type !== 'tv_show') {
      console.log(`ℹ️ Content ID ${id} not found or not a TV show`);
      return res.status(404).json({ ok: false, error: 'TV show not found' });
    }
    const { imdb_id } = r.rows[0];
    const episodeData = await fetchEpisodes(imdb_id);
    if (!episodeData.ok) {
      return res.status(500).json({ ok: false, error: episodeData.error });
    }
    console.log(`ℹ️ Fetched episodes for TV show ID ${id}`);
    res.json(episodeData);
  } catch (err) {
    console.error('Episodes endpoint error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

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
  const [, token] = auth.split(' ');
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

app.post('/api/movies', requireAdmin, async (req, res) => {
  try {
    const { name, imdbId, contentPasswords, oneTimePasswords, type } = req.body;
    if (!name && !imdbId) {
      return res.status(400).json({ ok: false, error: 'Provide title or IMDb ID' });
    }
    if (!['movie', 'tv_show'].includes(type)) {
      return res.status(400).json({ ok: false, error: 'Invalid content type' });
    }

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

    const passwordHashes = contentPasswords && contentPasswords.length
      ? await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)))
      : [];
    const oneTimePasswordHashes = oneTimePasswords && oneTimePasswords.length
      ? await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)))
      : [];

    const result = await pool.query(
      'INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes, year, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [movieData.title, movieData.imdb_id, type, JSON.stringify(passwordHashes), JSON.stringify(oneTimePasswordHashes), movieData.year, movieData.image]
    );

    console.log(`ℹ️ Added content ID ${result.rows[0].id}: ${movieData.title} (${type})`);
    res.json({ ok: true, movieId: result.rows[0].id });
  } catch (err) {
    console.error('Add content error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

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

app.get('/api/admin/password-status', requireAdmin, async (req, res) => {
  try {
    res.json({ ok: true, disabled: passwordsDisabled });
  } catch (err) {
    console.error('Get password status error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

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
      console.log(`ℹ️ Authorized content ID ${id} with admin password`);
      return res.json({ ok: true, token });
    }

    const r = await pool.query('SELECT password_hashes, one_time_password_hashes, type FROM movies WHERE id=$1', [id]);
    if (!r.rowCount) {
      console.log(`ℹ️ Content ID ${id} not found`);
      return res.status(404).json({ ok: false, error: 'Movie not found' });
    }

    const { password_hashes, one_time_password_hashes, type } = r.rows[0];
    let regularHashes = [];
    let oneTimeHashes = [];
    try {
      regularHashes = password_hashes ? JSON.parse(password_hashes) : [];
      oneTimeHashes = one_time_password_hashes ? JSON.parse(one_time_password_hashes) : [];
    } catch (err) {
      console.error(`JSON parse error for content ID ${id}:`, err);
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

    // Check content-specific passwords first
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

    for (const hash of regularHashes) {
      if (await bcrypt.compare(password, hash)) {
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with regular password`);
        return res.json({ ok: true, token });
      }
    }

    // Only check global passwords if no content-specific passwords are set
    if (regularHashes.length === 0 && oneTimeHashes.length === 0) {
      const globalResult = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');
      for (const global of globalResult.rows) {
        if (global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
          await pool.query('DELETE FROM global_passwords WHERE id = $1', [global.id]);
          const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
          console.log(`ℹ️ Authorized content ID ${id} with global one-time password`);
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
    }

    console.log(`ℹ️ Failed to authorize content ID ${id}: Wrong password`);
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
      console.log(`ℹ️ Content ID ${movieId} not found for embed`);
      return res.status(404).json({ ok: false, error: 'Movie not found' });
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🤖 Discord bot ${DISCORD_BOT_TOKEN ? 'started' : 'disabled (no token)'}`);
});
