// server.js (PART 1 of 3)
// Full server file — paste all parts in order into server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Client, GatewayIntentBits, SlashCommandBuilder, EmbedBuilder, REST, Routes } = require('discord.js');
const { Server } = require('socket.io');
const { createServer } = require('http');

const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

/*
  CONFIG
*/
const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || '';
const DISCORD_WISHLIST_CHANNEL_ID = process.env.DISCORD_WISHLIST_CHANNEL_ID || '';
const DISCORD_CODE_MANAGER_ROLE_ID = process.env.DISCORD_CODE_MANAGER_ROLE_ID || '';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_AUTOCODE_CHANNEL_ID = process.env.DISCORD_AUTOCODE_CHANNEL_ID || '';
const OMDB_KEY = process.env.OMDB_KEY || '7f93c41d'; // you already used this in client

// IMPORTANT: set DISCORD_REDIRECT_BASE in env to your deployment base (e.g. https://myapp.onrender.com)
// If not set, fallback to the domain you provided.
const DISCORD_REDIRECT_BASE = process.env.DISCORD_REDIRECT_BASE || 'https://sajdhgaehtoihgaohgjdh.onrender.com';
const DISCORD_REDIRECT_URI = `${DISCORD_REDIRECT_BASE.replace(/\/$/, '')}/api/auth/discord/callback`;

/*
  Postgres pool
*/
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

/*
  Discord client for bot features (not OAuth)
*/
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ]
});

let wishlistChannel = null;
let autoCodeChannel = null;

/*
  Watch Together storage (in-memory)
*/
const watchTogetherRooms = new Map();

function generateCode(prefix = 'om-') {
  return prefix + Math.random().toString(36).substr(2, 12).toUpperCase();
}

function generateRoomCode() {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
}

/*
  Ensure DB tables (safe idempotent)
*/
async function ensureTables() {
  try {
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
        duration TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS global_passwords (
        id SERIAL PRIMARY KEY,
        password_hash TEXT,
        is_one_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS om_codes (
        id SERIAL PRIMARY KEY,
        code TEXT UNIQUE,
        global_password_id INTEGER,
        used BOOLEAN DEFAULT FALSE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS one_time_admin_codes (
        id SERIAL PRIMARY KEY,
        code_hash TEXT,
        used BOOLEAN DEFAULT FALSE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS bot_config (
        key TEXT PRIMARY KEY,
        value BOOLEAN DEFAULT TRUE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        discord_id TEXT UNIQUE,
        discord_username TEXT,
        auto_code_enabled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      INSERT INTO bot_config (key, value) VALUES ('codes_enabled', TRUE)
      ON CONFLICT (key) DO NOTHING;
    `);

    // add duration column if older schema
    await pool.query(`ALTER TABLE movies ADD COLUMN IF NOT EXISTS duration TEXT;`).catch(() => {});
    console.log('Database tables ensured');
  } catch (err) {
    console.error('ensureTables error:', err);
  }
}

async function getCodesEnabled() {
  try {
    const { rows } = await pool.query('SELECT value FROM bot_config WHERE key = $1', ['codes_enabled']);
    return rows[0] ? rows[0].value : true;
  } catch (err) {
    console.error('getCodesEnabled', err);
    return true;
  }
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

/*
  Discord bot readiness & commands
*/
client.once('ready', async () => {
  console.log('Discord bot ready');
  // Clear one-time codes on restart (optional, your original code did this)
  await deleteAllOMCodes().catch(console.error);

  const commands = [
    new SlashCommandBuilder().setName('gencode').setDescription('Generate 1 OM one-time code'),
    new SlashCommandBuilder()
      .setName('toggle-codes')
      .setDescription('Enable / disable code generation')
      .addStringOption(o => o.setName('state').setDescription('on or off').setRequired(true)
        .addChoices({ name: 'on', value: 'on' }, { name: 'off', value: 'off' })),
    new SlashCommandBuilder()
      .setName('genadminlogincode')
      .setDescription('Generate one-time admin login code for adding one content')
  ];

  try {
    if (!DISCORD_BOT_TOKEN) {
      console.warn('No DISCORD_BOT_TOKEN set; skipping command registration');
    } else {
      const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
      await rest.put(Routes.applicationCommands(client.user.id), { body: commands.map(c => c.toJSON()) });
      console.log('Slash commands registered');
    }
  } catch (e) {
    console.error('Failed to register commands:', e);
  }

  if (DISCORD_WISHLIST_CHANNEL_ID) {
    wishlistChannel = await client.channels.fetch(DISCORD_WISHLIST_CHANNEL_ID).catch(console.error);
    if (wishlistChannel) console.log('Wishlist channel ready');
    else console.error('Wishlist channel not found');
  }

  if (DISCORD_AUTOCODE_CHANNEL_ID) {
    autoCodeChannel = await client.channels.fetch(DISCORD_AUTOCODE_CHANNEL_ID).catch(console.error);
    if (autoCodeChannel) console.log('Auto-code channel ready');
    else console.error('Auto-code channel not found');
  }
});

/*
  Bot: handle messages in auto-code channel
*/
client.on('messageCreate', async (message) => {
  if (message.channel.id !== DISCORD_AUTOCODE_CHANNEL_ID || message.author.bot) return;

  // If message includes this phrase, treat as auto-code request trigger
  if (message.content.includes('requested a one-time code for')) {
    const enabled = await getCodesEnabled();
    if (!enabled) {
      return message.reply('Code generation is currently **DISABLED** by admin.');
    }

    // Generate code and store
    const code = generateCode();
    const hash = await bcrypt.hash(code, 10);

    try {
      const { rows: [gp] } = await pool.query(
        'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, true) RETURNING id',
        [hash]
      );

      await pool.query('INSERT INTO om_codes (code, global_password_id, used) VALUES ($1, $2, FALSE)', [code, gp.id]);

      // send to the author via DM
      const user = await client.users.fetch(message.author.id);
      const embed = new EmbedBuilder()
        .setColor('#e50914')
        .setTitle('OM One-Time Code')
        .setDescription(`\`\`\`${code}\`\`\``)
        .setFooter({ text: 'This code will auto-fill on the website!' });

      await user.send({ embeds: [embed] });
      await message.reply(`✅ Code sent to ${message.author.username} via DM!`);
    } catch (err) {
      console.error('auto-code message handler error', err);
      await message.reply('❌ Failed to generate/send code.');
    }
  }
});
// server.js (PART 2 of 3)

client.on('interactionCreate', async (i) => {
  if (!i.isChatInputCommand()) return;

  try {
    if (i.commandName === 'gencode') {
      const enabled = await getCodesEnabled();
      if (!enabled) return i.reply({ content: 'Code generation is **DISABLED** by admin.', ephemeral: true });

      const code = generateCode();
      const hash = await bcrypt.hash(code, 10);

      const { rows: [gp] } = await pool.query(
        'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, true) RETURNING id',
        [hash]
      );

      await pool.query('INSERT INTO om_codes (code, global_password_id, used) VALUES ($1, $2, FALSE)', [code, gp.id]);

      const embed = new EmbedBuilder()
        .setColor('#e50914')
        .setTitle('OM One-Time Code')
        .setDescription(`\`\`\`${code}\`\`\``)
        .setFooter({ text: 'One-time use only!' });

      await i.reply({ embeds: [embed] });
    }

    if (i.commandName === 'toggle-codes') {
      // permission check
      if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) {
        return i.reply({ content: 'No permission', ephemeral: true });
      }
      const state = i.options.getString('state');
      const enabled = state === 'on';
      await setCodesEnabled(enabled);
      await i.reply(`Code generation: **${enabled ? 'ENABLED' : 'DISABLED'}**`);
    }

    if (i.commandName === 'genadminlogincode') {
      if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) {
        return i.reply({ content: 'No permission', ephemeral: true });
      }
      const code = generateCode('admin-');
      const hash = await bcrypt.hash(code, 10);

      await pool.query('INSERT INTO one_time_admin_codes (code_hash, used) VALUES ($1, FALSE)', [hash]);

      const embed = new EmbedBuilder()
        .setColor('#e50914')
        .setTitle('One-Time Admin Login Code')
        .setDescription(`\`\`\`${code}\`\`\``)
        .setFooter({ text: 'Allows adding one content item only!' });

      await i.reply({ embeds: [embed] });
    }
  } catch (err) {
    console.error('interactionCreate error', err);
    try { await i.reply({ content: 'Error executing command', ephemeral: true }); } catch {}
  }
});

if (DISCORD_BOT_TOKEN) {
  client.login(DISCORD_BOT_TOKEN).catch(console.error);
}

/*
  Initialize DB tables
*/
ensureTables();

/*
  Socket.IO (Watch Together)
*/
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('create-room', (data) => {
    const roomCode = generateRoomCode();
    const room = {
      id: roomCode,
      host: socket.id,
      hostName: data.hostName || 'Host',
      isPublic: data.isPublic || false,
      movieTitle: data.movieTitle || 'Unknown',
      maxViewers: 9,
      viewers: new Map(),
      createdAt: new Date()
    };

    room.viewers.set(socket.id, { id: socket.id, name: data.hostName || 'Host', isHost: true });
    watchTogetherRooms.set(roomCode, room);

    socket.join(roomCode);
    socket.emit('room-created', { roomCode, room });
    console.log(`Room created: ${roomCode} by ${socket.id}`);
  });

  socket.on('join-room', (data) => {
    const room = watchTogetherRooms.get(data.roomCode);
    if (!room) {
      socket.emit('room-error', { error: 'Room not found' });
      return;
    }

    if (room.viewers.size >= room.maxViewers) {
      socket.emit('room-error', { error: 'Room is full' });
      return;
    }

    room.viewers.set(socket.id, {
      id: socket.id,
      name: data.viewerName || `Viewer${room.viewers.size}`,
      isHost: false
    });

    socket.join(data.roomCode);
    socket.emit('room-joined', { room });

    socket.to(data.roomCode).emit('viewer-joined', {
      viewer: { id: socket.id, name: data.viewerName || `Viewer${room.viewers.size}` }
    });

    socket.emit('viewers-updated', { viewers: Array.from(room.viewers.values()) });
    console.log(`User ${socket.id} joined room ${data.roomCode}`);
  });

  // WebRTC signaling pass-through
  socket.on('webrtc-offer', (data) => {
    socket.to(data.target).emit('webrtc-offer', { offer: data.offer, sender: socket.id });
  });

  socket.on('webrtc-answer', (data) => {
    socket.to(data.target).emit('webrtc-answer', { answer: data.answer, sender: socket.id });
  });

  socket.on('webrtc-ice-candidate', (data) => {
    socket.to(data.target).emit('webrtc-ice-candidate', { candidate: data.candidate, sender: socket.id });
  });

  socket.on('host-screen-started', (data) => {
    socket.to(data.roomCode).emit('host-screen-started', { hostId: socket.id });
  });

  socket.on('host-screen-stopped', (data) => {
    socket.to(data.roomCode).emit('host-screen-stopped');
  });

  socket.on('chat-message', (data) => {
    const room = watchTogetherRooms.get(data.roomCode);
    if (room) {
      const viewer = room.viewers.get(socket.id);
      io.to(data.roomCode).emit('chat-message', {
        message: data.message,
        sender: viewer?.name || 'Unknown',
        timestamp: new Date().toLocaleTimeString()
      });
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);

    for (const [roomCode, room] of watchTogetherRooms.entries()) {
      if (room.host === socket.id) {
        io.to(roomCode).emit('room-closed', { reason: 'Host left the room' });
        watchTogetherRooms.delete(roomCode);
        console.log(`Room ${roomCode} closed - host disconnected`);
      } else if (room.viewers.has(socket.id)) {
        room.viewers.delete(socket.id);
        socket.to(roomCode).emit('viewer-left', { viewerId: socket.id });
        console.log(`Viewer ${socket.id} left room ${roomCode}`);

        if (room.viewers.size === 0) {
          setTimeout(() => {
            if (!watchTogetherRooms.has(roomCode) || watchTogetherRooms.get(roomCode).viewers.size === 0) {
              watchTogetherRooms.delete(roomCode);
              console.log(`Room ${roomCode} closed - no viewers`);
            }
          }, 300000);
        }
      }
    }
  });
});

/*
  Watch Together API
*/
app.get('/api/watch-together/rooms', (req, res) => {
  try {
    const publicRooms = Array.from(watchTogetherRooms.values())
      .filter(room => room.isPublic && room.viewers.size > 0)
      .map(room => ({
        id: room.id,
        hostName: room.hostName,
        movieTitle: room.movieTitle,
        viewerCount: room.viewers.size,
        maxViewers: room.maxViewers,
        createdAt: room.createdAt
      }));
    res.json({ ok: true, rooms: publicRooms });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/watch-together/room-exists', (req, res) => {
  const { roomCode } = req.body || {};
  const room = watchTogetherRooms.get(roomCode);
  res.json({ ok: true, exists: !!room, isFull: room ? room.viewers.size >= room.maxViewers : false });
});

/*
  Auth middleware
*/
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Invalid token' });
  }
};

const requireFullAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: 'Insufficient permissions' });
  next();
};
// server.js (PART 3 of 3)

/*
  DISCORD OAUTH (fixed) — uses DISCORD_REDIRECT_URI, always HTTPS (configure DISCORD_REDIRECT_BASE env)
*/
app.get('/api/auth/discord', (req, res) => {
  // Use the canonical redirect URI (forced HTTPS)
  const redirectUri = DISCORD_REDIRECT_URI;
  const discordAuthUrl =
    `https://discord.com/api/oauth2/authorize?client_id=${encodeURIComponent(DISCORD_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code&scope=identify`;
  return res.redirect(discordAuthUrl);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');

  try {
    // Exchange code for token
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    const tokenData = await tokenResponse.json();
    if (!tokenData || !tokenData.access_token) {
      console.error('tokenData:', tokenData);
      return res.redirect('/?error=token_failed');
    }

    // Get user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    const userData = await userResponse.json();
    if (!userData || !userData.id) {
      console.error('userData:', userData);
      return res.redirect('/?error=user_failed');
    }

    // Upsert user into DB
    const discordUsername = `${userData.username}#${userData.discriminator || '0000'}`;
    const { rows } = await pool.query(
      `INSERT INTO users (discord_id, discord_username)
        VALUES ($1, $2)
        ON CONFLICT (discord_id)
        DO UPDATE SET discord_username = $2
        RETURNING id`,
      [userData.id, discordUsername]
    );

    const token = jwt.sign({
      userId: rows[0].id,
      discordId: userData.id,
      username: userData.username
    }, JWT_SECRET, { expiresIn: '30d' });

    // Redirect to frontend with token
    return res.redirect(`/?discord_login=success&token=${encodeURIComponent(token)}`);
  } catch (error) {
    console.error('Discord OAuth error:', error);
    return res.redirect('/?error=auth_failed');
  }
});

/*
  User settings endpoints
*/
app.get('/api/user/settings', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT discord_username, auto_code_enabled FROM users WHERE id = $1', [req.user.userId]);
    if (!rows[0]) return res.json({ ok: false, error: 'User not found' });
    res.json({ ok: true, settings: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/user/settings/auto-code', authMiddleware, async (req, res) => {
  const { enabled } = req.body;
  try {
    await pool.query('UPDATE users SET auto_code_enabled = $1 WHERE id = $2', [enabled, req.user.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

/*
  Auto-code request endpoint: sends a message to autoCodeChannel (Discord)
*/
app.post('/api/auto-code/request', authMiddleware, async (req, res) => {
  const { movieTitle, movieId } = req.body;
  try {
    const { rows: userRows } = await pool.query('SELECT discord_username FROM users WHERE id = $1', [req.user.userId]);
    if (!userRows[0]) return res.json({ ok: false, error: 'User not found' });

    const codesEnabled = await getCodesEnabled();
    if (!codesEnabled) return res.json({ ok: false, error: 'Code generation is currently disabled by admin' });

    if (autoCodeChannel) {
      await autoCodeChannel.send(`${userRows[0].discord_username} - requested a one-time code for: **${movieTitle}** (ID: ${movieId})`);
      return res.json({ ok: true, message: 'Code request sent! Check your DMs for the code.' });
    } else {
      return res.json({ ok: false, error: 'Auto-code channel not configured' });
    }
  } catch (err) {
    console.error('Auto-code request error:', err);
    return res.json({ ok: false, error: 'Failed to request code' });
  }
});

/*
  Movies endpoints
*/
app.get('/api/movies', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, title, type, year, image, imdb_id, duration FROM movies ORDER BY created_at DESC');
    res.json({ ok: true, movies: rows });
  } catch (err) {
    console.error('Error fetching movies:', err);
    res.status(500).json({ ok: false, error: 'Failed to load movies' });
  }
});

/*
  Admin login
*/
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ ok: true, token, role: 'admin' });
  } else {
    return res.json({ ok: false, error: 'Wrong password' });
  }
});

/*
  One-time admin login using hashed code
*/
app.post('/api/admin/onetime-login', async (req, res) => {
  const { code } = req.body;
  try {
    const { rows } = await pool.query('SELECT id, code_hash, used FROM one_time_admin_codes');
    for (const r of rows) {
      if (!r.used && await bcrypt.compare(code, r.code_hash)) {
        const token = jwt.sign({ role: 'limited_admin', code_id: r.id }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ ok: true, token, role: 'limited_admin' });
      }
    }
    return res.json({ ok: false, error: 'Invalid or used code' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

/*
  Add movie endpoint (admins and limited_admin)
*/
app.post('/api/movies', authMiddleware, async (req, res) => {
  const { role, code_id } = req.user;
  try {
    if (role === 'limited_admin') {
      const { rows } = await pool.query('SELECT used FROM one_time_admin_codes WHERE id = $1', [code_id]);
      if (!rows[0] || rows[0].used) return res.status(403).json({ ok: false, error: 'Code already used' });
    }

    let { imdbId, contentPasswords = [], oneTimePasswords = [], type = 'movie' } = req.body;
    if (!imdbId) return res.status(400).json({ ok: false, error: 'IMDb ID required' });

    if (!imdbId.startsWith('tt')) imdbId = 'tt' + imdbId;

    const hashes = await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)));
    const otHashes = await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)));

    // initially save with imdbId as title, we'll update after fetching OMDb
    const { rows: inserted } = await pool.query(
      `INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [imdbId, imdbId, type, JSON.stringify(hashes), JSON.stringify(otHashes)]
    );

    const movieId = inserted[0].id;

    // Fetch OMDb details
    let posterUrl = null, finalTitle = imdbId, year = null, duration = null;
    try {
      const omdbRes = await fetch(`https://www.omdbapi.com/?i=${encodeURIComponent(imdbId)}&apikey=${OMDB_KEY}`);
      const omdbData = await omdbRes.json();
      if (omdbData && omdbData.Response !== 'False') {
        if (omdbData.Poster && omdbData.Poster !== 'N/A') posterUrl = omdbData.Poster;
        if (omdbData.Title) finalTitle = omdbData.Title;
        if (omdbData.Year) year = omdbData.Year;
        if (omdbData.Runtime && omdbData.Runtime !== 'N/A') duration = omdbData.Runtime;
      }
    } catch (err) {
      console.error('OMDb fetch failed:', err);
    }

    await pool.query('UPDATE movies SET image = $1, title = $2, year = $3, duration = $4 WHERE id = $5',
      [posterUrl, finalTitle, year, duration, movieId]);

    if (role === 'limited_admin') {
      await pool.query('UPDATE one_time_admin_codes SET used = TRUE WHERE id = $1', [code_id]);
    }

    return res.json({ ok: true, id: movieId });
  } catch (err) {
    console.error('Add movie error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

/*
  Wishlist request endpoint (posts to wishlistChannel if configured)
*/
app.post('/api/wishlist', async (req, res) => {
  const { title, type, imdb_id } = req.body;
  try {
    if (wishlistChannel) {
      await wishlistChannel.send(`Wishlist request: **${title}** (${type}) - ${imdb_id || 'no imdb id'}`);
      return res.json({ ok: true });
    } else {
      return res.json({ ok: false, error: 'Wishlist channel not configured' });
    }
  } catch (err) {
    console.error('wishlist error', err);
    return res.json({ ok: false, error: 'Failed' });
  }
});

/*
  Helpful admin endpoints (toggle codes etc)
*/
app.post('/api/admin/toggle-codes', authMiddleware, requireFullAdmin, async (req, res) => {
  const { enabled } = req.body;
  try {
    await setCodesEnabled(enabled);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

/*
  Utility: fetch trailer via YouTube (basic)
*/
app.get('/api/trailer', async (req, res) => {
  const title = req.query.title || '';
  if (!title) return res.json({ ok: false, error: 'No title' });
  try {
    if (!YOUTUBE_API_KEY) return res.json({ ok: false, error: 'No YouTube API key configured' });

    const q = encodeURIComponent(title);
    const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${q}&key=${YOUTUBE_API_KEY}&maxResults=1&type=video`;
    const r = await fetch(url);
    const data = await r.json();
    if (data.items && data.items.length) {
      const videoId = data.items[0].id.videoId;
      return res.json({ ok: true, url: `https://www.youtube.com/embed/${videoId}` });
    } else {
      return res.json({ ok: false, error: 'No trailer found' });
    }
  } catch (err) {
    console.error('trailer fetch error', err);
    return res.json({ ok: false, error: 'Failed to get trailer' });
  }
});

/*
  Start server
*/
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Discord OAuth redirect base: ${DISCORD_REDIRECT_BASE}`);
});
