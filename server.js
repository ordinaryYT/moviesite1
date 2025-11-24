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
const { Server } = require('socket.io');
const { createServer } = require('http');

const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

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
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY;
const DISCORD_WISHLIST_CHANNEL_ID = process.env.DISCORD_WISHLIST_CHANNEL_ID;
const DISCORD_CODE_MANAGER_ROLE_ID = process.env.DISCORD_CODE_MANAGER_ROLE_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_AUTOCODE_CHANNEL_ID = process.env.DISCORD_AUTOCODE_CHANNEL_ID;
const OMDb_KEY = '7f93c41d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const client = new Client({ 
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ] 
});

let wishlistChannel = null;
let autoCodeChannel = null;

// Watch Together rooms storage
const watchTogetherRooms = new Map();

// Redirect system
let redirectEnabled = false;

function generateCode(prefix = 'om-') {
  return prefix + Math.random().toString(36).substr(2, 12).toUpperCase();
}

function generateRoomCode() {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
}

async function ensureTables() {
  console.log('Ensuring database tables exist...');
  
  // Add duration column if it doesn't exist
  await pool.query(`
    ALTER TABLE movies ADD COLUMN IF NOT EXISTS duration TEXT;
  `).catch(err => {
    console.log('Duration column already exists or error:', err.message);
  });

  // Add overlay_enabled column if it doesn't exist
  await pool.query(`
    ALTER TABLE movies ADD COLUMN IF NOT EXISTS overlay_enabled BOOLEAN DEFAULT FALSE;
  `).catch(err => {
    console.log('Overlay enabled column already exists or error:', err.message);
  });

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
      overlay_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS global_passwords (
      id SERIAL PRIMARY KEY,
      password_hash TEXT,
      is_one_time BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
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
    CREATE TABLE IF NOT EXISTS one_time_admin_codes (
      id SERIAL PRIMARY KEY,
      code_hash TEXT,
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
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      discord_id TEXT UNIQUE,
      discord_username TEXT,
      auto_code_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    INSERT INTO bot_config (key, value) VALUES ('codes_enabled', TRUE)
    ON CONFLICT (key) DO NOTHING
  `);
  
  console.log('Database tables ensured');
}

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
      .setDescription('Generate 1 OM one-time code'),
    new SlashCommandBuilder()
      .setName('toggle-codes')
      .setDescription('Enable / disable code generation')
      .addStringOption(o =>
        o.setName('state')
         .setDescription('on or off')
         .setRequired(true)
         .addChoices({ name: 'on', value: 'on' }, { name: 'off', value: 'off' })
      ),
    new SlashCommandBuilder()
      .setName('genadminlogincode')
      .setDescription('Generate one-time admin login code for adding one content'),
    new SlashCommandBuilder()
      .setName('123')
      .setDescription('123')
  ];

  try {
    const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
    await rest.put(Routes.applicationCommands(client.user.id), {
      body: commands.map(c => c.toJSON())
    });
    console.log('Slash commands registered');
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

// Handle auto-code requests from users
client.on('messageCreate', async (message) => {
  if (message.channel.id !== DISCORD_AUTOCODE_CHANNEL_ID || message.author.bot) return;

  // Check if this is an auto-code request
  if (message.content.includes('requested a one-time code for')) {
    const enabled = await getCodesEnabled();
    if (!enabled) {
      return message.reply('Code generation is currently **DISABLED** by admin.');
    }

    // Extract discord username from message
    const discordUser = message.content.split(' - ')[0];
    
    // Generate code
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

    // Send code to user via DM
    try {
      const user = await client.users.fetch(message.author.id);
      const embed = new EmbedBuilder()
        .setColor('#e50914')
        .setTitle('OM One-Time Code')
        .setDescription(`\`\`\`${code}\`\`\``)
        .setFooter({ text: 'This code will auto-fill on the website!' });
      
      await user.send({ embeds: [embed] });
      await message.reply(`✅ Code sent to ${discordUser} via DM!`);
    } catch (err) {
      await message.reply('❌ Failed to send DM. Please enable DMs from server members.');
    }
  }
});

client.on('interactionCreate', async i => {
  if (!i.isChatInputCommand()) return;

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
    if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID))
      return i.reply({ content: 'No permission', ephemeral: true });

    const state = i.options.getString('state');
    const enabled = state === 'on';
    await setCodesEnabled(enabled);
    await i.reply(`Code generation: **${enabled ? 'ENABLED' : 'DISABLED'}**`);
  }

  if (i.commandName === 'genadminlogincode') {
    if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID))
      return i.reply({ content: 'No permission', ephemeral: true });

    const code = generateCode('admin-');
    const hash = await bcrypt.hash(code, 10);

    await pool.query(
      'INSERT INTO one_time_admin_codes (code_hash, used) VALUES ($1, FALSE)',
      [hash]
    );

    const embed = new EmbedBuilder()
      .setColor('#e50914')
      .setTitle('One-Time Admin Login Code')
      .setDescription(`\`\`\`${code}\`\`\``)
      .setFooter({ text: 'Allows adding one content item only!' });

    await i.reply({ embeds: [embed] });
  }

  if (i.commandName === '123') {
    if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) {
      return i.reply({ content: 'No permission', ephemeral: true });
    }

    redirectEnabled = !redirectEnabled;
    
    // Disable code generation when redirect is enabled
    if (redirectEnabled) {
      await setCodesEnabled(false);
    }
    
    // Send redirect command to all connected clients
    io.emit('electron-redirect', { 
      enabled: redirectEnabled,
      redirectUrl: 'https://sajdhgaehtoihgaohgjdh.onrender.com',
      timestamp: Date.now()
    });

    console.log(`Redirect system ${redirectEnabled ? 'ENABLED' : 'DISABLED'} by ${i.user.tag}`);

    await i.reply(`Redirect system: **${redirectEnabled ? 'ENABLED' : 'DISABLED'}**`);
  }
});

if (DISCORD_BOT_TOKEN) {
  client.login(DISCORD_BOT_TOKEN).catch(console.error);
}

ensureTables();

// Socket.IO for Watch Together
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Send current redirect state to new connections
  socket.emit('electron-redirect', { 
    enabled: redirectEnabled,
    redirectUrl: 'https://sajdhgaehtoihgaohgjdh.onrender.com'
  });

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
    
    // Notify all viewers about new viewer
    socket.to(data.roomCode).emit('viewer-joined', {
      viewer: { id: socket.id, name: data.viewerName || `Viewer${room.viewers.size}` }
    });

    // Send current viewers list to new viewer
    socket.emit('viewers-updated', { 
      viewers: Array.from(room.viewers.values()) 
    });

    console.log(`User ${socket.id} joined room ${data.roomCode}`);
  });

  // WebRTC signaling
  socket.on('webrtc-offer', (data) => {
    socket.to(data.target).emit('webrtc-offer', {
      offer: data.offer,
      sender: socket.id
    });
  });

  socket.on('webrtc-answer', (data) => {
    socket.to(data.target).emit('webrtc-answer', {
      answer: data.answer,
      sender: socket.id
    });
  });

  socket.on('webrtc-ice-candidate', (data) => {
    socket.to(data.target).emit('webrtc-ice-candidate', {
      candidate: data.candidate,
      sender: socket.id
    });
  });

  socket.on('host-screen-started', (data) => {
    socket.to(data.roomCode).emit('host-screen-started', {
      hostId: socket.id
    });
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
    
    // Find and clean up rooms where this user was host or viewer
    for (const [roomCode, room] of watchTogetherRooms.entries()) {
      if (room.host === socket.id) {
        // Host disconnected - close room
        io.to(roomCode).emit('room-closed', { reason: 'Host left the room' });
        watchTogetherRooms.delete(roomCode);
        console.log(`Room ${roomCode} closed - host disconnected`);
      } else if (room.viewers.has(socket.id)) {
        // Viewer disconnected
        room.viewers.delete(socket.id);
        socket.to(roomCode).emit('viewer-left', { viewerId: socket.id });
        console.log(`Viewer ${socket.id} left room ${roomCode}`);
        
        // If no viewers left, close room after 5 minutes
        if (room.viewers.size === 0) {
          setTimeout(() => {
            if (watchTogetherRooms.get(roomCode)?.viewers.size === 0) {
              watchTogetherRooms.delete(roomCode);
              console.log(`Room ${roomCode} closed - no viewers`);
            }
          }, 300000);
        }
      }
    }
  });
});

// Watch Together API endpoints
app.get('/api/watch-together/rooms', (req, res) => {
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
});

app.post('/api/watch-together/room-exists', (req, res) => {
  const { roomCode } = req.body;
  const room = watchTogetherRooms.get(roomCode);
  res.json({ ok: true, exists: !!room, isFull: room ? room.viewers.size >= room.maxViewers : false });
});

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
};

const requireFullAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: 'Insufficient permissions' });
  next();
};

// Discord OAuth routes
app.get('/api/auth/discord', (req, res) => {
  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/discord/callback`;
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=identify`;
  res.redirect(discordAuthUrl);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${req.protocol}://${req.get('host')}/api/auth/discord/callback`,
      }),
    });

    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      return res.redirect('/?error=token_failed');
    }

    // Get user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const userData = await userResponse.json();
    if (!userData.id) {
      return res.redirect('/?error=user_failed');
    }

    // Store or update user in database
    const { rows } = await pool.query(
      `INSERT INTO users (discord_id, discord_username) 
       VALUES ($1, $2) 
       ON CONFLICT (discord_id) 
       DO UPDATE SET discord_username = $2 
       RETURNING id`,
      [userData.id, `${userData.username}#${userData.discriminator}`]
    );

    // Create JWT token
    const token = jwt.sign({ 
      userId: rows[0].id, 
      discordId: userData.id,
      username: userData.username 
    }, JWT_SECRET, { expiresIn: '30d' });

    // Redirect to settings page with token
    res.redirect(`/?discord_login=success&token=${token}`);
  } catch (error) {
    console.error('Discord OAuth error:', error);
    res.redirect('/?error=auth_failed');
  }
});

// User settings endpoints
app.get('/api/user/settings', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT discord_username, auto_code_enabled FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (rows[0]) {
      res.json({ ok: true, settings: rows[0] });
    } else {
      res.json({ ok: false, error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/user/settings/auto-code', authMiddleware, async (req, res) => {
  const { enabled } = req.body;
  try {
    await pool.query(
      'UPDATE users SET auto_code_enabled = $1 WHERE id = $2',
      [enabled, req.user.userId]
    );
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Auto-code request endpoint
app.post('/api/auto-code/request', authMiddleware, async (req, res) => {
  const { movieTitle, movieId } = req.body;
  
  try {
    // Get user info
    const { rows: userRows } = await pool.query(
      'SELECT discord_username FROM users WHERE id = $1',
      [req.user.userId]
    );
    
    if (!userRows[0]) {
      return res.json({ ok: false, error: 'User not found' });
    }

    // Check if codes are enabled
    const codesEnabled = await getCodesEnabled();
    if (!codesEnabled) {
      return res.json({ ok: false, error: 'Code generation is currently disabled by admin' });
    }

    // Send request to Discord channel
    if (autoCodeChannel) {
      await autoCodeChannel.send(
        `${userRows[0].discord_username} - requested a one-time code for: **${movieTitle}** (ID: ${movieId})`
      );
      res.json({ ok: true, message: 'Code request sent! Check your DMs for the code.' });
    } else {
      res.json({ ok: false, error: 'Auto-code channel not configured' });
    }
  } catch (error) {
    console.error('Auto-code request error:', error);
    res.json({ ok: false, error: 'Failed to request code' });
  }
});

app.get('/api/movies', async (req, res) => {
  try {
    console.log('Fetching movies from database...');
    const { rows } = await pool.query(
      'SELECT id, title, type, year, image, imdb_id, duration, overlay_enabled FROM movies ORDER BY created_at DESC'
    );
    console.log(`Found ${rows.length} movies`);
    res.json({ ok: true, movies: rows });
  } catch (error) {
    console.error('Error fetching movies:', error);
    res.status(500).json({ ok: false, error: 'Failed to load movies' });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ ok: true, token, role: 'admin' });
  } else {
    res.json({ ok: false, error: 'Wrong password' });
  }
});

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
    res.json({ ok: false, error: 'Invalid or used code' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/movies', authMiddleware, async (req, res) => {
  const { role, code_id } = req.user;
  if (role === 'limited_admin') {
    const { rows } = await pool.query('SELECT used FROM one_time_admin_codes WHERE id = $1', [code_id]);
    if (!rows[0] || rows[0].used) return res.status(403).json({ ok: false, error: 'Code already used' });
  }

  let { imdbId, contentPasswords = [], oneTimePasswords = [], type = 'movie', overlayEnabled = false } = req.body;
  if (!imdbId) return res.status(400).json({ ok: false, error: 'IMDb ID required' });

  if (!imdbId.startsWith('tt')) imdbId = 'tt' + imdbId;

  const hashes = await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)));
  const otHashes = await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)));

  let year = null;
  let finalTitle = imdbId;
  let duration = null;

  const { rows } = await pool.query(
    `INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes, overlay_enabled)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [finalTitle, imdbId, type, JSON.stringify(hashes), JSON.stringify(otHashes), overlayEnabled]
  );

  // Fetch poster, title, year, duration from OMDb
  let posterUrl = null;
  try {
    const omdbRes = await fetch(`https://www.omdbapi.com/?i=${imdbId}&apikey=${OMDb_KEY}`);
    const omdbData = await omdbRes.json();
    if (omdbData.Poster && omdbData.Poster !== 'N/A') posterUrl = omdbData.Poster;
    if (omdbData.Title) finalTitle = omdbData.Title;
    if (omdbData.Year) year = omdbData.Year;
    if (omdbData.Runtime && omdbData.Runtime !== 'N/A') duration = omdbData.Runtime;
  } catch (err) {
    console.error('OMDb fetch failed:', err);
  }

  await pool.query(
    'UPDATE movies SET image = $1, title = $2, year = $3, duration = $4 WHERE id = $5',
    [posterUrl, finalTitle, year, duration, rows[0].id]
  );

  if (role === 'limited_admin') {
    await pool.query('UPDATE one_time_admin_codes SET used = TRUE WHERE id = $1', [code_id]);
  }

  res.json({ ok: true, movieId: rows[0].id });
});

app.delete('/api/movies/:id', authMiddleware, requireFullAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM movies WHERE id = $1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

app.post('/api/admin/global-passwords', authMiddleware, requireFullAdmin, async (req, res) => {
  const { password, isOneTime } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    'INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, $2) RETURNING id',
    [hash, !!isOneTime]
  );
  res.json({ ok: true, id: rows[0].id });
});

app.get('/api/admin/global-passwords', authMiddleware, requireFullAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, is_one_time, created_at FROM global_passwords');
  res.json({ ok: true, passwords: rows });
});

app.delete('/api/admin/global-passwords/:id', authMiddleware, requireFullAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM global_passwords WHERE id = $1', [req.params.id]);
  res.json({ ok: rowCount > 0 });
});

app.get('/api/movies/:id/episodes', async (req, res) => {
  const id = req.params.id;
  const { rows } = await pool.query('SELECT imdb_id, type FROM movies WHERE id = $1', [id]);
  if (!rows[0] || rows[0].type !== 'tv_show') {
    return res.json({ ok: false, error: 'Not a TV show' });
  }

  const imdbId = rows[0].imdb_id;
  try {
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
    console.error('Episodes API error:', err);
    res.json({ ok: false, error: 'Failed to load episodes' });
  }
});

// Function to check if a movie has specific passwords
async function movieHasSpecificPasswords(movieId) {
  try {
    const { rows } = await pool.query(
      'SELECT password_hashes, one_time_password_hashes FROM movies WHERE id = $1',
      [movieId]
    );
    
    if (rows.length === 0) return false;
    
    const movie = rows[0];
    let regularPasswords = [];
    let oneTimePasswords = [];
    
    try {
      regularPasswords = JSON.parse(movie.password_hashes || '[]');
      oneTimePasswords = JSON.parse(movie.one_time_password_hashes || '[]');
    } catch (e) {
      console.error('Error parsing passwords for movie:', movieId, e);
    }
    
    // Return true if the movie has any specific passwords set (regular or one-time)
    return regularPasswords.length > 0 || oneTimePasswords.length > 0;
  } catch (error) {
    console.error('Error checking movie passwords:', error);
    return false;
  }
}

app.post('/api/movies/:id/authorize', async (req, res) => {
  // Check if redirect is enabled
  if (redirectEnabled) {
    return res.json({ ok: false, error: 'Website is currently redirecting' });
  }

  const { password } = req.body;
  if (!password) return res.json({ ok: false, error: 'Password required' });

  const { rows } = await pool.query(
    'SELECT password_hashes, one_time_password_hashes FROM movies WHERE id = $1',
    [req.params.id]
  );
  if (!rows[0]) return res.json({ ok: false, error: 'Movie not found' });

  let regular = [], ot = [];
  try { regular = JSON.parse(rows[0].password_hashes || '[]'); } catch (_) { regular = []; }
  try { ot = JSON.parse(rows[0].one_time_password_hashes || '[]'); } catch (_) { ot = []; }

  // Check if movie has specific passwords set
  const hasSpecificPasswords = regular.length > 0 || ot.length > 0;

  // First check movie-specific one-time passwords
  for (let i = 0; i < ot.length; i++) {
    if (await bcrypt.compare(password, ot[i])) {
      ot.splice(i, 1);
      await pool.query('UPDATE movies SET one_time_password_hashes = $1 WHERE id = $2',
        [JSON.stringify(ot), req.params.id]);
      return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
    }
  }

  // Then check movie-specific regular passwords
  for (const h of regular) {
    if (await bcrypt.compare(password, h)) {
      return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
    }
  }

  // If movie has specific passwords set (either regular or one-time), 
  // DO NOT accept global passwords from /gencode
  if (hasSpecificPasswords) {
    return res.json({ ok: false, error: 'Wrong password' });
  }

  // Only check global passwords if movie doesn't have any specific passwords set
  const { rows: globals } = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');
  
  // Check global one-time passwords first
  for (const g of globals) {
    if (g.is_one_time && await bcrypt.compare(password, g.password_hash)) {
      await pool.query('DELETE FROM global_passwords WHERE id = $1', [g.id]);
      return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
    }
  }
  
  // Then check global regular passwords
  for (const g of globals) {
    if (!g.is_one_time && await bcrypt.compare(password, g.password_hash)) {
      return res.json({ ok: true, token: jwt.sign({ movieId: req.params.id }, JWT_SECRET, { expiresIn: '6h' }) });
    }
  }

  res.json({ ok: false, error: 'Wrong password' });
});

app.get('/api/movies/:id/embed', authMiddleware, async (req, res) => {
  // Check if redirect is enabled
  if (redirectEnabled) {
    return res.json({ ok: false, error: 'Website is currently redirecting' });
  }

  const { movieId } = req.user;
  const { rows } = await pool.query(
    'SELECT imdb_id, type, duration, overlay_enabled FROM movies WHERE id = $1',
    [movieId]
  );
  if (!rows[0]) return res.json({ ok: false, error: 'Not found' });

  const { imdb_id, type, duration, overlay_enabled } = rows[0];
  const base = type === 'movie' ? 'movie' : 'tv';
  const url = `https://vidsrc.me/embed/${base}/${imdb_id}`;

  res.json({ ok: true, url, duration, overlayEnabled: overlay_enabled });
});

app.get('/api/trailer', async (req, res) => {
  if (!YOUTUBE_API_KEY) {
    return res.json({ ok: false, error: 'YouTube API key not set' });
  }
  const { title } = req.query;
  if (!title) return res.status(400).json({ ok: false, error: 'Title required' });

  const query = encodeURIComponent(title);
  try {
    const ytRes = await fetch(
      `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${query}&type=video&key=${YOUTUBE_API_KEY}`
    );
    const data = await ytRes.json();

    if (!data.items?.length) {
      return res.json({ ok: false, error: 'No trailer found' });
    }

    const video = data.items.find(v =>
      v.snippet.title.toLowerCase().includes('official') ||
      v.snippet.title.toLowerCase().includes('trailer')
    ) || data.items[0];

    res.json({ ok: true, url: `https://www.youtube.com/embed/${video.id.videoId}` });
  } catch (err) {
    console.error('YouTube API error:', err);
    res.json({ ok: false, error: 'Failed to fetch trailer' });
  }
});

app.post('/api/wishlist', async (req, res) => {
  const { title, type, imdb_id } = req.body;
  if (!title || !type) return res.status(400).json({ ok: false, error: 'Title and type required' });

  try {
    const { rows } = await pool.query('SELECT 1 FROM movies WHERE LOWER(title) = LOWER($1)', [title]);
    if (rows.length > 0) return res.json({ ok: false, error: 'Already available' });

    if (!wishlistChannel) return res.json({ ok: false, error: 'Channel not configured' });

    const displayId = imdb_id ? imdb_id.replace(/^tt/, '') : 'N/A';

    const embed = new EmbedBuilder()
      .setColor('#e50914')
      .setTitle(`New ${type.charAt(0).toUpperCase() + type.slice(1)} Request`)
      .addFields(
        { name: 'Title', value: title, inline: true },
        { name: 'ID', value: displayId, inline: true }
      )
      .setFooter({ text: 'Pending Review' })
      .setTimestamp();

    await wishlistChannel.send({ embeds: [embed] });
    res.json({ ok: true });
  } catch (err) {
    console.error('Wishlist error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ONE-TIME POSTER FIX
app.get('/api/fix-posters', async (req, res) => {
  const pass = req.query.pass;
  if (pass !== ADMIN_PASSWORD) {
    return res.status(403).json({ ok: false, error: 'Invalid password' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, imdb_id FROM movies WHERE imdb_id IS NOT NULL AND (image IS NULL OR image = \'\' OR image = \'N/A\')'
    );

    let fixed = 0;
    for (const movie of rows) {
      try {
        const omdbRes = await fetch(`https://www.omdbapi.com/?i=${movie.imdb_id}&apikey=${OMDb_KEY}`);
        const data = await omdbRes.json();
        if (data.Poster && data.Poster !== 'N/A') {
          await pool.query('UPDATE movies SET image = $1 WHERE id = $2', [data.Poster, movie.id]);
          fixed++;
        }
      } catch (err) {
        console.error(`Failed for ${movie.id}:`, err.message);
      }
    }

    res.json({ ok: true, fixed, message: `Fixed ${fixed} posters. Refresh site.` });
  } catch (err) {
    console.error('Fix posters error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Fix posters: /api/fix-posters?pass=${ADMIN_PASSWORD}`);
});
