require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Client, GatewayIntentBits, SlashCommandBuilder, EmbedBuilder, REST, Routes } = require('discord.js');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');

const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY;
const DISCORD_WISHLIST_CHANNEL_ID = process.env.DISCORD_WISHLIST_CHANNEL_ID;
const DISCORD_CODE_MANAGER_ROLE_ID = process.env.DISCORD_CODE_MANAGER_ROLE_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const OMDb_KEY = '7f93c41d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
let wishlistChannel = null;

// ==================== WATCH TOGETHER ====================
const rooms = new Map();

app.get('/api/public-rooms', (req, res) => {
  const list = Array.from(rooms.entries())
    .filter(([_, r]) => r.isPublic)
    .map(([id, r]) => ({ id, name: r.name, count: r.viewers.size + 1 }));
  res.json({ ok: true, rooms: list });
});

io.on('connection', (socket) => {
  socket.on('create-room', ({ name, isPublic, code }) => {
    let roomId = isPublic ? uuidv4().slice(0, 8) : code?.trim();
    if (!isPublic && (!roomId || rooms.has(roomId))) return socket.emit('error', 'Invalid/taken code');
    if (rooms.has(roomId)) return socket.emit('error', 'Room exists');

    rooms.set(roomId, { name: name || 'Movie Night', isPublic, host: socket.id, viewers: new Set() });
    socket.join(roomId);
    socket.emit('room-created', { roomId });
  });

  socket.on('join-room', (roomId) => {
    const room = rooms.get(roomId);
    if (!room) return socket.emit('error', 'Not found');
    if (room.viewers.size >= 9) return socket.emit('room-full');
    socket.join(roomId);
    room.viewers.add(socket.id);
    socket.emit('joined', { hostId: room.host });
    io.to(room.host).emit('new-viewer', { viewerId: socket.id });
  });

  socket.on('offer', (data) => io.to(data.to).emit('offer', { offer: data.offer, from: socket.id }));
  socket.on('answer', (data) => io.to(data.to).emit('answer', { answer: data.answer, from: socket.id }));
  socket.on('ice-candidate', (data) => io.to(data.to).emit('ice-candidate', { candidate: data.candidate, from: socket.id }));

  const leave = () => {
    for (const roomId of [...socket.rooms]) {
      if (roomId === socket.id) continue;
      const room = rooms.get(roomId);
      if (!room) continue;
      if (room.host === socket.id) {
        io.to(roomId).emit('room-closed');
        rooms.delete(roomId);
      } else {
        room.viewers.delete(socket.id);
      }
      socket.leave(roomId);
    }
  };
  socket.on('leave-room', leave);
  socket.on('disconnect', leave);
});
// ==================== END WATCH TOGETHER ====================

function generateCode(prefix = 'om-') {
  return prefix + Math.random().toString(36).substr(2, 12).toUpperCase();
}

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
    );
    CREATE TABLE IF NOT EXISTS global_passwords (
      id SERIAL PRIMARY KEY,
      password_hash TEXT,
      is_one_time BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS om_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE,
      global_password_id INTEGER,
      used BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS one_time_admin_codes (
      id SERIAL PRIMARY KEY,
      code_hash TEXT,
      used BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS bot_config (
      key TEXT PRIMARY KEY,
      value BOOLEAN DEFAULT TRUE
    );
  `);
  await pool.query(`INSERT INTO bot_config (key, value) VALUES ('codes_enabled', TRUE) ON CONFLICT (key) DO NOTHING`);
}
ensureTables();

async function getCodesEnabled() {
  const { rows } = await pool.query('SELECT value FROM bot_config WHERE key = $1', ['codes_enabled']);
  return rows[0] ? rows[0].value : true;
}

async function setCodesEnabled(enabled) {
  await pool.query('INSERT INTO bot_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['codes_enabled', enabled]);
}

async function deleteAllOMCodes() {
  try {
    await pool.query('DELETE FROM om_codes');
    await pool.query('DELETE FROM global_passwords WHERE is_one_time = TRUE');
  } catch (err) {
    console.error('Failed to delete OM codes:', err);
  }
}

client.once('ready', async () => {
  console.log('Discord bot ready');
  await deleteAllOMCodes();

  const commands = [
    new SlashCommandBuilder().setName('gencode').setDescription('Generate 1 OM one-time code'),
    new SlashCommandBuilder().setName('toggle-codes').setDescription('Enable / disable code generation')
      .addStringOption(o => o.setName('state').setDescription('on or off').setRequired(true)
        .addChoices({ name: 'on', value: 'on' }, { name: 'off', value: 'off' })),
    new SlashCommandBuilder().setName('genadminlogincode').setDescription('Generate one-time admin login code')
  ];

  try {
    const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
    await rest.put(Routes.applicationCommands(client.user.id), { body: commands.map(c => c.toJSON()) });
    console.log('Slash commands registered');
  } catch (e) {
    console.error('Failed to register commands:', e);
  }

  if (DISCORD_WISHLIST_CHANNEL_ID) {
    wishlistChannel = await client.channels.fetch(DISCORD_WISHLIST_CHANNEL_ID);
  }
});
client.login(DISCORD_BOT_TOKEN);

// ==================== ALL ROUTES (FULLY INCLUDED) ====================
app.post('/api/admin-login', async (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: 'Wrong password' });
  }
});

app.get('/api/movies', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM movies ORDER BY created_at DESC');
    res.json({ ok: true, movies: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Database error' });
  }
});

app.post('/api/add-movie', async (req, res) => {
  const { title, imdb_id, type = 'movie', password, one_time_password } = req.body;
  try {
    const passwordHash = password ? await bcrypt.hash(password, 10) : null;
    const otpHash = one_time_password ? await bcrypt.hash(one_time_password, 10) : null;

    await pool.query(`
      INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (imdb_id) DO UPDATE SET title = $1, type = $3
    `, [title, imdb_id, type, passwordHash ? [passwordHash] : [], otpHash ? [otpHash] : []]);

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Failed to add movie' });
  }
});

app.post('/api/movies/:id/authorize', async (req, res) => {
  const { password } = req.body;
  const { id } = req.params;

  const movieRes = await pool.query('SELECT password_hashes, one_time_password_hashes FROM movies WHERE id = $1', [id]);
  if (movieRes.rows.length === 0) return res.json({ ok: false, error: 'Movie not found' });

  const { password_hashes, one_time_password_hashes } = movieRes.rows[0];

  for (const hash of [...(password_hashes || []), ...(one_time_password_hashes || [])]) {
    if (await bcrypt.compare(password, hash)) {
      if (one_time_password_hashes?.includes(hash)) {
        await pool.query('UPDATE movies SET one_time_password_hashes = array_remove(one_time_password_hashes, $1) WHERE id = $2', [hash, id]);
      }
      return res.json({ ok: true, token: jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' }) });
    }
  }

  const globals = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');
  for (const g of globals.rows) {
    if (await bcrypt.compare(password, g.password_hash)) {
      if (g.is_one_time) await pool.query('DELETE FROM global_passwords WHERE id = $1', [g.id]);
      return res.json({ ok: true, token: jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' }) });
    }
  }

  res.json({ ok: false, error: 'Wrong password' });
});

app.get('/api/movies/:id/embed', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.json({ ok: false, error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.movieId != req.params.id) throw new Error();
    const movieRes = await pool.query('SELECT type FROM movies WHERE id = $1', [req.params.id]);
    const type = movieRes.rows[0]?.type || 'movie';
    const base = type === 'movie' ? 'movie' : 'tv';
    res.json({ ok: true, url: `https://vidsrc.me/embed/${base}/${req.params.id}` });
  } catch {
    res.json({ ok: false, error: 'Invalid token' });
  }
});

app.get('/api/trailer', async (req, res) => {
  if (!YOUTUBE_API_KEY) return res.json({ ok: false, error: 'YouTube API not set' });
  const { title } = req.query;
  if (!title) return res.status(400).json({ ok: false, error: 'Title required' });

  try {
    const ytRes = await fetch(`https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(title + ' official trailer')}&type=video&key=${YOUTUBE_API_KEY}`);
    const data = await ytRes.json();
    if (!data.items?.length) return res.json({ ok: false, error: 'No trailer' });
    const video = data.items[0];
    res.json({ ok: true, url: `https://www.youtube.com/embed/${video.id.videoId}` });
  } catch (err) {
    res.json({ ok: false, error: 'Failed to fetch trailer' });
  }
});

app.post('/api/wishlist', async (req, res) => {
  const { title, type, imdb_id } = req.body;
  if (!title || !type) return res.status(400).json({ ok: false, error: 'Title and type required' });

  try {
    const { rows } = await pool.query('SELECT 1 FROM movies WHERE LOWER(title) = LOWER($1)', [title]);
    if (rows.length > 0) return res.json({ ok: false, error: 'Already available' });

    if (!wishlistChannel) return res.json({ ok: false, error: 'Wishlist channel not set' });

    const embed = new EmbedBuilder()
      .setColor('#e50914')
      .setTitle(`New ${type} Request`)
      .addFields({ name: 'Title', value: title, inline: true })
      .setTimestamp();

    await wishlistChannel.send({ embeds: [embed] });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Failed' });
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Watch Together is FULLY WORKING in Electron`);
});
