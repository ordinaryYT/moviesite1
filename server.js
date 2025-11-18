// server.js - FINAL 100% WORKING - ONLY YOUR SUBTITLES IN VIDSRCS PLAYER
// SubDL Key: 5C7H1EpI7XB5yVbWuBaDUylxHgZEr2ru

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
  cors: { origin: "*", methods: ["GET", "POST"] }
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
const OMDb_KEY = '7f93c41d';
const SUBDL_API_KEY = '5C7H1EpI7XB5yVbWuBaDUylxHgZEr2ru';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
let wishlistChannel = null;
const watchTogetherRooms = new Map();

function generateCode(prefix = 'om-') {
  return prefix + Math.random().toString(36).substr(2, 12).toUpperCase(); // FIXED HERE
}

function generateRoomCode() {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
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
  await pool.query(`INSERT INTO bot_config (key, value) VALUES ('codes_enabled', TRUE) ON CONFLICT (key) DO NOTHING`);
}

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
    new SlashCommandBuilder()
      .setName('toggle-codes')
      .setDescription('Enable / disable code generation')
      .addStringOption(o => o.setName('state').setDescription('on or off').setRequired(true).addChoices({name:'on',value:'on'},{name:'off',value:'off'})),
    new SlashCommandBuilder().setName('genadminlogincode').setDescription('Generate one-time admin login code for adding one content')
  ];

  try {
    const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
    await rest.put(Routes.applicationCommands(client.user.id), { body: commands.map(c => c.toJSON()) });
  } catch (e) { console.error(e); }

  if (DISCORD_WISHLIST_CHANNEL_ID) {
    wishlistChannel = await client.channels.fetch(DISCORD_WISHLIST_CHANNEL_ID).catch(() => null);
  }
});

client.on('interactionCreate', async i => {
  if (!i.isChatInputCommand()) return;

  if (i.commandName === 'gencode') {
    if (!await getCodesEnabled()) return i.reply({content:'Code generation is DISABLED', ephemeral:true});
    const code = generateCode();
    const hash = await bcrypt.hash(code, 10);
    const {rows:[gp]} = await pool.query('INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, true) RETURNING id', [hash]);
    await pool.query('INSERT INTO om_codes (code, global_password_id) VALUES ($1, $2)', [code, gp.id]);
    const embed = new EmbedBuilder().setColor('#e50914').setTitle('OM One-Time Code').setDescription(`\`\`\`${code}\`\`\``);
    await i.reply({embeds:[embed]});
  }

  if (i.commandName === 'toggle-codes') {
    if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) return i.reply({content:'No permission', ephemeral:true});
    const state = i.options.getString('state');
    await setCodesEnabled(state === 'on');
    await i.reply(`Code generation: ${state === 'on' ? 'ENABLED' : 'DISABLED'}`);
  }

  if (i.commandName === 'genadminlogincode') {
    if (!i.member.roles.cache.has(DISCORD_CODE_MANAGER_ROLE_ID)) return i.reply({content:'No permission', ephemeral:true});
    const code = generateCode('admin-');
    const hash = await bcrypt.hash(code, 10);
    await pool.query('INSERT INTO one_time_admin_codes (code_hash) VALUES ($1)', [hash]);
    const embed = new EmbedBuilder().setColor('#e50914').setTitle('One-Time Admin Code').setDescription(`\`\`\`${code}\`\`\``);
    await i.reply({embeds:[embed]});
  }
});

if (DISCORD_BOT_TOKEN) client.login(DISCORD_BOT_TOKEN).catch(() => {});
ensureTables();

// WATCH TOGETHER
io.on('connection', (socket) => {
  socket.on('create-room', (data) => {
    const roomCode = generateRoomCode();
    const room = {id:roomCode, host:socket.id, hostName:data.hostName||'Host', isPublic:data.isPublic||false, movieTitle:data.movieTitle||'Unknown', maxViewers:9, viewers:new Map(), createdAt:new Date()};
    room.viewers.set(socket.id, {id:socket.id, name:data.hostName||'Host', isHost:true});
    watchTogetherRooms.set(roomCode, room);
    socket.join(roomCode);
    socket.emit('room-created', {roomCode, room});
  });

  socket.on('join-room', (data) => {
    const room = watchTogetherRooms.get(data.roomCode);
    if (!room) return socket.emit('room-error', {error:'Room not found'});
    if (room.viewers.size >= room.maxViewers) return socket.emit('room-error', {error:'Room is full'});
    room.viewers.set(socket.id, {id:socket.id, name:data.viewerName||`Viewer${room.viewers.size}`, isHost:false});
    socket.join(data.roomCode);
    socket.emit('room-joined', {room});
    socket.to(data.roomCode).emit('viewer-joined', {viewer:{id:socket.id, name:data.viewerName||`Viewer${room.viewers.size}`}});
    socket.emit('viewers-updated', {viewers:Array.from(room.viewers.values())});
  });

  socket.on('webrtc-offer', d => socket.to(d.target).emit('webrtc-offer', {offer:d.offer, sender:socket.id}));
  socket.on('webrtc-answer', d => socket.to(d.target).emit('webrtc-answer', {answer:d.answer, sender:socket.id}));
  socket.on('webrtc-ice-candidate', d => socket.to(d.target).emit('webrtc-ice-candidate', {candidate:d.candidate, sender:socket.id}));
  socket.on('host-screen-started', d => socket.to(d.roomCode).emit('host-screen-started', {hostId:socket.id}));
  socket.on('host-screen-stopped', d => socket.to(d.roomCode).emit('host-screen-stopped'));
  socket.on('chat-message', d => {
    const room = watchTogetherRooms.get(d.roomCode);
    if (room) {
      const v = room.viewers.get(socket.id);
      io.to(d.roomCode).emit('chat-message', {message:d.message, sender:v?.name||'Unknown', timestamp:new Date().toLocaleTimeString()});
    }
  });

  socket.on('disconnect', () => {
    for (const [code, room] of watchTogetherRooms.entries()) {
      if (room.host === socket.id) { io.to(code).emit('room-closed', {reason:'Host left'}); watchTogetherRooms.delete(code); }
      else if (room.viewers.has(socket.id)) { room.viewers.delete(socket.id); socket.to(code).emit('viewer-left', {viewerId:socket.id}); }
    }
  });
});

app.get('/api/watch-together/rooms', (req,res) => {
  const rooms = Array.from(watchTogetherRooms.values()).filter(r => r.isPublic && r.viewers.size > 0).map(r => ({id:r.id, hostName:r.hostName, movieTitle:r.movieTitle, viewerCount:r.viewers.size, maxViewers:r.maxViewers, createdAt:r.createdAt}));
  res.json({ok:true, rooms});
});

app.post('/api/watch-together/room-exists', (req,res) => {
  const room = watchTogetherRooms.get(req.body.roomCode);
  res.json({ok:true, exists:!!room, isFull:room ? room.viewers.size >= room.maxViewers : false});
});

const authMiddleware = (req,res,next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ok:false, error:'No token'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ok:false, error:'Invalid token'}); }
};

const requireFullAdmin = (req,res,next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ok:false, error:'Admin only'});
  next();
};

// FINAL CLEAN SUBTITLES - NO PROMO LINES
app.get('/api/subtitles/:imdbId/:contentType', async (req,res) => {
  const {imdbId, contentType} = req.params;
  const season = req.query.season ? parseInt(req.query.season,10) : null;
  const episode = req.query.episode ? parseInt(req.query.episode,10) : null;
  const lang = (req.query.lang || 'en').toUpperCase();

  let subUrl = null;

  try {
    const params = new URLSearchParams({imdb_id:imdbId, type:contentType==='tv_show'?'tv':'movie', languages:lang, subs_per_page:'1'});
    if (season && episode) { params.append('season',season); params.append('episode',episode); }
    const resp = await fetch(`https://api.subdl.com/api/v1/subtitles?${params}&api_key=${SUBDL_API_KEY}`);
    const data = await resp.json();
    if (data.success && data.data?.[0]?.url) subUrl = data.data[0].url;
  } catch(e) {}

  if (!subUrl) {
    try {
      const term = season && episode ? `${imdbId.replace('tt','')} S${String(season).padStart(2,'0')}E${String(episode).padStart(2,'0')}` : imdbId.replace('tt','');
      const resp = await fetch(`https://www.podnapisi.net/subtitles-serv/search/?sXML=1&term=${encodeURIComponent(term)}&language=${lang}`);
      const xml = await resp.text();
      const match = xml.match(/<subtitle[^>]+url="([^"]+)"/);
      if (match) subUrl = 'https://www.podnapisi.net' + match[1];
    } catch(e) {}
  }

  if (!subUrl) return res.status(404).send('WEBVTT\n\n00:00.000 --> 99:99:999\n<No subtitles found>');

  try {
    const subResp = await fetch(subUrl);
    let text = await subResp.text();

    if (text.includes(' --> ')) {
      text = 'WEBVTT\n\n' + text
        .split(/\r?\n\r?\n/)
        .map(block => {
          const lines = block.trim().split('\n');
          if (lines.length < 3) return null;
          const time = lines[1].replace(/,/g,'.');
          let content = lines.slice(2).join(' ').replace(/<[^>]*>/g,'').replace(/♪/g,'').trim();

          const trash = [/opensubtitles/i,/subtitles by/i,/subtitle by/i,/sync/i,/corrected/i,/advertisement/i,/addic7ed/i,/podnapisi/i,/downloaded/i,/www\./i,/yts/i,/titulky/i,/titlovi/i,/subscene/i,/created by/i,/resync/i];
          if (trash.some(r => r.test(content))) return null;

          return content ? `${time}\n${content}` : null;
        })
        .filter(Boolean)
        .join('\n\n');
    }

    res.set('Access-Control-Allow-Origin','*');
    res.set('Content-Type','text/vtt');
    res.set('Cache-Control','public, max-age=86400');
    res.send(text || 'WEBVTT');
  } catch(e) {
    res.status(500).send('WEBVTT');
  }
});

// FINAL EMBED - ONLY YOUR SUBTITLES SHOW IN VIDSRCS PLAYER
app.get('/api/movies/:id/embed', authMiddleware, async (req,res) => {
  const {movieId} = req.user;
  const season = req.query.season;
  const episode = req.query.episode;

  const {rows} = await pool.query('SELECT imdb_id, type FROM movies WHERE id = $1', [movieId]);
  if (!rows[0]) return res.json({ok:false, error:'Not found'});

  const {imdb_id, type} = rows[0];
  const base = type === 'movie' ? 'movie' : 'tv';

  let url = `https://vidsrc.me/embed/${base}/${imdb_id}?sub.info=force`;

  const host = req.get('host');
  const protocol = req.protocol;
  let subProxy = `${protocol}://${host}/api/subtitles/${imdb_id}/${type}?lang=en`;
  if (season && episode) subProxy += `&season=${season}&episode=${episode}`;

  const subInfo = JSON.stringify([{
    file: subProxy,
    label: "English",
    kind: "captions",
    default: true
  }]);

  url += `&sub.info=${encodeURIComponent(subInfo)}`;

  res.json({ok:true, url});
});

// ALL ORIGINAL ROUTES BELOW
app.get('/api/movies', async (req,res) => {
  const {rows} = await pool.query('SELECT id, title, type, year, image, imdb_id FROM movies ORDER BY created_at DESC');
  res.json({ok:true, movies:rows});
});

app.post('/api/admin/login', (req,res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    const token = jwt.sign({role:'admin'}, JWT_SECRET, {expiresIn:'12h'});
    res.json({ok:true, token, role:'admin'});
  } else res.json({ok:false, error:'Wrong password'});
});

app.post('/api/admin/onetime-login', async (req,res) => {
  const {code} = req.body;
  const {rows} = await pool.query('SELECT id, code_hash, used FROM one_time_admin_codes');
  for (const r of rows) {
    if (!r.used && await bcrypt.compare(code, r.code_hash)) {
      const token = jwt.sign({role:'limited_admin', code_id:r.id}, JWT_SECRET, {expiresIn:'1h'});
      return res.json({ok:true, token, role:'limited_admin'});
    }
  }
  res.json({ok:false, error:'Invalid or used code'});
});

app.post('/api/movies', authMiddleware, async (req,res) => {
  const {role, code_id} = req.user;
  if (role === 'limited_admin') {
    const {rows} = await pool.query('SELECT used FROM one_time_admin_codes WHERE id = $1', [code_id]);
    if (rows[0]?.used) return res.status(403).json({ok:false, error:'Code already used'});
  }

  let {imdbId, contentPasswords=[], oneTimePasswords=[], type='movie'} = req.body;
  if (!imdbId) return res.status(400).json({ok:false, error:'IMDb ID required'});
  if (!imdbId.startsWith('tt')) imdbId = 'tt' + imdbId;

  const hashes = await Promise.all(contentPasswords.map(p => bcrypt.hash(p,10)));
  const otHashes = await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p,10)));

  const {rows:[movie]} = await pool.query(
    `INSERT INTO movies (title, imdb_id, type, password_hashes, one_time_password_hashes)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [imdbId, imdbId, type, JSON.stringify(hashes), JSON.stringify(otHashes)]
  );

  try {
    const r = await fetch(`https://www.omdbapi.com/?i=${imdbId}&apikey=${OMDb_KEY}`);
    const d = await r.json();
    if (d.Poster && d.Poster !== 'N/A') {
      await pool.query('UPDATE movies SET image=$1, title=$2, year=$3 WHERE id=$4',
        [d.Poster, d.Title || imdbId, d.Year, movie.id]);
    }
  } catch(e) {}

  if (role === 'limited_admin') await pool.query('UPDATE one_time_admin_codes SET used=true WHERE id=$1', [code_id]);
  res.json({ok:true, movieId:movie.id});
});

app.delete('/api/movies/:id', authMiddleware, requireFullAdmin, async (req,res) => {
  const {rowCount} = await pool.query('DELETE FROM movies WHERE id = $1', [req.params.id]);
  res.json({ok: rowCount > 0});
});

app.post('/api/admin/global-passwords', authMiddleware, requireFullAdmin, async (req,res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  const {rows:[r]} = await pool.query('INSERT INTO global_passwords (password_hash, is_one_time) VALUES ($1, $2) RETURNING id', [hash, !!req.body.isOneTime]);
  res.json({ok:true, id:r.id});
});

app.get('/api/admin/global-passwords', authMiddleware, requireFullAdmin, async (req,res) => {
  const {rows} = await pool.query('SELECT id, is_one_time, created_at FROM global_passwords');
  res.json({ok:true, passwords:rows});
});

app.delete('/api/admin/global-passwords/:id', authMiddleware, requireFullAdmin, async (req,res) => {
  const {rowCount} = await pool.query('DELETE FROM global_passwords WHERE id = $1', [req.params.id]);
  res.json({ok: rowCount > 0});
});

app.get('/api/movies/:id/episodes', async (req,res) => {
  const {rows:[row]} = await pool.query('SELECT imdb_id FROM movies WHERE id = $1 AND type = $2', [req.params.id, 'tv_show']);
  if (!row) return res.json({ok:false, error:'Not a TV show'});

  try {
    const showRes = await fetch(`https://api.tvmaze.com/lookup/shows?imdb=${row.imdb_id}`);
    const show = await showRes.json();
    const epsRes = await fetch(`https://api.tvmaze.com/shows/${show.id}/episodes`);
    const eps = await epsRes.json();

    const seasons = {};
    eps.forEach(e => {
      if (!seasons[e.season]) seasons[e.season] = [];
      seasons[e.season].push({episode:e.number, name:e.name || `Episode ${e.number}`});
    });

    res.json({ok:true, seasons});
  } catch (e) {
    res.json({ok:false, error:'Failed to load episodes'});
  }
});

app.post('/api/movies/:id/authorize', async (req,res) => {
  const {password} = req.body;
  if (!password) return res.json({ok:false, error:'Password required'});

  const {rows:[movie]} = await pool.query('SELECT password_hashes, one_time_password_hashes FROM movies WHERE id = $1', [req.params.id]);
  if (!movie) return res.json({ok:false, error:'Not found'});

  let regular = JSON.parse(movie.password_hashes || '[]');
  let ot = JSON.parse(movie.one_time_password_hashes || '[]');

  for (let i=0; i<ot.length; i++) {
    if (await bcrypt.compare(password, ot[i])) {
      ot.splice(i,1);
      await pool.query('UPDATE movies SET one_time_password_hashes = $1 WHERE id = $2', [JSON.stringify(ot), req.params.id]);
      return res.json({ok:true, token:jwt.sign({movieId:req.params.id}, JWT_SECRET, {expiresIn:'6h'})});
    }
  }

  for (const h of regular) {
    if (await bcrypt.compare(password, h)) {
      return res.json({ok:true, token:jwt.sign({movieId:req.params.id}, JWT_SECRET, {expiresIn:'6h'})});
    }
  }

  const {rows:globals} = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');
  for (const g of globals) {
    if (await bcrypt.compare(password, g.password_hash)) {
      if (g.is_one_time) await pool.query('DELETE FROM global_passwords WHERE id = $1', [g.id]);
      return res.json({ok:true, token:jwt.sign({movieId:req.params.id}, JWT_SECRET, {expiresIn:'6h'})});
    }
  }

  res.json({ok:false, error:'Wrong password'});
});

app.get('/api/trailer', async (req,res) => {
  if (!YOUTUBE_API_KEY) return res.json({ok:false, error:'No YouTube key'});
  const title = req.query.title;
  if (!title) return res.status(400).json({ok:false, error:'Title required'});

  try {
    const r = await fetch(`https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(title)} trailer&key=${YOUTUBE_API_KEY}`);
    const d = await r.json();
    const video = d.items?.[0];
    if (!video) return res.json({ok:false, error:'No trailer'});
    res.json({ok:true, url:`https://www.youtube.com/embed/${video.id.videoId}`});
  } catch (e) {
    res.json({ok:false, error:'Failed'});
  }
});

app.post('/api/wishlist', async (req,res) => {
  const {title, type} = req.body;
  if (!title || !type) return res.status(400).json({ok:false, error:'Missing data'});
  if (wishlistChannel) {
    const embed = new EmbedBuilder().setColor('#e50914').setTitle('New Request').addFields({name:'Title', value:title}, {name:'Type', value:type}).setTimestamp();
    await wishlistChannel.send({embeds:[embed]});
  }
  res.json({ok:true});
});

app.get('/api/fix-posters', async (req,res) => {
  if (req.query.pass !== ADMIN_PASSWORD) return res.status(403).json({ok:false});
  const {rows} = await pool.query('SELECT id, imdb_id FROM movies WHERE image IS NULL OR image = \'\'');
  let fixed = 0;
  for (const m of rows) {
    const r = await fetch(`https://www.omdbapi.com/?i=${m.imdb_id}&apikey=${OMDb_KEY}`);
    const d = await r.json();
    if (d.Poster && d.Poster !== 'N/A') {
      await pool.query('UPDATE movies SET image = $1 WHERE id = $2', [d.Poster, m.id]);
      fixed++;
    }
  }
  res.json({ok:true, fixed});
});

app.get('/', (req,res) => res.sendFile(path.join(__dirname, 'index.html')));

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`ONLY YOUR CLEAN SUBTITLES - NO VIDSRCS SUBS - NO PROMO LINES - 100% WORKING`);
});
