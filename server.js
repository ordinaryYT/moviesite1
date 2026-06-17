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
  
  // First create all tables
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
      right_cover_enabled BOOLEAN DEFAULT FALSE,
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

  // Now safely add columns if they don't exist
  await pool.query(`
    ALTER TABLE movies ADD COLUMN IF NOT EXISTS overlay_enabled BOOLEAN DEFAULT FALSE;
  `).catch(err => console.log('Overlay column check:', err.message));

  await pool.query(`
    ALTER TABLE movies ADD COLUMN IF NOT EXISTS right_cover_enabled BOOLEAN DEFAULT FALSE;
  `).catch(err => console.log('Right cover column check:', err.message));

  await pool.query(`
    ALTER TABLE movies ADD COLUMN IF NOT EXISTS duration TEXT;
  `).catch(err => console.log('Duration column check:', err.message));

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
      .setDescription('Toggle redirect system')
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

  if (message.content.includes('requested a one-time code for')) {
    const enabled = await getCodesEnabled();
    if (!enabled) {
      return message.reply('Code generation is currently **DISABLED** by admin.');
    }

    const discordUser = message.content.split(' - ')[0];
    
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
    
    if (redirectEnabled) {
      await setCodesEnabled(false);
    }
    
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

// Socket.IO for Watch Together + Redirect
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.emit('electron-redirect', { 
    enabled: redirectEnabled,
    redirectUrl: 'https://sajdhgaehtoihgaohgjdh.onrender.com'
  });

  // ... (rest of your socket handlers remain unchanged)
  socket.on('create-room', (data) => { /* ... */ });
  socket.on('join-room', (data) => { /* ... */ });
  socket.on('webrtc-offer', (data) => { /* ... */ });
  socket.on('webrtc-answer', (data) => { /* ... */ });
  socket.on('webrtc-ice-candidate', (data) => { /* ... */ });
  socket.on('host-screen-started', (data) => { /* ... */ });
  socket.on('host-screen-stopped', (data) => { /* ... */ });
  socket.on('chat-message', (data) => { /* ... */ });

  socket.on('disconnect', () => { /* ... */ });
});

// All your API routes (unchanged)
app.get('/api/watch-together/rooms', (req, res) => { /* ... */ });
app.post('/api/watch-together/room-exists', (req, res) => { /* ... */ });

// ... (all other routes: auth, movies, admin, etc. remain the same)

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Fix posters: /api/fix-posters?pass=${ADMIN_PASSWORD}`);
});
