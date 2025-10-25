require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Client, GatewayIntentBits } = require('discord.js');

// Render Node 18 has fetch built in, fallback if not
const fetch = global.fetch || ((...args) => import('node-fetch').then(({ default: f }) => f(...args)));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'boughton5';
const EMBED_BASE = 'https://vidsrc.me/embed/movie/';
const ADMIN_ROLE = process.env.ADMIN_ROLE || 'Admin';
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

// --- PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- Discord Bot ---
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ]
});

client.on('ready', () => {
  console.log(`✅ Bot logged in as ${client.user.tag}`);
});

client.on('messageCreate', async (message) => {
  if (message.author.bot || !message.content.startsWith('!')) return;

  const args = message.content.slice(1).trim().split(/ +/);
  const command = args.shift().toLowerCase();

  // !temppassword <movie_id>
  if (command === 'temppassword') {
    if (args.length < 1) {
      return message.reply('Please provide a movie ID. Use !movies to see available movies.');
    }

    const movieId = parseInt(args[0]);
    const movies = await getMovies();
    const movie = movies.find(m => m.id === movieId);

    if (!movie) {
      return message.reply('Movie not found. Use !movies to see available movies.');
    }

    try {
      const res = await fetch(`http://localhost:${PORT}/api/movies/${movieId}/temp-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ discord_id: message.author.id })
      });
      const data = await res.json();

      if (data.ok) {
        await message.author.send(`Temporary password for "${movie.title}": **${data.tempPassword}** (one-time use)`);
        await message.reply('Check your DMs for the temporary password!');
      } else {
        await message.reply(`Error: ${data.error}`);
      }
    } catch (err) {
      console.error('Temp password command error:', err);
      await message.reply('Failed to generate temporary password.');
    }
  }

  // !movies
  if (command === 'movies') {
    const movies = await getMovies();
    if (movies.length === 0) {
      return message.reply('No movies available.');
    }

    const movieList = movies.map(m => `ID: ${m.id} | ${m.title} (${m.year || 'N/A'})`).join('\n');
    await message.reply(`Available movies:\n${movieList}`);
  }

  // !block <@user> [reason]
  if (command === 'block') {
    if (!message.member.roles.cache.some(role => role.name === ADMIN_ROLE)) {
      return message.reply('You need the Admin role to use this command.');
    }

    const user = message.mentions.users.first();
    const reason = args.slice(1).join(' ') || 'No reason provided';

    if (!user) {
      return message.reply('Please mention a user to block.');
    }

    try {
      const res = await fetch(`http://localhost:${PORT}/api/discord/block`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
        },
        body: JSON.stringify({ discord_id: user.id, reason })
      });
      const data = await res.json();

      if (data.ok) {
        await message.reply(`Blocked user <@${user.id}> from generating temp passwords. Reason: ${reason}`);
      } else {
        await message.reply(`Error: ${data.error}`);
      }
    } catch (err) {
      console.error('Block command error:', err);
      await message.reply('Failed to block user.');
    }
  }

  // !unblock <@user>
  if (command === 'unblock') {
    if (!message.member.roles.cache.some(role => role.name === ADMIN_ROLE)) {
      return message.reply('You need the Admin role to use this command.');
    }

    const user = message.mentions.users.first();
    if (!user) {
      return message.reply('Please mention a user to unblock.');
    }

    try {
      const res = await fetch(`http://localhost:${PORT}/api/discord/unblock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
        },
        body: JSON.stringify({ discord_id: user.id })
      });
      const data = await res.json();

      if (data.ok) {
        await message.reply(`Unblocked user <@${user.id}> from generating temp passwords.`);
      } else {
        await message.reply(`Error: ${data.error}`);
      }
    } catch (err) {
      console.error('Unblock command error:', err);
      await message.reply('Failed to unblock user.');
    }
  }

  // !toggle_temp <on/off>
  if (command === 'toggle_temp') {
    if (!message.member.roles.cache.some(role => role.name === ADMIN_ROLE)) {
      return message.reply('You need the Admin role to use this command.');
    }

    const state = args[0]?.toLowerCase();
    if (state !== 'on' && state !== 'off') {
      return message.reply('Please specify "on" or "off".');
    }

    try {
      const res = await fetch(`http://localhost:${PORT}/api/settings/temp-passwords`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.ADMIN_TOKEN}`
        },
        body: JSON.stringify({ enabled: state === 'on' })
      });
      const data = await res.json();

      if (data.ok) {
        await message.reply(`Temporary password generation turned ${state}.`);
      } else {
        await message.reply(`Error: ${data.error}`);
      }
    } catch (err) {
      console.error('Toggle temp passwords error:', err);
      await message.reply('Failed to toggle temporary passwords.');
    }
  }
});

// Start Discord bot
client.login(BOT_TOKEN).catch(err => console.error('Bot login failed:', err));

// --- Auto-create tables ---
async function ensureTables() {
  try {
    // Movies table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS movies (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        imdb_id TEXT,
        password_hash TEXT,
        one_time_password_hash TEXT,
        year TEXT,
        image TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    
    // Discord blocked users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS discord_blocks (
        id SERIAL PRIMARY KEY,
        discord_id TEXT UNIQUE NOT NULL,
        blocked_by TEXT NOT NULL,
        blocked_at TIMESTAMP DEFAULT NOW(),
        reason TEXT
      )
    `);
    
    // Temp passwords table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS temp_passwords (
        id SERIAL PRIMARY KEY,
        movie_id INTEGER REFERENCES movies(id) ON DELETE CASCADE,
        password_hash TEXT NOT NULL,
        discord_user TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        used BOOLEAN DEFAULT FALSE
      )
    `);
    
    // Global temp password toggle
    await pool.query(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `);
    
    // Ensure temp_passwords_enabled setting
    await pool.query(`
      INSERT INTO settings (key, value) 
      VALUES ('temp_passwords_enabled', 'true') 
      ON CONFLICT (key) DO NOTHING
    `);

    console.log('✅ All tables ready');
  } catch (err) {
    console.error('Error ensuring tables:', err);
    throw err;
  }
}
ensureTables().catch(console.error);

// --- Utility Functions ---
async function isTempPasswordsEnabled() {
  const result = await pool.query('SELECT value FROM settings WHERE key = $1', ['temp_passwords_enabled']);
  return result.rows[0]?.value === 'true';
}

async function isUserBlocked(discordId) {
  const result = await pool.query('SELECT id FROM discord_blocks WHERE discord_id = $1', [discordId]);
  return result.rowCount > 0;
}

function generateTempPassword(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

async function getMovies() {
  try {
    const res = await pool.query('SELECT id, title, year, image FROM movies ORDER BY created_at DESC');
    return res.rows;
  } catch (err) {
    console.error('Error fetching movies:', err);
    return [];
  }
}

// --- IMDb Search Helper ---
async function searchImdb(title) {
  const q = encodeURIComponent(title);
  const url = `https://search.imdbot.workers.dev/?q=${q}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('IMDb search failed');
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
}

// --- Public: list movies ---
app.get('/api/movies', async (_, res) => {
  try {
    const result = await pool.query('SELECT id, title, year, image FROM movies ORDER BY created_at DESC');
    res.json({ ok: true, movies: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Admin login ---
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ ok: false, error: 'Invalid admin password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ ok: true, token });
});

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ ok: false, error: 'Missing auth' });
  const [type, token] = auth.split(' ');
  if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Bad header' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

// --- Add Movie ---
app.post('/api/movies', requireAdmin, async (req, res) => {
  try {
    const { name, imdbId, moviePassword, oneTimePassword } = req.body;
    if ((!name && !imdbId) || !moviePassword)
      return res.status(400).json({ ok: false, error: 'Provide movie name or IMDb ID and password' });

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

    const passwordHash = await bcrypt.hash(moviePassword, 10);
    const oneTimePasswordHash = oneTimePassword ? await bcrypt.hash(oneTimePassword, 10) : null;

    const result = await pool.query(
      'INSERT INTO movies (title, imdb_id, password_hash, one_time_password_hash, year, image) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [movieData.title, movieData.imdb_id, passwordHash, oneTimePasswordHash, movieData.year, movieData.image]
    );

    res.json({ ok: true, movieId: result.rows[0].id });
  } catch (err) {
    console.error('Add movie error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Delete movie ---
app.delete('/api/movies/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await pool.query('DELETE FROM movies WHERE id=$1 RETURNING id', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'DB error' });
  }
});

// --- Authorize viewer ---
app.post('/api/movies/:id/authorize', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    const r = await pool.query('SELECT password_hash, one_time_password_hash FROM movies WHERE id=$1', [id]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });

    const { password_hash, one_time_password_hash } = r.rows[0];

    // Check one-time password first
    if (one_time_password_hash && await bcrypt.compare(password, one_time_password_hash)) {
      await pool.query('UPDATE movies SET one_time_password_hash = NULL WHERE id = $1', [id]);
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      return res.json({ ok: true, token });
    }

    // Check temp password
    const tempResult = await pool.query(
      'SELECT id, password_hash FROM temp_passwords WHERE movie_id = $1 AND used = FALSE',
      [id]
    );
    for (const temp of tempResult.rows) {
      if (await bcrypt.compare(password, temp.password_hash)) {
        await pool.query('UPDATE temp_passwords SET used = TRUE WHERE id = $1', [temp.id]);
        const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
        return res.json({ ok: true, token });
      }
    }

    // Check regular password
    if (password_hash && await bcrypt.compare(password, password_hash)) {
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      return res.json({ ok: true, token });
    }

    return res.status(401).json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error('Authorization error:', err);
    res.status(500).json({ ok: false, error: 'Authorization failed' });
  }
});

// --- Get embed ---
app.get('/api/movies/:id/embed', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Missing token' });
    const data = jwt.verify(token, JWT_SECRET);
    const movieId = data.movieId;
    const r = await pool.query('SELECT imdb_id FROM movies WHERE id=$1', [movieId]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'Movie not found' });
    res.json({ ok: true, url: EMBED_BASE + r.rows[0].imdb_id });
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// --- Generate temp password ---
app.post('/api/movies/:id/temp-password', async (req, res) => {
  try {
    const { discord_id } = req.body;
    const movieId = req.params.id;

    if (!await isTempPasswordsEnabled()) {
      return res.status(403).json({ ok: false, error: 'Temp password generation disabled' });
    }

    if (await isUserBlocked(discord_id)) {
      return res.status(403).json({ ok: false, error: 'User is blocked' });
    }

    const movieCheck = await pool.query('SELECT id FROM movies WHERE id = $1', [movieId]);
    if (!movieCheck.rowCount) {
      return res.status(404).json({ ok: false, error: 'Movie not found' });
    }

    const tempPassword = generateTempPassword();
    const passwordHash = await bcrypt.hash(tempPassword, 10);

    await pool.query(
      'INSERT INTO temp_passwords (movie_id, password_hash, discord_user) VALUES ($1, $2, $3)',
      [movieId, passwordHash, discord_id]
    );

    res.json({ ok: true, tempPassword });
  } catch (err) {
    console.error('Temp password error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Block user ---
app.post('/api/discord/block', requireAdmin, async (req, res) => {
  try {
    const { discord_id, reason } = req.body;
    if (!discord_id) return res.status(400).json({ ok: false, error: 'Missing Discord ID' });

    await pool.query(
      'INSERT INTO discord_blocks (discord_id, blocked_by, reason) VALUES ($1, $2, $3) ON CONFLICT (discord_id) DO NOTHING',
      [discord_id, 'admin', reason || 'No reason provided']
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Block error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Unblock user ---
app.post('/api/discord/unblock', requireAdmin, async (req, res) => {
  try {
    const { discord_id } = req.body;
    if (!discord_id) return res.status(400).json({ ok: false, error: 'Missing Discord ID' });

    const result = await pool.query('DELETE FROM discord_blocks WHERE discord_id = $1', [discord_id]);
    if (!result.rowCount) {
      return res.status(404).json({ ok: false, error: 'User not blocked' });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Unblock error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Toggle temp passwords ---
app.post('/api/settings/temp-passwords', requireAdmin, async (req, res) => {
  try {
    const { enabled } = req.body;
    await pool.query(
      'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2',
      ['temp_passwords_enabled', enabled.toString()]
    );
    res.json({ ok: true, enabled });
  } catch (err) {
    console.error('Toggle temp passwords error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// --- Obfuscated client-side code ---
app.get('/script.js', (req, res) => {
  const jsCode = `
    // Obfuscated client-side code
    (function(){
      const _0x=document;const _1_=window.location.origin+'/api';let _2_=null;let _3_=[];let _4_=null;
      const _5_=_0x.getElementById('movieGrid');const _6_=_0x.getElementById('playerIframe');
      const _7_=_0x.getElementById('playerContainer');const _8_=_0x.getElementById('adminBtn');
      const _9_=_0x.getElementById('adminPanel');const _10_=_0x.getElementById('loginModal');
      const _11_=_0x.getElementById('addMovieModal');const _12_=_0x.getElementById('passwordModal');
      const _13_=_0x.getElementById('searchInput');
      function _14_(_a_){const _b_=_a_.toLowerCase();const _c_=_3_.filter(_d_=>_d_.title.toLowerCase().includes(_b_));_15_(_c_)}
      async function _15_(_e_){_5_.innerHTML='';if(_e_.length===0){_5_.innerHTML='<p style="text-align:center;color:#aaa;grid-column:1/-1;">No movies found</p>';return}_e_.forEach(_f_=>_16_(_f_))}
      async function _16_(_g_){try{let _h_=_g_.image;let _i_=_g_.year||'N/A';const _j_=await _17_(_g_.title,_i_);
      if(!_j_.includes('placeholder.com')){_h_=_j_}else if(!_h_||_h_.includes('placeholder.com')){_h_=_j_}
      const _k_=_0x.createElement('div');_k_.className='movie-card';
      _k_.innerHTML=\`<img src="\${_h_}" onerror="this.src='https://via.placeholder.com/300x450/333/fff?text=No+Poster'"><div class="movie-info"><h3>\${_g_.title}</h3><p>\${_i_}</p></div>\`;
      _k_.onclick=() => _18_(_g_.id,_g_.title);_5_.appendChild(_k_)}catch(_l_){console.error('Movie card render failed for',_g_.title,_l_);const _m_=_0x.createElement('div');
      _m_.className='movie-card';_m_.innerHTML=\`<img src="https://via.placeholder.com/300x450/333/fff?text=No+Poster"><div class="movie-info"><h3>\${_g_.title}</h3><p>\${_g_.year||'N/A'}</p></div>\`;
      _m_.onclick=() => _18_(_g_.id,_g_.title);_5_.appendChild(_m_)}}
      async function _17_(_n_,_o_=''){try{const _p_=await fetch(\`https://api.tvmaze.com/search/shows?q=\${encodeURIComponent(_n_)}\`);
      const _q_=await _p_.json();if(_q_.length>0&&_q_[0].show.image&&_q_[0].show.image.medium){return _q_[0].show.image.medium}}catch(_r_){console.log('TVMaze search failed')}
      try{const _s_=await fetch(\`https://en.wikipedia.org/api/rest_v1/page/summary/\${encodeURIComponent(_n_.replace(/ /g,'_'))}\`);
      const _t_=await _s_.json();if(_t_.thumbnail&&_t_.thumbnail.source){return _t_.thumbnail.source}}catch(_u_){console.log('Wikipedia search failed')}
      return \`https://via.placeholder.com/300x450/333/fff?text=\${encodeURIComponent(_n_.substring(0,20))}\`;}
      function _18_(_v_,_w_){_4_=_v_;_0x.getElementById('passwordMovieTitle').textContent=_w_;_12_.classList.add('active')}
      function _19_(){_10_.classList.add('active')}function _20_(){_10_.classList.remove('active')}
      function _21_(){_11_.classList.remove('active')}function _22_(){_12_.classList.remove('active');_4_=null}
      async function _23_(){const _x_=_0x.getElementById('adminPassword').value;
      if(!_x_)return alert('Please enter password');try{const _y_=await fetch(_1_+'/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:_x_})});
      const _z_=await _y_.json();if(_z_.ok){_2_=_z_.token;_20_();_24_();_25_()}else{alert('Invalid password')}}catch(_aa_){console.error('Login failed',_aa_);alert('Login failed')}}
      function _24_(){_5_.style.display='none';_9_.classList.add('active');
      _9_.innerHTML=\`<h2>Admin Panel</h2><div class="admin-actions"><button class="admin-btn" onclick="_26_()">Add Movie</button><button class="admin-btn" onclick="_27_()">Exit Admin</button></div><div class="movie-list-admin" id="movieListAdmin"></div>\`}
      function _27_(){_2_=null;_9_.classList.remove('active');_5_.style.display='grid'}function _26_(){_11_.classList.add('active')}
      async function _28_(){const _ab_=_0x.getElementById('movieTitle').value;const _ac_=_0x.getElementById('movieImdbId').value;
      const _ad_=_0x.getElementById('moviePassword').value;const _ae_=_0x.getElementById('oneTimePassword').value;
      if((!_ab_&&!_ac_)||!_ad_)return alert('Please provide movie title or IMDb ID and password');
      try{const _af_=await fetch(_1_+'/movies',{method:'POST',headers:{'Content-Type':'application/json','Authorization': \`Bearer \${_2_}\`},body:JSON.stringify({name:_ab_,imdbId:_ac_,moviePassword:_ad_,oneTimePassword:_ae_||null})});
      const _ag_=await _af_.json();if(_ag_.ok){alert('Movie added successfully');_21_();_25_();_29_()}else{alert('Error: '+_ag_.error)}}catch(_ah_){console.error('Add movie failed',_ah_);alert('Failed to add movie')}}
      async function _25_(){try{const _ai_=await fetch(_1_+'/movies');const _aj_=await _ai_.json();
      if(_aj_.ok){_3_=_aj_.movies;const _ak_=_0x.getElementById('movieListAdmin');_ak_.innerHTML='<h3>Movies</h3>';
      _aj_.movies.forEach(_al_=>{_ak_.appendChild(_0x.createElement('div')).outerHTML=\`<div class="movie-item-admin"><div><strong>\${_al_.title}</strong> \${_al_.year? \`(\${_al_.year})\`:''}</div><button onclick="_30_(\${_al_.id})">Delete</button></div>\`})}}catch(_am_){console.error('Failed to load admin movies',_am_)}}
      async function _30_(_an_){if(!confirm('Are you sure you want to delete this movie?'))return;
      try{const _ao_=await fetch(_1_+'/movies/'+_an_,{method:'DELETE',headers:{'Authorization': \`Bearer \${_2_}\`}});
      const _ap_=await _ao_.json();if(_ap_.ok){_25_();_29_()}else{alert('Error: '+_ap_.error)}}catch(_aq_){console.error('Delete failed',_aq_);alert('Failed to delete movie')}}
      async function _31_(){const _ar_=_0x.getElementById('moviePasswordInput').value;
      if(!_ar_)return alert('Please enter password');try{const _as_=await fetch(_1_+'/movies/'+_4_+'/authorize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:_ar_})});
      const _at_=await _as_.json();if(_at_.ok){const _au_=await fetch(_1_+'/movies/'+_4_+'/embed',{headers:{'Authorization': \`Bearer \${_at_.token}\`}});
      const _av_=await _au_.json();if(_av_.ok){_32_(_av_.url)}else{alert('Error: '+_av_.error)}}else{alert('Wrong password')}}catch(_aw_){console.error('Password verification failed',_aw_);alert('Error verifying password')}}
      function _32_(_ax_){_6_.src=_ax_;_7_.classList.add('active');_12_.classList.remove('active');_0x.getElementById('moviePasswordInput').value=''}
      function _33_(){_7_.classList.remove('active');_6_.src=''}
      async function _29_(){_5_.innerHTML='<p style="text-align:center;color:#aaa;">Loading...</p>';
      try{const _ay_=await fetch(_1_+'/movies');const _az_=await _ay_.json();
      if(!_az_.ok||!_az_.movies.length){_5_.innerHTML='<p style="text-align:center;color:#aaa;">No movies found.</p>';return}
      _5_.innerHTML='';_3_=_az_.movies;_15_(_3_)}catch(_ba_){console.error('Backend fetch failed',_ba_);_5_.innerHTML='<p style="color:red;text-align:center;">Error loading movies.</p>'}}
      _8_.addEventListener('click',_19_);_13_.addEventListener('input',(_bb_)=>_14_(_bb_.target.value));
      _0x.addEventListener('keydown',_bc_=>{if(_bc_.key==='Escape'){_33_();_20_();_21_();_22_()}});_29_();
    })();
  `;
  res.type('text/javascript').send(jsCode);
});

// Serve HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
