require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const fetch = global.fetch || ((...args) => import('node-fetch').then(({ default: f }) => f(...args)));

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'boughton5';
const EMBED_BASE_MOVIE = 'https://vidsrc.me/embed/movie/';
const EMBED_BASE_TV = 'https://vidsrc.me/embed/tv/';
const MIGRATE_MOVIES = process.env.MIGRATE_MOVIES === 'true';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

let passwordsDisabled = false;

async function ensureTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS content (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        imdb_id TEXT,
        type TEXT NOT NULL CHECK (type IN ('movie', 'tv_show')),
        password_hashes JSONB DEFAULT '[]',
        one_time_password_hashes JSONB DEFAULT '[]',
        year TEXT,
        image TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Content table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS global_passwords (
        id SERIAL PRIMARY KEY,
        password_hash TEXT NOT NULL,
        is_one_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Global passwords table ready');

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
    console.log('✅ Movies table ready');

    if (MIGRATE_MOVIES) {
      const moviesTableExists = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'movies'
        )
      `);
      if (moviesTableExists.rows[0].exists) {
        console.log('ℹ️ Movies table found, attempting migration...');
        const columnsResult = await pool.query(`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = 'movies'
        `);
        const columns = columnsResult.rows.map(row => row.column_name);
        console.log('ℹ️ Movies table columns:', columns);

        const selectFields = ['title', 'imdb_id', 'year', 'image', 'created_at'].filter(col => columns.includes(col));
        const passwordFields = ['password_hash', 'one_time_password_hash'].filter(col => columns.includes(col));

        let query = `
          INSERT INTO content (
            title, 
            imdb_id, 
            type, 
            password_hashes, 
            one_time_password_hashes, 
            year, 
            image, 
            created_at
          )
          SELECT 
            title,
            imdb_id,
            'movie' AS type,
            CASE 
              WHEN ${columns.includes('password_hash') ? 'password_hash IS NOT NULL' : 'FALSE'} 
              THEN jsonb_build_array(password_hash) 
              ELSE '[]'::jsonb 
            END AS password_hashes,
            CASE 
              WHEN ${columns.includes('one_time_password_hash') ? 'one_time_password_hash IS NOT NULL' : 'FALSE'} 
              THEN jsonb_build_array(one_time_password_hash) 
              ELSE '[]'::jsonb 
            END AS one_time_password_hashes,
            ${selectFields.includes('year') ? 'year' : 'NULL'},
            ${selectFields.includes('image') ? 'image' : 'NULL'},
            ${selectFields.includes('created_at') ? 'created_at' : 'NOW()'}
          FROM movies
          ON CONFLICT DO NOTHING
          RETURNING id
        `;
        const migrationResult = await pool.query(query);
        console.log(`✅ Migrated ${migrationResult.rowCount} records from movies to content`);

        if (migrationResult.rowCount > 0) {
          await pool.query('DROP TABLE movies CASCADE');
          console.log('✅ Dropped movies table and dependencies');
        } else {
          console.log('ℹ️ No records migrated, preserving movies table');
        }
      } else {
        console.log('ℹ️ No movies table found, skipping migration');
      }
    } else {
      console.log('ℹ️ MIGRATE_MOVIES=false, preserving movies table');
    }
  } catch (err) {
    console.error('Error ensuring table schema:', err);
    throw err;
  }
}
ensureTable().catch(err => console.error('Failed to initialize database:', err));

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

app.get('/api/content', async (_, res) => {
  try {
    let result = await pool.query('SELECT id, title, type, year, image FROM content ORDER BY created_at DESC');
    console.log(`ℹ️ /api/content queried content table, found ${result.rowCount} items`);
    if (result.rowCount > 0) {
      return res.json({ ok: true, items: result.rows });
    }

    const moviesTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'movies'
      )
    `);
    if (moviesTableExists.rows[0].exists) {
      console.log('ℹ️ Content table empty, falling back to movies table');
      result = await pool.query('SELECT id, title, year, image FROM movies ORDER BY created_at DESC');
      console.log(`ℹ️ /api/content queried movies table, found ${result.rowCount} items`);
      const items = result.rows.map(row => ({
        id: row.id,
        title: row.title,
        type: 'movie',
        year: row.year,
        image: row.image
      }));
      return res.json({ ok: true, items });
    }

    console.log('ℹ️ No content or movies found');
    return res.json({ ok: true, items: [] });
  } catch (err) {
    console.error('Error in /api/content:', err);
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

app.post('/api/content', requireAdmin, async (req, res) => {
  try {
    const { name, imdbId, type, contentPasswords, oneTimePasswords } = req.body;
    if (!name && !imdbId) {
      return res.status(400).json({ ok: false, error: 'Provide title or IMDb ID' });
    }
    if (!['movie', 'tv_show'].includes(type)) {
      return res.status(400).json({ ok: false, error: 'Invalid content type' });
    }

    let contentData;
    if (imdbId) {
      contentData = {
        imdb_id: imdbId.startsWith('tt') ? imdbId : 'tt' + imdbId,
        title: name || imdbId,
        year: null,
        image: null
      };
    } else {
      const search = await searchImdb(name);
      if (!search) return res.status(404).json({ ok: false, error: 'No IMDb match found' });
      contentData = search;
    }

    const passwordHashes = contentPasswords && contentPasswords.length
      ? await Promise.all(contentPasswords.map(p => bcrypt.hash(p, 10)))
      : [];
    const oneTimePasswordHashes = oneTimePasswords && oneTimePasswords.length
      ? await Promise.all(oneTimePasswords.map(p => bcrypt.hash(p, 10)))
      : [];

    const result = await pool.query(
      'INSERT INTO content (title, imdb_id, type, password_hashes, one_time_password_hashes, year, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [contentData.title, contentData.imdb_id, type, JSON.stringify(passwordHashes), JSON.stringify(oneTimePasswordHashes), contentData.year, contentData.image]
    );

    console.log(`ℹ️ Added content ID ${result.rows[0].id}: ${contentData.title}`);
    res.json({ ok: true, contentId: result.rows[0].id });
  } catch (err) {
    console.error('Add content error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.delete('/api/content/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    let deleted = false;

    let r = await pool.query('DELETE FROM content WHERE id=$1 RETURNING id', [id]);
    if (r.rowCount > 0) {
      console.log(`ℹ️ Deleted content ID ${id} from content table`);
      deleted = true;
    } else {
      const moviesTableExists = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'movies'
        )
      `);
      if (moviesTableExists.rows[0].exists) {
        r = await pool.query('DELETE FROM movies WHERE id=$1 RETURNING id', [id]);
        if (r.rowCount > 0) {
          console.log(`ℹ️ Deleted content ID ${id} from movies table`);
          deleted = true;
        }
      }
    }

    if (!deleted) return res.status(404).json({ ok: false, error: 'Content not found' });
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

app.post('/api/content/:id/authorize', async (req, res) => {
  try {
    const id = req.params.id;
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ ok: false, error: 'Password required' });
    }

    if (passwordsDisabled) {
      if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ ok: false, error: 'Wrong password' });
      }
      const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
      console.log(`ℹ️ Authorized content ID ${id} with admin password`);
      return res.json({ ok: true, token });
    }

    let contentResult = await pool.query(
      'SELECT password_hashes, one_time_password_hashes, type FROM content WHERE id=$1',
      [id]
    );
    let isContentTable = true;
    if (!contentResult.rowCount) {
      const moviesTableExists = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'movies'
        )
      `);
      if (moviesTableExists.rows[0].exists) {
        console.log(`ℹ️ Content ID ${id} not found in content table, checking movies table`);
        contentResult = await pool.query(
          'SELECT password_hash, one_time_password_hash FROM movies WHERE id=$1',
          [id]
        );
        isContentTable = false;
      }
      if (!contentResult.rowCount) {
        console.log(`ℹ️ Content ID ${id} not found`);
        return res.status(404).json({ ok: false, error: 'Content not found' });
      }
    }

    let regularHashes = [];
    let oneTimeHashes = [];
    if (isContentTable) {
      const { password_hashes, one_time_password_hashes } = contentResult.rows[0];
      try {
        // Safely parse JSON, default to empty array if invalid or null
        regularHashes = (typeof password_hashes === 'string' && password_hashes)
          ? JSON.parse(password_hashes)
          : (password_hashes || []);
        oneTimeHashes = (typeof one_time_password_hashes === 'string' && one_time_password_hashes)
          ? JSON.parse(one_time_password_hashes)
          : (one_time_password_hashes || []);
      } catch (parseErr) {
        console.error(`JSON parse error for content ID ${id}:`, parseErr);
        // Log the problematic fields for debugging
        console.log(`ℹ️ password_hashes: ${JSON.stringify(password_hashes)}`);
        console.log(`ℹ️ one_time_password_hashes: ${JSON.stringify(one_time_password_hashes)}`);
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
    } else {
      const { password_hash, one_time_password_hash } = contentResult.rows[0];
      regularHashes = password_hash ? [password_hash] : [];
      oneTimeHashes = one_time_password_hash ? [one_time_password_hash] : [];
    }

    const globalResult = await pool.query('SELECT id, password_hash, is_one_time FROM global_passwords');

    for (let i = 0; i < oneTimeHashes.length; i++) {
      if (await bcrypt.compare(password, oneTimeHashes[i])) {
        if (isContentTable) {
          oneTimeHashes.splice(i, 1);
          await pool.query(
            'UPDATE content SET one_time_password_hashes = $1 WHERE id = $2',
            [JSON.stringify(oneTimeHashes), id]
          );
        } else {
          await pool.query(
            'UPDATE movies SET one_time_password_hash = NULL WHERE id = $1',
            [id]
          );
        }
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with ${isContentTable ? 'content' : 'movies'} one-time password`);
        return res.json({ ok: true, token });
      }
    }

    for (const global of globalResult.rows) {
      if (global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
        await pool.query('DELETE FROM global_passwords WHERE id = $1', [global.id]);
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with global one-time password`);
        return res.json({ ok: true, token });
      }
    }

    for (const hash of regularHashes) {
      if (await bcrypt.compare(password, hash)) {
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with ${isContentTable ? 'content' : 'movies'} password`);
        return res.json({ ok: true, token });
      }
    }

    for (const global of globalResult.rows) {
      if (!global.is_one_time && await bcrypt.compare(password, global.password_hash)) {
        const token = jwt.sign({ contentId: id }, JWT_SECRET, { expiresIn: '6h' });
        console.log(`ℹ️ Authorized content ID ${id} with global password`);
        return res.json({ ok: true, token });
      }
    }

    console.log(`ℹ️ Failed to authorize content ID ${id}: Wrong password`);
    return res.status(401).json({ ok: false, error: 'Wrong password' });
  } catch (err) {
    console.error(`Authorization error for content ID ${req.params.id}:`, err);
    res.status(500).json({ ok: false, error: 'Authorization failed' });
  }
});

app.get('/api/content/:id/embed', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer') return res.status(401).json({ ok: false, error: 'Missing token' });
    const data = jwt.verify(token, JWT_SECRET);
    const contentId = data.contentId;

    let r = await pool.query('SELECT imdb_id, type AS contentType FROM content WHERE id=$1', [contentId]);
    let isContentTable = true;
    if (!r.rowCount) {
      const moviesTableExists = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'movies'
        )
      `);
      if (moviesTableExists.rows[0].exists) {
        console.log(`ℹ️ Content ID ${contentId} not found in content table, checking movies table`);
        r = await pool.query('SELECT imdb_id FROM movies WHERE id=$1', [contentId]);
        isContentTable = false;
      }
      if (!r.rowCount) {
        console.log(`ℹ️ Content ID ${contentId} not found for embed`);
        return res.status(404).json({ ok: false, error: 'Content not found' });
      }
    }

    const { imdb_id } = r.rows[0];
    const contentType = isContentTable ? r.rows[0].contentType : 'movie';
    const baseUrl = contentType === 'movie' ? EMBED_BASE_MOVIE : EMBED_BASE_TV;
    const url = baseUrl + imdb_id;
    console.log(`ℹ️ Serving embed URL for content ID ${contentId}: ${url}`);
    res.json({ ok: true, url });
  } catch (err) {
    console.error('Embed error:', err);
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
