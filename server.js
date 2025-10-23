// server.js - Backend Server
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Helper function to verify admin token
function verifyAdminToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.json({ ok: false, error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.json({ ok: false, error: 'Invalid token' });
    }
    next();
  } catch (error) {
    return res.json({ ok: false, error: 'Invalid token' });
  }
}

// Comprehensive database initialization with migration
async function initDB() {
  let client;
  try {
    client = await pool.connect();
    console.log('Connected to database, running initialization...');

    // Step 1: Check if movies table exists
    const tableCheck = await client.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'movies'
      );
    `);

    if (!tableCheck.rows[0].exists) {
      // Create table if it doesn't exist
      console.log('Creating movies table...');
      await client.query(`
        CREATE TABLE movies (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          year VARCHAR(10),
          imdb_id VARCHAR(20),
          image TEXT,
          movie_password_hash TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Movies table created successfully');
    } else {
      console.log('✅ Movies table already exists');
    }

    // Step 2: Check and add missing columns one by one with proper error handling
    console.log('Checking for missing columns...');
    
    // Check and add movie_password_hash column
    try {
      const passwordHashCheck = await client.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'movies' 
        AND column_name = 'movie_password_hash'
      `);

      if (passwordHashCheck.rows.length === 0) {
        console.log('Adding missing column: movie_password_hash...');
        
        // First add the column with a temporary default value
        await client.query(`
          ALTER TABLE movies 
          ADD COLUMN movie_password_hash TEXT NOT NULL DEFAULT 'temp_default_hash_123'
        `);
        
        // Then update existing rows with proper hashes
        const defaultHash = await bcrypt.hash('defaultpassword', 10);
        await client.query(`
          UPDATE movies 
          SET movie_password_hash = $1 
          WHERE movie_password_hash = 'temp_default_hash_123'
        `, [defaultHash]);
        
        console.log('✅ movie_password_hash column added successfully');
      } else {
        console.log('✅ movie_password_hash column already exists');
      }
    } catch (columnError) {
      console.log('⚠️ movie_password_hash column might already exist, continuing...');
    }

    // Check and add other columns if needed
    const otherColumns = [
      { name: 'title', type: 'VARCHAR(255) NOT NULL DEFAULT \'Unknown Movie\'' },
      { name: 'year', type: 'VARCHAR(10)' },
      { name: 'imdb_id', type: 'VARCHAR(20)' },
      { name: 'image', type: 'TEXT' },
      { name: 'created_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' }
    ];

    for (const column of otherColumns) {
      try {
        const columnCheck = await client.query(`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = 'movies' 
          AND column_name = $1
        `, [column.name]);

        if (columnCheck.rows.length === 0) {
          console.log(`Adding missing column: ${column.name}...`);
          await client.query(`ALTER TABLE movies ADD COLUMN ${column.name} ${column.type}`);
          console.log(`✅ Column ${column.name} added successfully`);
        }
      } catch (error) {
        console.log(`⚠️ Column ${column.name} might already exist, continuing...`);
      }
    }

    // Step 3: Verify the table structure
    const finalCheck = await client.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'movies' 
      ORDER BY ordinal_position
    `);

    console.log('📊 Final table structure:');
    finalCheck.rows.forEach(row => {
      console.log(`   ${row.column_name} (${row.data_type}) - nullable: ${row.is_nullable}`);
    });

    console.log('✅ Database initialization completed successfully');

  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    
    // Try a simpler approach if the complex one fails
    try {
      console.log('🔄 Trying alternative initialization...');
      await client.query(`
        CREATE TABLE IF NOT EXISTS movies (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL DEFAULT 'Unknown Movie',
          year VARCHAR(10),
          imdb_id VARCHAR(20),
          image TEXT,
          movie_password_hash TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Alternative initialization successful');
    } catch (altError) {
      console.error('❌ Alternative initialization also failed:', altError);
      throw altError;
    }
  } finally {
    if (client) client.release();
  }
}

// Simple database reset function (use with caution)
async function resetDatabase() {
  let client;
  try {
    client = await pool.connect();
    console.log('🔄 Resetting database...');
    
    await client.query('DROP TABLE IF EXISTS movies');
    
    await client.query(`
      CREATE TABLE movies (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        year VARCHAR(10),
        imdb_id VARCHAR(20),
        image TEXT,
        movie_password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ Database reset successfully');
    return true;
  } catch (error) {
    console.error('❌ Database reset failed:', error);
    return false;
  } finally {
    if (client) client.release();
  }
}

// Force database migration endpoint (for manual fixes)
app.post('/api/admin/migrate', async (req, res) => {
  try {
    await initDB();
    res.json({ ok: true, message: 'Database migration completed' });
  } catch (error) {
    console.error('Migration error:', error);
    res.json({ ok: false, error: 'Migration failed: ' + error.message });
  }
});

// Database reset endpoint (use with caution - will delete all data)
app.post('/api/admin/reset-db', async (req, res) => {
  const { confirm } = req.body;
  
  if (confirm !== 'YES_DELETE_EVERYTHING') {
    return res.json({ 
      ok: false, 
      error: 'Safety confirmation required. Send confirm: "YES_DELETE_EVERYTHING" to reset database.' 
    });
  }
  
  try {
    const success = await resetDatabase();
    if (success) {
      res.json({ ok: true, message: 'Database reset completed successfully' });
    } else {
      res.json({ ok: false, error: 'Database reset failed' });
    }
  } catch (error) {
    console.error('Reset error:', error);
    res.json({ ok: false, error: 'Reset failed: ' + error.message });
  }
});

// Routes

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      ok: true, 
      message: 'Server and database are running',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.json({ 
      ok: false, 
      message: 'Server running but database connection failed',
      error: error.message 
    });
  }
});

// Database check endpoint
app.get('/api/debug/db', async (req, res) => {
  try {
    const tables = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    const moviesColumns = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'movies'
    `);
    
    const movieCount = await pool.query('SELECT COUNT(*) FROM movies');
    
    res.json({
      ok: true,
      tables: tables.rows,
      movies_columns: moviesColumns.rows,
      movie_count: parseInt(movieCount.rows[0].count)
    });
  } catch (error) {
    res.json({ 
      ok: false, 
      error: error.message 
    });
  }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  
  if (!password) {
    return res.json({ ok: false, error: 'Password required' });
  }
  
  try {
    if (password === ADMIN_PASSWORD) {
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
      return res.json({ ok: true, token });
    } else {
      return res.json({ ok: false, error: 'Invalid password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    return res.json({ ok: false, error: 'Login failed' });
  }
});

// Get all movies
app.get('/api/movies', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, title, year, imdb_id, image FROM movies ORDER BY title');
    res.json({ 
      ok: true, 
      movies: result.rows.map(movie => ({
        id: movie.id,
        title: movie.title,
        year: movie.year,
        imdbId: movie.imdb_id,
        image: movie.image
      }))
    });
  } catch (error) {
    console.error('Get movies error:', error);
    res.json({ ok: false, error: 'Failed to fetch movies' });
  }
});

// Add new movie
app.post('/api/movies', verifyAdminToken, async (req, res) => {
  const { name, imdbId, moviePassword } = req.body;
  
  if ((!name && !imdbId) || !moviePassword) {
    return res.json({ ok: false, error: 'Movie title or IMDb ID and password required' });
  }
  
  try {
    let movieData = { title: name, year: null, image: null };
    
    // Try to fetch movie data from OMDB if IMDb ID provided
    if (imdbId) {
      try {
        const omdbResponse = await fetch(`https://www.omdbapi.com/?i=${imdbId}&apikey=${process.env.OMDB_API_KEY || 'demo'}`);
        const omdbData = await omdbResponse.json();
        
        if (omdbData.Response === 'True') {
          movieData.title = omdbData.Title;
          movieData.year = omdbData.Year;
          movieData.image = omdbData.Poster !== 'N/A' ? omdbData.Poster : null;
        }
      } catch (omdbError) {
        console.log('OMDB fetch failed, using provided data');
      }
    }
    
    // Hash movie password
    const passwordHash = await bcrypt.hash(moviePassword, 10);
    
    const result = await pool.query(
      'INSERT INTO movies (title, year, imdb_id, image, movie_password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [movieData.title, movieData.year, imdbId, movieData.image, passwordHash]
    );
    
    res.json({ ok: true, movieId: result.rows[0].id });
  } catch (error) {
    console.error('Add movie error:', error);
    res.json({ ok: false, error: 'Failed to add movie' });
  }
});

// Delete movie
app.delete('/api/movies/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    await pool.query('DELETE FROM movies WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (error) {
    console.error('Delete movie error:', error);
    res.json({ ok: false, error: 'Failed to delete movie' });
  }
});

// Authorize movie access
app.post('/api/movies/:id/authorize', async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  
  if (!password) {
    return res.json({ ok: false, error: 'Password required' });
  }
  
  let client;
  try {
    client = await pool.connect();
    const result = await client.query('SELECT movie_password_hash FROM movies WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'Movie not found' });
    }
    
    const isValid = await bcrypt.compare(password, result.rows[0].movie_password_hash);
    
    if (isValid) {
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '6h' });
      return res.json({ ok: true, token });
    } else {
      return res.json({ ok: false, error: 'Wrong password' });
    }
  } catch (error) {
    console.error('Authorization error:', error);
    res.json({ ok: false, error: 'Authorization failed' });
  } finally {
    if (client) client.release();
  }
});

// Get movie embed URL
app.get('/api/movies/:id/embed', async (req, res) => {
  const { id } = req.params;
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.json({ ok: false, error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.movieId !== id) {
      return res.json({ ok: false, error: 'Invalid token' });
    }
    
    const result = await pool.query('SELECT imdb_id FROM movies WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'Movie not found' });
    }
    
    const imdbId = result.rows[0].imdb_id;
    
    if (!imdbId) {
      return res.json({ ok: false, error: 'No IMDb ID for this movie' });
    }
    
    const embedUrl = `https://multiembed.mov/?video_id=${imdbId}`;
    res.json({ ok: true, url: embedUrl });
  } catch (error) {
    console.error('Embed error:', error);
    res.json({ ok: false, error: 'Failed to get embed URL' });
  }
});

// Start server
app.listen(PORT, async () => {
  try {
    console.log('🚀 Starting server initialization...');
    await initDB();
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Health check available at: http://localhost:${PORT}/api/health`);
    console.log(`🐛 Database debug available at: http://localhost:${PORT}/api/debug/db`);
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
});
