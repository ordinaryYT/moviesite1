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

// Initialize database table
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS movies (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        year VARCHAR(10),
        imdb_id VARCHAR(20),
        image TEXT,
        movie_password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Database initialized');
  } catch (error) {
    console.error('Database initialization failed:', error);
  }
}

// Routes

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
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
  
  try {
    const result = await pool.query('SELECT movie_password_hash FROM movies WHERE id = $1', [id]);
    
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
  await initDB();
  console.log(`Server running on port ${PORT}`);
});
