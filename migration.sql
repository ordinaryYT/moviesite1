CREATE TABLE IF NOT EXISTS movies (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  imdb_id TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  year TEXT,
  image TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
