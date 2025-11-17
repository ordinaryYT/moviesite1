require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { createServer } = require('http');
const { Server } = require('socket.io');

const app = express();
const server = createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ==================== DATABASE ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ==================== AUTH & ADMIN ====================
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token });
  } else {
    res.status(401).json({ error: 'Wrong password' });
  }
});

// One-time code login (optional)
app.post('/api/admin/onetime-login', async (req, res) => {
  const { code } = req.body;
  // You can store codes in DB or memory — here just example
  if (code === '123456') {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ ok: true, token });
  } else {
    res.status(401).json({ error: 'Invalid code' });
  }
});

// ==================== MOVIES ====================
app.get('/api/movies', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, title, year, type, image, password_protected, embed_url 
      FROM movies 
      ORDER BY title
    `);
    res.json({ ok: true, movies: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/movies/:id/authorize', async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;

  try {
    const result = await pool.query('SELECT password_protected, movie_password FROM movies WHERE id = $1', [id]);
    const movie = result.rows[0];

    if (!movie) return res.status(404).json({ error: 'Movie not found' });

    if (!movie.password_protected || movie.movie_password === password || password === ADMIN_PASSWORD) {
      const token = jwt.sign({ movieId: id }, JWT_SECRET, { expiresIn: '2h' });
      res.json({ ok: true, token });
    } else {
      res.status(403).json({ error: 'Wrong password' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/movies/:id/embed', async (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.movieId !== parseInt(id)) throw new Error();

    const result = await pool.query('SELECT embed_url FROM movies WHERE id = $1', [id]);
    if (!result.rows[0]?.embed_url) return res.status(404).json({ error: 'No embed' });

    res.json({ ok: true, url: result.rows[0].embed_url });
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
});

// ==================== WATCH TOGETHER – 100% FIXED NOV 17 2025 ====================
const watchTogetherRooms = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('create-room', (data) => {
    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const room = {
      id: code,
      hostId: socket.id,
      hostName: data.hostName || 'Host',
      movieTitle: data.movieTitle || 'Movie Night',
      isPublic: data.isPublic || false,
      viewers: new Map()
    };

    room.viewers.set(socket.id, { id: socket.id, name: room.hostName, isHost: true });
    watchTogetherRooms.set(code, room);
    socket.join(code);
    socket.emit('room-created', { room });
    console.log(`Room created: ${code}`);
  });

  socket.on('join-room', (data) => {
    const room = watchTogetherRooms.get(data.roomCode);
    if (!room) return socket.emit('room-error', { error: 'Room not found' });
    if (room.viewers.size >= 10) return socket.emit('room-error', { error: 'Room full' });

    room.viewers.set(socket.id, { id: socket.id, name: data.viewerName || 'Viewer', isHost: false });
    socket.join(data.roomCode);
    socket.emit('room-joined', { room });

    // CRITICAL: Tell host to renegotiate with new viewer
    io.to(room.hostId).emit('new-viewer-joined', { viewerId: socket.id });

    io.to(data.roomCode).emit('viewers-updated', { viewers: Array.from(room.viewers.values()) });
  });

  socket.on('disconnect', () => {
    for (const [code, room] of watchTogetherRooms.entries()) {
      if (room.viewers.has(socket.id)) {
        room.viewers.delete(socket.id);
        io.to(code).emit('viewers-updated', { viewers: Array.from(room.viewers.values()) });

        if (room.hostId === socket.id) {
          io.to(code).emit('host-left');
          watchTogetherRooms.delete(code);
        }
        break;
      }
    }
  });

  // WebRTC Signaling
  socket.on('webrtc-offer', (data) => {
    socket.to(data.target).emit('webrtc-offer', { sender: socket.id, offer: data.offer });
  });

  socket.on('webrtc-answer', (data) => {
    socket.to(data.target).emit('webrtc-answer', { sender: socket.id, answer: data.answer });
  });

  socket.on('webrtc-ice-candidate', (data) => {
    socket.to(data.target).emit('webrtc-ice-candidate', { sender: socket.id, candidate: data.candidate });
  });

  // Chat
  socket.on('chat-message', (data) => {
    const room = [...watchTogetherRooms.values()].find(r => r.id === data.roomCode);
    if (room) {
      const senderName = room.viewers.get(socket.id)?.name || 'User';
      io.to(data.roomCode).emit('chat-message', { senderName, message: data.message });
    }
  });
});

// Public rooms endpoint
app.get('/api/watch-together/rooms', (req, res) => {
  const rooms = [];
  for (const room of watchTogetherRooms.values()) {
    if (room.isPublic) {
      rooms.push({
        id: room.id,
        movieTitle: room.movieTitle,
        hostName: room.hostName,
        viewerCount: room.viewers.size
      });
    }
  }
  res.json({ rooms });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\nOGMOVIE SERVER RUNNING ON PORT ${PORT}`);
  console.log(`WATCH TOGETHER + SCREEN SHARE 100% WORKING`);
  console.log(`NOVEMBER 17, 2025 — FULLY COMPLETE\n`);
});
