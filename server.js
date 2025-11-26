import express from "express";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(__dirname));

// Proxy to avoid exposing API key + fix CORS
app.get("/api/search", async (req, res) => {
  const q = req.query.q;
  const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${q}+music+official&type=video&videoCategoryId=10&maxResults=30&key=AIzaSyAMmMh2xRotnCthmKrZut9QjVd47qQ_7_o`;
  
  try {
    const response = await fetch(url);
    const data = await response.json();
    const results = data.items.map(item => ({
      id: item.id.videoId,
      title: item.snippet.title,
      artist: item.snippet.channelTitle,
      thumb: item.snippet.thumbnails.high?.url || item.snippet.thumbnails.medium.url
    }));
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: "YouTube API error" });
  }
});

// New endpoint for similar songs
app.get("/api/similar", async (req, res) => {
  const videoId = req.query.videoId;
  const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&videoCategoryId=10&maxResults=30&key=AIzaSyAMmMh2xRotnCthmKrZut9QjVd47qQ_7_o&relatedToVideoId=${videoId}`;
  
  try {
    const response = await fetch(url);
    const data = await response.json();
    const results = data.items.map(item => ({
      id: item.id.videoId,
      title: item.snippet.title,
      artist: item.snippet.channelTitle,
      thumb: item.snippet.thumbnails.high?.url || item.snippet.thumbnails.medium.url
    }));
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: "YouTube API error" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`OGmusic running → http://localhost:${PORT}`);
});
