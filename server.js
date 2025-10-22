// server.js
import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.static('public')); // optional if you host HTML in /public

// Proxy endpoint
app.get('/proxy-video', async (req, res) => {
  const { video_id } = req.query;
  if (!video_id) return res.status(400).send('Missing video_id');

  try {
    const url = `https://multiembed.mov/?video_id=${video_id}`;
    const response = await fetch(url);
    let html = await response.text();

    // --- SANITIZE HTML ---
    html = html.replace(/window\.open\s*\(.*?\)/g, 'console.log("popup blocked")');
    html = html.replace(/target="_blank"/g, 'target="_self"');
    html = html.replace(/<script[^>]*ad[^>]*>.*?<\/script>/gis, '');

    res.set('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching video');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
