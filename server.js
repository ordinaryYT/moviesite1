const API = location.origin + '/api';
const EMBED_BASE = 'https://multiembed.mov/?video_id=';
const movieGrid = document.getElementById('movieGrid');
const playerIframe = document.getElementById('playerIframe');
const playerContainer = document.getElementById('playerContainer');
const adminBtn = document.getElementById('adminBtn');
const adminPanel = document.getElementById('adminPanel');
const loginModal = document.getElementById('loginModal');
const addMovieModal = document.getElementById('addMovieModal');
const passwordModal = document.getElementById('passwordModal');
const loadingScreen = document.getElementById('loadingScreen');
const searchInput = document.getElementById('searchInput');
const watermarkElement = document.querySelector('.iframe-overlay');
const watermarkBlocker = document.querySelector('.watermark-blocker');

let adminToken = null;
let currentMovies = [];
let selectedMovieId = null;
let loadingTimer = null;
let clickCount = 0;
let watermarkInterval = null;
let isMonitoring = false;
const MAX_LOADING_CLICKS = 5;
const LOADING_DURATION = 10000;

// === Watermark Hiding System ===
function startWatermarkHiding() {
  stopWatermarkHiding();
  isMonitoring = true;
  
  console.log('🚀 Starting watermark hiding system...');
  
  // CONSTANT monitoring - check every 100ms
  watermarkInterval = setInterval(() => {
    if (!playerContainer.classList.contains('active') || !isMonitoring) {
      stopWatermarkHiding();
      return;
    }
    
    // ALWAYS show loading screen to block their watermark
    if (!loadingScreen.classList.contains('active')) {
      showLoadingScreen();
    }
    
  }, 100); // Check every 100ms - CONSTANT
}

function stopWatermarkHiding() {
  isMonitoring = false;
  if (watermarkInterval) {
    clearInterval(watermarkInterval);
    watermarkInterval = null;
  }
  if (loadingTimer) {
    clearTimeout(loadingTimer);
    loadingTimer = null;
  }
  console.log('🛑 Watermark hiding stopped');
}

function showLoadingScreen() {
  if (!loadingScreen.classList.contains('active')) {
    loadingScreen.classList.add('active');
    console.log('📺 Loading screen shown - hiding their watermark');
    
    // Keep loading screen up for 10 seconds
    loadingTimer = setTimeout(() => {
      hideLoadingScreen();
    }, LOADING_DURATION);
  }
}

function hideLoadingScreen() {
  if (loadingScreen.classList.contains('active')) {
    loadingScreen.classList.remove('active');
    console.log('📺 Loading screen hidden');
  }
}

// === Search Functionality ===
function filterMovies(searchTerm) {
  const filteredMovies = currentMovies.filter(movie => 
    movie.title.toLowerCase().includes(searchTerm.toLowerCase())
  );
  displayMovies(filteredMovies);
}

function displayMovies(movies) {
  movieGrid.innerHTML = '';
  if (movies.length === 0) {
    movieGrid.innerHTML = '<p style="text-align:center;color:#aaa;grid-column:1/-1;">No movies found</p>';
    return;
  }
  movies.forEach(movie => {
    createMovieCard(movie);
  });
}

async function getMoviePoster(movieTitle, year = '') {
  try {
    const response = await fetch(`https://api.tvmaze.com/search/shows?q=${encodeURIComponent(movieTitle)}`);
    const data = await response.json();
    if (data.length > 0 && data[0].show.image && data[0].show.image.medium) {
      return data[0].show.image.medium;
    }
  } catch (error) {
    console.log('TVMaze search failed');
  }
  
  try {
    const wikiResponse = await fetch(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(movieTitle.replace(/ /g, '_'))}`);
    const wikiData = await wikiResponse.json();
    if (wikiData.thumbnail && wikiData.thumbnail.source) {
      return wikiData.thumbnail.source;
    }
  } catch (error) {
    console.log('Wikipedia search failed');
  }
  
  return `https://via.placeholder.com/300x450/333/fff?text=${encodeURIComponent(movieTitle.substring(0, 20))}`;
}

async function createMovieCard(movie) {
  try {
    let img = movie.image;
    let year = movie.year || 'N/A';
    const poster = await getMoviePoster(movie.title, movie.year);
    if (!poster.includes('placeholder.com')) {
      img = poster;
    } else if (!img || img.includes('placeholder.com')) {
      img = poster;
    }
    
    const card = document.createElement('div');
    card.className = 'movie-card';
    card.innerHTML = `
      <img src="${img}" onerror="this.src='https://via.placeholder.com/300x450/333/fff?text=No+Poster'">
      <div class="movie-info"><h3>${movie.title}</h3><p>${year}</p></div>`;
    card.onclick = () => requestMoviePassword(movie.id, movie.title);
    movieGrid.appendChild(card);
  } catch (e) {
    console.error('Movie card render failed for', movie.title, e);
    const card = document.createElement('div');
    card.className = 'movie-card';
    card.innerHTML = `
      <img src="https://via.placeholder.com/300x450/333/fff?text=No+Poster">
      <div class="movie-info"><h3>${movie.title}</h3><p>${movie.year || 'N/A'}</p></div>`;
    card.onclick = () => requestMoviePassword(movie.id, movie.title);
    movieGrid.appendChild(card);
  }
}

// === Admin Functions ===
function openAdminPanel() {
  loginModal.classList.add('active');
}

function closeLoginModal() {
  loginModal.classList.remove('active');
}

function closeAddMovieModal() {
  addMovieModal.classList.remove('active');
}

async function adminLogin() {
  const password = document.getElementById('adminPassword').value;
  if (!password) return alert('Please enter password');
  
  try {
    const res = await fetch(API + '/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (data.ok) {
      adminToken = data.token;
      loginModal.classList.remove('active');
      showAdminPanel();
      loadAdminMovies();
    } else {
      alert('Invalid password');
    }
  } catch (e) {
    console.error('Login failed', e);
    alert('Login failed');
  }
}

function showAdminPanel() {
  movieGrid.style.display = 'none';
  adminPanel.classList.add('active');
  adminPanel.innerHTML = `
    <h2>Admin Panel</h2>
    <div class="admin-actions">
      <button class="admin-btn" onclick="openAddMovieModal()">Add Movie</button>
      <button class="admin-btn" onclick="exitAdmin()">Exit Admin</button>
    </div>
    <div class="movie-list-admin" id="movieListAdmin"></div>
  `;
}

function exitAdmin() {
  adminToken = null;
  adminPanel.classList.remove('active');
  movieGrid.style.display = 'grid';
}

function openAddMovieModal() {
  addMovieModal.classList.add('active');
}

async function addMovie() {
  const title = document.getElementById('movieTitle').value;
  const imdbId = document.getElementById('movieImdbId').value;
  const password = document.getElementById('moviePassword').value;
  
  if ((!title && !imdbId) || !password) {
    return alert('Please provide movie title or IMDb ID and password');
  }
  
  try {
    const res = await fetch(API + '/movies', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ 
        name: title, 
        imdbId: imdbId, 
        moviePassword: password 
      })
    });
    const data = await res.json();
    if (data.ok) {
      alert('Movie added successfully');
      closeAddMovieModal();
      loadAdminMovies();
      loadMovies();
    } else {
      alert('Error: ' + data.error);
    }
  } catch (e) {
    console.error('Add movie failed', e);
    alert('Failed to add movie');
  }
}

async function loadAdminMovies() {
  try {
    const res = await fetch(API + '/movies');
    const data = await res.json();
    if (data.ok) {
      currentMovies = data.movies;
      const movieListAdmin = document.getElementById('movieListAdmin');
      movieListAdmin.innerHTML = '<h3>Movies</h3>';
      
      data.movies.forEach(movie => {
        const movieItem = document.createElement('div');
        movieItem.className = 'movie-item-admin';
        movieItem.innerHTML = `
          <div>
            <strong>${movie.title}</strong> ${movie.year ? `(${movie.year})` : ''}
          </div>
          <button onclick="deleteMovie(${movie.id})">Delete</button>
        `;
        movieListAdmin.appendChild(movieItem);
      });
    }
  } catch (e) {
    console.error('Failed to load admin movies', e);
  }
}

async function deleteMovie(id) {
  if (!confirm('Are you sure you want to delete this movie?')) return;
  
  try {
    const res = await fetch(API + '/movies/' + id, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });
    const data = await res.json();
    if (data.ok) {
      loadAdminMovies();
      loadMovies();
    } else {
      alert('Error: ' + data.error);
    }
  } catch (e) {
    console.error('Delete failed', e);
    alert('Failed to delete movie');
  }
}

// === Movie Playback ===
function requestMoviePassword(movieId, movieTitle) {
  selectedMovieId = movieId;
  document.getElementById('passwordMovieTitle').textContent = movieTitle;
  passwordModal.classList.add('active');
}

function closePasswordModal() {
  passwordModal.classList.remove('active');
  selectedMovieId = null;
}

async function verifyMoviePassword() {
  const password = document.getElementById('moviePasswordInput').value;
  if (!password) return alert('Please enter password');
  
  try {
    const res = await fetch(API + '/movies/' + selectedMovieId + '/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (data.ok) {
      const embedRes = await fetch(API + '/movies/' + selectedMovieId + '/embed', {
        headers: {
          'Authorization': `Bearer ${data.token}`
        }
      });
      const embedData = await embedRes.json();
      if (embedData.ok) {
        showPlayer(embedData.url);
      } else {
        alert('Error: ' + embedData.error);
      }
    } else {
      alert('Wrong password');
    }
  } catch (e) {
    console.error('Password verification failed', e);
    alert('Error verifying password');
  }
}

function showPlayer(embedUrl) {
  clickCount = 0;
  playerIframe.src = embedUrl;
  playerContainer.classList.add('active');
  passwordModal.classList.remove('active');
  document.getElementById('moviePasswordInput').value = '';
  
  // Start CONSTANT watermark hiding
  setTimeout(() => {
    startWatermarkHiding();
  }, 1000);
  
  let interactionDetected = false;
  const handleInteraction = () => {
    if (!interactionDetected) {
      interactionDetected = true;
      clickCount++;
      setTimeout(() => {
        interactionDetected = false;
      }, 1000);
    }
  };
  
  window.addEventListener('blur', handleInteraction);
  playerContainer.addEventListener('click', handleInteraction);
  playerContainer.addEventListener('mousedown', handleInteraction);
  
  playerContainer._cleanUp = () => {
    window.removeEventListener('blur', handleInteraction);
    playerContainer.removeEventListener('click', handleInteraction);
    playerContainer.removeEventListener('mousedown', handleInteraction);
  };
}

function closePlayer() {
  playerContainer.classList.remove('active');
  playerIframe.src = '';
  hideLoadingScreen();
  stopWatermarkHiding();
  
  if (playerContainer._cleanUp) {
    playerContainer._cleanUp();
  }
}

// === Public Movie Loading ===
async function loadMovies() {
  movieGrid.innerHTML = '<p style="text-align:center;color:#aaa;">Loading...</p>';
  try {
    const res = await fetch(API + '/movies');
    const data = await res.json();
    if (!data.ok || !data.movies.length) {
      movieGrid.innerHTML = '<p style="text-align:center;color:#aaa;">No movies found.</p>';
      return;
    }
    movieGrid.innerHTML = '';
    currentMovies = data.movies;
    displayMovies(currentMovies);
  } catch (e) {
    console.error('Backend fetch failed', e);
    movieGrid.innerHTML = '<p style="color:red;text-align:center;">Error loading movies.</p>';
  }
}

// Event Listeners
adminBtn.addEventListener('click', openAdminPanel);
searchInput.addEventListener('input', (e) => {
  filterMovies(e.target.value);
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closePlayer();
    closeLoginModal();
    closeAddMovieModal();
    closePasswordModal();
  }
});

// Initialize
loadMovies();
