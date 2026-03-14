// Global Configuration File
// When running locally on your computer, the app connects to http://localhost:3000
// When the app is live on GitHub Pages, it needs to connect to your live backend server (like Render or Heroku)

const IS_LOCAL = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost' || window.location.protocol === 'file:';

// 🔴 IMPORTANT: ONCE YOU DEPLOY YOUR BACKEND TO RENDER.COM, PASTE THE URL BELOW!
// Example: 'https://classfix-api.onrender.com'
const LIVE_BACKEND_URL = 'https://classfix.onrender.com';

const API_BASE = IS_LOCAL ? 'http://localhost:3000' : (LIVE_BACKEND_URL === 'PASTE_YOUR_RENDER_URL_HERE' ? 'http://localhost:3000' : LIVE_BACKEND_URL);
