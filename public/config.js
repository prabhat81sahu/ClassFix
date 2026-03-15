// Global Configuration File
// When running locally on your computer, the app connects to http://localhost:3000

// We are forcing the app to always use the local backend until Render is properly configured
const API_BASE = window.location.hostname === 'localhost' ? 'http://localhost:3000' : '';
