// gateway.js
/**
 * IMMERSE Wallet Gateway (static UI + API proxy)
 *
 * Purpose:
 * - Serve the wallet frontend (Three.js 2D/3D/AR UI) as static files.
 * - Forward all API calls from the browser to the wallet backend under a single origin
 *   to avoid CORS complexity (the browser talks to /api/*; the gateway proxies to BACKEND_URL).
 */
const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const FRONTEND_DIR = path.join(__dirname, 'frontend');
const app = express();

app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'xr-spatial-tracking=(self)');
  next();
});

app.use(express.static(FRONTEND_DIR));

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:4000';

app.use('/api', createProxyMiddleware({
  target: BACKEND_URL, //target: 'http://127.0.0.1:4000',
  changeOrigin: true,           // changes Host header (not Origin)
  pathRewrite: { '^/api': '' }, // /api/login -> /login
}));

// fallback for anything NOT starting with /api
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, 'frontend.html')); 
});

app.listen(8080, '0.0.0.0', () => {
  console.log('Gateway up at http://0.0.0.0:8080');
});