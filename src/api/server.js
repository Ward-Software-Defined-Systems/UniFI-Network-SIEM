const express = require('express');
const helmet = require('helmet');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const config = require('../config');
const logger = require('../utils/logger');
const eventsRouter = require('./routes/events');
const statsRouter = require('./routes/stats');
const healthRouter = require('./routes/health');
const settingsRouter = require('./routes/settings');
const threatHuntRouter = require('./routes/threat-hunt');
const { createWebSocketServer } = require('./websocket');
const { requireApiToken } = require('./middleware/auth');

function ensureCerts() {
  const dataDir = path.resolve(config.db.path, '..');
  const keyPath = path.join(dataDir, 'server.key');
  const certPath = path.join(dataDir, 'server.cert');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  }

  logger.info('Generating self-signed TLS certificate...');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Use spawnSync with an args array — no shell metacharacter exposure even
  // if dataDir contains awkward characters (was execSync with shell quoting).
  const result = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048',
    '-keyout', keyPath, '-out', certPath,
    '-days', '365', '-nodes',
    '-subj', '/CN=unifi-siem-localhost',
  ], { stdio: 'pipe' });
  if (result.status !== 0) {
    const stderr = result.stderr?.toString() || '';
    throw new Error(`openssl failed (status ${result.status}): ${stderr}`);
  }

  logger.info({ keyPath, certPath }, 'Self-signed TLS certificate generated');
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

function createServer() {
  const app = express();

  // Security headers — CSP allows OpenStreetMap + CartoDB tiles for the
  // Live Map, inline styles for Tailwind, and wss: for the live event
  // WebSocket. Adjust if you swap tile providers or add inline scripts.
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:', 'https://*.tile.openstreetmap.org', 'https://*.basemaps.cartocdn.com'],
        'connect-src': ["'self'", 'wss:', 'https:'],
        'font-src': ["'self'", 'data:'],
        'object-src': ["'none'"],
        'frame-ancestors': ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false, // would block OSM tiles
  }));

  // Bound JSON body size — defense-in-depth against malicious payloads.
  app.use(express.json({ limit: '64kb' }));
  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request body too large (64 KB limit)' });
    }
    next(err);
  });

  // ---------------------------------------------------------------------
  // Auth: every /api/* router below requires a valid SIEM_API_TOKEN.
  // Static frontend files (index.html + bundle) are NOT gated so the
  // login UI can boot. The login form probes /api/health with the
  // candidate token to verify it before storing.
  // ---------------------------------------------------------------------
  app.use('/api/events', requireApiToken, eventsRouter);
  app.use('/api/stats', requireApiToken, statsRouter);
  app.use('/api/health', requireApiToken, healthRouter);
  app.use('/api/settings', requireApiToken, settingsRouter);
  app.use('/api/threat-hunt', requireApiToken, threatHuntRouter);

  // Serve frontend static files (no auth — needed to load the login UI).
  const frontendDist = path.join(__dirname, '../../frontend/dist');
  app.use(express.static(frontendDist));
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && !req.path.startsWith('/ws')) {
      res.sendFile(path.join(frontendDist, 'index.html'));
    }
  });

  const tlsOpts = ensureCerts();
  const server = https.createServer(tlsOpts, app);
  // Defaults to the schema-tracked perf timeouts. Operators can override via
  // Settings UI (requires restart since these are read once at server boot).
  server.timeout = config.performance.httpServerTimeoutMs;
  server.keepAliveTimeout = config.performance.httpKeepAliveTimeoutMs;
  server.headersTimeout = config.performance.httpHeadersTimeoutMs;
  const wss = createWebSocketServer(server);

  server.listen(config.http.port, config.http.host, () => {
    logger.info({ port: config.http.port, host: config.http.host }, 'HTTPS server listening');
    if (config.http.host === '127.0.0.1') {
      logger.info('HTTP_HOST=127.0.0.1 (default) — dashboard is reachable from this host only. Set HTTP_HOST=0.0.0.0 (or your LAN IP) in .env to expose to the network.');
    }
  });

  return { app, server, wss };
}

module.exports = { createServer };
