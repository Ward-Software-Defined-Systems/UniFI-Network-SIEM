const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const config = require('../config');
const logger = require('../utils/logger');
const eventsRouter = require('./routes/events');
const statsRouter = require('./routes/stats');
const healthRouter = require('./routes/health');
const settingsRouter = require('./routes/settings');
const { createWebSocketServer } = require('./websocket');

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

  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" ` +
    `-days 365 -nodes -subj "/CN=unifi-siem-localhost"`,
    { stdio: 'pipe' }
  );

  logger.info({ keyPath, certPath }, 'Self-signed TLS certificate generated');
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

function createServer() {
  const app = express();
  app.use(express.json());

  // API routes
  app.use('/api/events', eventsRouter);
  app.use('/api/stats', statsRouter);
  app.use('/api/health', healthRouter);
  app.use('/api/settings', settingsRouter);

  // Serve frontend static files
  const frontendDist = path.join(__dirname, '../../frontend/dist');
  app.use(express.static(frontendDist));
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && !req.path.startsWith('/ws')) {
      res.sendFile(path.join(frontendDist, 'index.html'));
    }
  });

  const tlsOpts = ensureCerts();
  const server = https.createServer(tlsOpts, app);
  const wss = createWebSocketServer(server);

  server.listen(config.http.port, () => {
    logger.info({ port: config.http.port }, 'HTTPS server listening');
  });

  return { app, server, wss };
}

module.exports = { createServer };
