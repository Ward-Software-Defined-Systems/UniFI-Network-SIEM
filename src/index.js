const config = require('./config');
const logger = require('./utils/logger');
const { getDb, closeDb } = require('./db/database');
const { queueEvent, flushQueue, setOnInsert } = require('./db/events');
const { startRetentionSchedule } = require('./db/retention');
const { createSyslogServer } = require('./collector/syslog-server');
const { createServer } = require('./api/server');
const { broadcastEvent } = require('./api/websocket');
const { initGeoIp } = require('./enrichment/geoip');
const { enqueueEvent, backfillFromCache, shutdownWorker } = require('./enrichment/enrichment-queue');

async function main() {
  logger.info('Starting UniFi Network SIEM...');

  // Initialize database
  getDb();

  // Load saved settings from DB into in-memory config
  try {
    const db = getDb();
    const rows = db.prepare('SELECT key, value FROM settings').all();
    for (const row of rows) {
      try {
        const val = JSON.parse(row.value);
        if (row.key === 'abuseIpDbKey' && val && !config.enrichment.abuseIpDbKey) {
          config.enrichment.abuseIpDbKey = val;
          logger.info('Loaded AbuseIPDB API key from settings DB');
        }
        if (row.key === 'rdnsEnabled') {
          config.enrichment.rdnsEnabled = !!val;
        }
      } catch {}
    }
  } catch {}

  // Initialize GeoIP (async, non-blocking if DB missing)
  await initGeoIp();

  // Defer backfill — let the server start and stabilize first (30s delay)
  setTimeout(() => backfillFromCache(), 30000);

  // Set up WebSocket broadcast + enrichment on each inserted event
  setOnInsert((event) => {
    broadcastEvent(event);
    enqueueEvent(event);
  });

  // Start HTTP + WebSocket server
  createServer();

  // Start syslog collector
  createSyslogServer(config.syslog.port, (event) => {
    // Store raw message if configured
    if (config.logging.logRawMessages && event._raw) {
      event.raw_message = event._raw;
    }
    delete event._raw;
    delete event._rinfo;

    queueEvent(event);
  });

  // Start retention cleanup schedule
  startRetentionSchedule();

  // Periodic stats broadcast
  const { getEventTypeCounts } = require('./db/events');
  setInterval(() => {
    try {
      const byType = getEventTypeCounts();
      const { broadcastStats } = require('./api/websocket');
      broadcastStats({ byType });
    } catch {}
  }, 5000);

  // Graceful shutdown
  const shutdown = () => {
    logger.info('Shutting down...');
    shutdownWorker();
    flushQueue();
    closeDb();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  logger.info('UniFi Network SIEM is running');
}

main();
