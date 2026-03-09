const config = require('./config');
const logger = require('./utils/logger');
const storage = require('./db/storage');
const { createSyslogServer } = require('./collector/syslog-server');
const { createServer } = require('./api/server');
const { broadcastEvent } = require('./api/websocket');
const { initGeoIp } = require('./enrichment/geoip');
const { enqueueEvent, backfillFromCache, shutdownWorker, setCacheAccessors } = require('./enrichment/enrichment-queue');

// Batch queue for the active backend
let queue = [];
let flushTimer = null;
let onInsertCallbacks = [];

function queueEvent(event) {
  if (!config.logging.logRawMessages) {
    delete event.raw_message;
  }
  queue.push(event);

  if (queue.length >= config.performance.insertBatchSize) {
    flushQueue();
  } else if (!flushTimer) {
    flushTimer = setTimeout(flushQueue, config.performance.insertBatchIntervalMs);
  }
}

async function flushQueue() {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  if (queue.length === 0) return;

  const batch = queue;
  queue = [];

  try {
    const backend = storage.getBackend();
    await backend.insertEvents(batch);

    for (const evt of batch) {
      for (const cb of onInsertCallbacks) {
        cb(evt);
      }
    }
  } catch (err) {
    logger.error({ err, count: batch.length }, 'Failed to insert event batch');
  }
}

async function main() {
  logger.info('Starting UniFi Network SIEM...');

  // Initialize storage (reads backend config from settings, connects)
  await storage.initialize();
  const backendName = storage.getBackendName();

  // Load saved settings from SQLite into in-memory config
  try {
    const settingsBackend = storage.getSettingsBackend();
    const rows = await settingsBackend.getAllSettings();
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

  // Initialize GeoIP
  await initGeoIp();

  // Set up cache accessors for enrichment queue (uses db/cache.js for SQLite, backend for others)
  if (backendName === 'SQLite') {
    const { getCachedEnrichment, setCachedEnrichment, markPrivate } = require('./db/cache');
    setCacheAccessors(getCachedEnrichment, setCachedEnrichment, markPrivate);
    // Defer backfill (SQLite only — worker thread handles UPDATEs)
    setTimeout(() => backfillFromCache(), 30000);
  } else {
    // For external backends, cache operations go through the backend
    const backend = storage.getBackend();
    setCacheAccessors(
      (ip) => { /* async not supported in sync path — enrichment queue will handle */ return null; },
      (ip, data) => { backend.setCachedEnrichment(ip, data).catch(() => {}); },
      (ip) => { backend.markPrivate(ip).catch(() => {}); },
    );
  }

  // Set up broadcast + enrichment on each inserted event
  onInsertCallbacks.push((event) => {
    broadcastEvent(event);
    enqueueEvent(event);
  });

  // Start HTTP + WebSocket server
  createServer();

  // Start syslog collector
  createSyslogServer(config.syslog.port, (event) => {
    if (config.logging.logRawMessages && event._raw) {
      event.raw_message = event._raw;
    }
    delete event._raw;
    delete event._rinfo;
    queueEvent(event);
  });

  // Start retention cleanup schedule (backend-aware)
  const retentionInterval = setInterval(async () => {
    try {
      const backend = storage.getBackend();
      const result = await backend.runRetention(config.db.retentionDays);
      if (result.deleted > 0) {
        logger.info({ deleted: result.deleted, retentionDays: config.db.retentionDays }, 'Retention cleanup completed');
      }
    } catch (err) {
      logger.error({ err }, 'Retention cleanup failed');
    }
  }, 60 * 60 * 1000);

  // Run retention once on startup
  try {
    const backend = storage.getBackend();
    await backend.runRetention(config.db.retentionDays);
  } catch {}

  // Periodic stats broadcast
  setInterval(async () => {
    try {
      const backend = storage.getBackend();
      const byType = await backend.getEventTypeCounts();
      const { broadcastStats } = require('./api/websocket');
      broadcastStats({ byType });
    } catch {}
  }, 5000);

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutting down...');
    shutdownWorker();
    await flushQueue();
    clearInterval(retentionInterval);
    await storage.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  logger.info({ backend: backendName }, 'UniFi Network SIEM is running');
}

main();
