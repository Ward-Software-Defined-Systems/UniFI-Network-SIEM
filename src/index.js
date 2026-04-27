const config = require('./config');
const logger = require('./utils/logger');
const storage = require('./db/storage');
const { createSyslogServer, pause: pauseSyslog, resume: resumeSyslog } = require('./collector/syslog-server');
const { createServer } = require('./api/server');
const { broadcastEvent, broadcastStats, getClientCount } = require('./api/websocket');
const { initGeoIp } = require('./enrichment/geoip');
const { enqueueEvent, backfillFromCache, shutdownWorker, setCacheAccessors, setUpdateEnrichment, setBatchUpdateEnrichment, queueEnrichmentUpdate } = require('./enrichment/enrichment-queue');

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
        // DB-stored key wins over .env when present and non-empty.
        // Settings UI is the user-facing source of truth; .env is bootstrap fallback.
        if (row.key === 'abuseIpDbKey' && typeof val === 'string' && val.trim()) {
          config.enrichment.abuseIpDbKey = val.trim();
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
    // Maintain an in-memory mirror so the sync enrichment queue can check cache
    const backend = storage.getBackend();
    const memCache = new Map();
    // Pre-warm: load existing cache entries from backend
    backend.getAllCachedEnrichment?.().then(entries => {
      for (const e of (entries || [])) {
        if (e.ip) memCache.set(e.ip, e);
      }
      logger.info({ size: memCache.size }, 'Enrichment memory cache warmed from backend');
    }).catch(() => {});
    setCacheAccessors(
      (ip) => memCache.get(ip) || null,
      (ip, data) => {
        memCache.set(ip, { ip, ...data });
        backend.setCachedEnrichment(ip, data).catch(() => {});
      },
      (ip) => {
        memCache.set(ip, { ip, is_private: true });
        backend.markPrivate(ip).catch(() => {});
      },
    );
    // Wire up event enrichment updates for external backends
    setUpdateEnrichment((ip, direction, data, limit) =>
      backend.updateEnrichment(ip, direction, data, limit)
    );
    // Wire up batch update if the backend supports it (OpenSearch)
    if (typeof backend.updateEnrichmentBatch === 'function') {
      setBatchUpdateEnrichment((ips, direction, data) =>
        backend.updateEnrichmentBatch(ips, direction, data)
      );
    }

    // Deferred startup backfill for external backends (matches SQLite's 30s delay)
    setTimeout(() => {
      if (memCache.size === 0) return;
      const { isPrivateIp } = require('./utils/ip-utils');
      const entries = [...memCache.values()].filter(e =>
        e.ip && !isPrivateIp(e.ip) && !e.is_private && (e.geo_country || e.abuse_score != null)
      );
      if (entries.length === 0) return;
      logger.info({ ips: entries.length }, 'Starting enrichment backfill for external backend');
      for (const e of entries) {
        const data = {
          geo_country: e.geo_country,
          geo_city: e.geo_city,
          geo_lat: e.geo_lat,
          geo_lon: e.geo_lon,
          abuse_score: e.abuse_score,
          hostname: e.hostname,
        };
        queueEnrichmentUpdate(e.ip, 'src', data);
        queueEnrichmentUpdate(e.ip, 'dst', data);
      }
    }, 30000);
  }

  // Set up broadcast + enrichment on each inserted event
  onInsertCallbacks.push((event) => {
    broadcastEvent(event);
    enqueueEvent(event);
  });

  // Start HTTP + WebSocket server
  const { app } = createServer();
  app.locals.pauseSyslog = pauseSyslog;
  app.locals.resumeSyslog = resumeSyslog;

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

  // Periodic stats broadcast — skip both the backend query and the broadcast
  // when no WS clients are connected (saves a backend roundtrip every 5s).
  const statsInterval = setInterval(async () => {
    if (getClientCount() === 0) return;
    try {
      const backend = storage.getBackend();
      const byType = await backend.getEventTypeCounts();
      broadcastStats({ byType });
    } catch {}
  }, 5000);

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutting down...');
    shutdownWorker();
    await flushQueue();
    clearInterval(retentionInterval);
    clearInterval(statsInterval);
    await storage.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  logger.info({ backend: backendName }, 'UniFi Network SIEM is running');
}

main();
