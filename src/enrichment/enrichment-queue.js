const { Worker } = require('worker_threads');
const path = require('path');
const { isPrivateIp } = require('../utils/ip-utils');
const { lookupGeoIp, isGeoIpAvailable } = require('./geoip');
const { checkIp, isAbuseIpDbAvailable } = require('./abuseipdb');
const { reverseLookup } = require('./rdns');
const config = require('../config');
const logger = require('../utils/logger');

const ipQueue = new Set();
let processing = false;
let activeCount = 0;

// Worker thread for SQLite UPDATE operations (only used with SQLite backend)
let worker = null;

// Cache access — resolved at runtime based on active backend
let _getCache = null;
let _setCache = null;
let _markPrivate = null;
let _updateEnrichment = null;      // Single-IP update (backend.updateEnrichment)
let _batchUpdateEnrichment = null; // Batch update (backend.updateEnrichmentBatch) — optional
let _updateQueue = [];              // Serialized queue for update_by_query calls
let _updateRunning = false;
let _updateRunningPromise = null;   // Resolves when the in-flight drain finishes
let _updateDrainTimer = null;
let _shuttingDown = false;
let _drainingForShutdown = false;   // M7: lets the shutdown drain bypass the _shuttingDown guard
let _droppedSinceLastWarn = 0;       // M8: throttle queue-drop warnings
let _lastDropWarn = 0;
const UPDATE_BATCH_DELAY_MS = 500;  // Accumulate for 500ms before draining
const UPDATE_BATCH_MAX_IPS = 50;    // Or drain when 50 IPs queued per direction
const UPDATE_BATCH_DRAIN_LIMIT = 200; // Max items to drain per cycle (prevents mega-batches)
const SHUTDOWN_DRAIN_TIMEOUT_MS = 5000; // M7: bound the shutdown drain

function setCacheAccessors(getCached, setCached, markPriv) {
  _getCache = getCached;
  _setCache = setCached;
  _markPrivate = markPriv;
}

function setUpdateEnrichment(fn) {
  _updateEnrichment = fn;
}

function setBatchUpdateEnrichment(fn) {
  _batchUpdateEnrichment = fn;
}

/** Queue an enrichment update — batched drain groups IPs with same data */
function queueEnrichmentUpdate(ip, direction, data) {
  if (_shuttingDown) return;
  if (!_updateEnrichment && !_batchUpdateEnrichment) return;
  if (isPrivateIp(ip)) return;

  // M8: high-watermark backpressure. If a downstream backend stalls
  // (network blip, OpenSearch GC pause, WardSONDB index rebuild) the
  // queue can grow unbounded, eating heap. When we hit the cap, drop
  // the OLDEST entry — the new enrichment is more likely to reflect
  // current state than a 30-minute-old queued update. Warn at most
  // once every 30s so a flood doesn't drown the logs.
  const max = config.enrichment?.queueMaxDepth || 50000;
  if (_updateQueue.length >= max) {
    _updateQueue.shift();
    _droppedSinceLastWarn++;
    const now = Date.now();
    if (now - _lastDropWarn > 30000) {
      logger.warn(
        { dropped: _droppedSinceLastWarn, max, queue: _updateQueue.length },
        'Enrichment update queue at capacity — dropping oldest entries',
      );
      _lastDropWarn = now;
      _droppedSinceLastWarn = 0;
    }
  }

  _updateQueue.push({ ip, direction, data });

  // Drain immediately if we have enough items, otherwise debounce
  if (_updateQueue.length >= UPDATE_BATCH_MAX_IPS * 2) {
    if (_updateDrainTimer) { clearTimeout(_updateDrainTimer); _updateDrainTimer = null; }
    drainUpdateQueue();
  } else if (!_updateDrainTimer && !_updateRunning) {
    _updateDrainTimer = setTimeout(() => { _updateDrainTimer = null; drainUpdateQueue(); }, UPDATE_BATCH_DELAY_MS);
  }
}

function drainUpdateQueue() {
  // If a drain is already running, just hand back its promise — callers
  // (including the shutdown path) can await the same drain rather than
  // racing a second one and double-processing items.
  if (_updateRunning) return _updateRunningPromise;
  // M7: during normal operation, _shuttingDown blocks new drains. The
  // shutdown path flips _drainingForShutdown to bypass this so the
  // bounded shutdown drain can flush whatever was already queued.
  if (_shuttingDown && !_drainingForShutdown) return Promise.resolve();
  _updateRunning = true;
  _updateRunningPromise = (async () => {
    try {
      while (_updateQueue.length > 0) {
        if (_shuttingDown && !_drainingForShutdown) break;
        // Take a bounded chunk to prevent mega-batches
        const batch = _updateQueue.splice(0, UPDATE_BATCH_DRAIN_LIMIT);

        if (_batchUpdateEnrichment) {
          // Group by direction + enrichment data for batch calls
          const groups = new Map();
          for (const item of batch) {
            const key = `${item.direction}:${JSON.stringify(item.data)}`;
            if (!groups.has(key)) {
              groups.set(key, { direction: item.direction, data: item.data, ips: [] });
            }
            groups.get(key).ips.push(item.ip);
          }

          for (const group of groups.values()) {
            try {
              const result = await _batchUpdateEnrichment(group.ips, group.direction, group.data);
              if (result.updated > 0) {
                logger.debug({ ips: group.ips.length, direction: group.direction, updated: result.updated }, 'Batch enrichment update');
              }
            } catch (err) {
              logger.warn({ err: err.message, ips: group.ips.length, direction: group.direction }, 'Batch enrichment update failed');
            }
          }
        } else if (_updateEnrichment) {
          // Fallback: serial per-IP updates
          for (const { ip, direction, data } of batch) {
            try {
              await _updateEnrichment(ip, direction, data);
            } catch (err) {
              logger.warn({ err: err.message, ip, direction }, 'Enrichment update failed');
            }
          }
        }
      }
    } finally {
      _updateRunning = false;
      _updateRunningPromise = null;
    }
  })();
  return _updateRunningPromise;
}

function initWorker() {
  if (worker) return;

  worker = new Worker(path.join(__dirname, 'enrichment-worker.js'), {
    workerData: { dbPath: config.db.path },
  });

  worker.on('message', (msg) => {
    switch (msg.type) {
      case 'ready':
        logger.info('Enrichment worker thread started');
        break;
      case 'backfill-start':
        logger.info({ ips: msg.ips }, 'Worker: starting enrichment backfill');
        break;
      case 'backfill-progress':
        logger.info({ processed: msg.processed, total: msg.total, updated: msg.totalUpdated }, 'Worker: backfill progress');
        break;
      case 'backfill-done':
        logger.info({ ips: msg.ips, totalUpdated: msg.totalUpdated }, 'Worker: backfill complete');
        break;
      case 'update-done':
        logger.debug({ ip: msg.ip, src: msg.srcChanged, dst: msg.dstChanged }, 'Worker: enrichment update applied');
        break;
      case 'update-error':
        // H18: surface SQLITE_BUSY / I/O errors that previously vanished
        // silently in the worker's catch.
        logger.warn({ ip: msg.ip, err: msg.error, code: msg.code }, 'Worker: enrichment update failed');
        break;
    }
  });

  worker.on('error', (err) => {
    logger.error({ err }, 'Enrichment worker error');
  });

  worker.on('exit', (code) => {
    if (code !== 0) {
      logger.warn({ code }, 'Enrichment worker exited unexpectedly, restarting...');
      worker = null;
      setTimeout(initWorker, 5000);
    }
  });
}

function sendToWorker(msg) {
  if (!worker) initWorker();
  worker.postMessage(msg);
}

function enqueueIp(ip) {
  if (!ip || ipQueue.has(ip)) return;
  if (isPrivateIp(ip)) return;
  if (!_getCache) return; // Not initialized yet

  const cached = _getCache(ip);
  if (cached) {
    if (cached.geo_country || cached.abuse_score != null) {
      const data = {
        geo_country: cached.geo_country,
        geo_city: cached.geo_city,
        geo_lat: cached.geo_lat,
        geo_lon: cached.geo_lon,
        abuse_score: cached.abuse_score,
        hostname: cached.hostname,
      };
      if (worker) {
        // SQLite: delegate to worker thread
        sendToWorker({ type: 'update', ip, data });
      } else if (_updateEnrichment) {
        // External backends: queue serial update_by_query calls
        queueEnrichmentUpdate(ip, 'src', data);
        queueEnrichmentUpdate(ip, 'dst', data);
      }
    }
    if (cached.abuse_score == null && isAbuseIpDbAvailable()) {
      ipQueue.add(ip);
      processQueue();
    }
    return;
  }

  ipQueue.add(ip);
  processQueue();
}

function enqueueEvent(event) {
  const types = new Set(['firewall', 'threat', 'dns_filter']);
  if (!types.has(event.event_type)) return;

  if (event.src_ip) enqueueIp(event.src_ip);
  if (event.dst_ip) enqueueIp(event.dst_ip);
}

async function processQueue() {
  if (processing) return;
  processing = true;

  while (ipQueue.size > 0 && activeCount < config.enrichment.concurrency) {
    const ip = ipQueue.values().next().value;
    ipQueue.delete(ip);
    activeCount++;

    enrichIp(ip).finally(() => {
      activeCount--;
      if (ipQueue.size > 0) processQueue();
    });
  }

  processing = false;
}

async function enrichIp(ip) {
  try {
    if (isPrivateIp(ip)) {
      if (_markPrivate) _markPrivate(ip);
      return;
    }

    const existing = _getCache ? _getCache(ip) : null;
    const enrichment = {
      geo_country: existing?.geo_country || null,
      geo_city: existing?.geo_city || null,
      geo_lat: existing?.geo_lat || null,
      geo_lon: existing?.geo_lon || null,
      abuse_score: existing?.abuse_score ?? null,
      hostname: existing?.hostname || null,
    };

    if (!enrichment.geo_country && isGeoIpAvailable()) {
      const geo = lookupGeoIp(ip);
      if (geo) {
        enrichment.geo_country = geo.country;
        enrichment.geo_city = geo.city;
        enrichment.geo_lat = geo.lat;
        enrichment.geo_lon = geo.lon;
      }
    }

    if (isAbuseIpDbAvailable()) {
      const abuse = await checkIp(ip);
      if (abuse) {
        enrichment.abuse_score = abuse.abuseScore;
        if (!enrichment.geo_country && abuse.countryCode) {
          enrichment.geo_country = abuse.countryCode;
        }
      }
    }

    if (config.enrichment.rdnsEnabled) {
      enrichment.hostname = await reverseLookup(ip);
    }

    // Cache the result
    if (_setCache) _setCache(ip, enrichment);

    // Update existing events with enrichment data
    if (worker) {
      // SQLite: delegate to worker thread
      sendToWorker({ type: 'update', ip, data: enrichment });
    } else if (_updateEnrichment) {
      // External backends: queue serial update_by_query calls
      queueEnrichmentUpdate(ip, 'src', enrichment);
      queueEnrichmentUpdate(ip, 'dst', enrichment);
    }

    logger.debug({ ip, country: enrichment.geo_country, abuse: enrichment.abuse_score }, 'Enriched IP');
  } catch (err) {
    logger.warn({ err, ip }, 'Failed to enrich IP');
  }
}

function getQueueSize() {
  return ipQueue.size;
}

// M8: expose the update-queue depth so /api/health surfaces backpressure.
function getUpdateQueueSize() {
  return _updateQueue.length;
}

function backfillFromCache() {
  initWorker();
  setTimeout(() => {
    sendToWorker({ type: 'backfill' });
  }, 1000);
}

async function shutdownWorker() {
  // M7: drain any queued external-backend enrichment updates with a
  // bounded timeout BEFORE tearing down. Without this, a normal
  // SIGTERM dropped recently-queued update_by_query calls on the
  // floor — the next OpenSearch dashboard render saw stale enrichment
  // until the next event for that IP triggered a re-queue.
  _shuttingDown = true;
  if (_updateDrainTimer) { clearTimeout(_updateDrainTimer); _updateDrainTimer = null; }

  if (_updateQueue.length > 0 || _updateRunning) {
    _drainingForShutdown = true;
    try {
      const drain = drainUpdateQueue();
      const timeout = new Promise((resolve) => {
        const t = setTimeout(resolve, SHUTDOWN_DRAIN_TIMEOUT_MS);
        if (typeof t.unref === 'function') t.unref();
      });
      await Promise.race([drain, timeout]);
      if (_updateQueue.length > 0) {
        logger.warn({ remaining: _updateQueue.length }, 'Enrichment update queue not fully drained at shutdown');
      }
    } finally {
      _drainingForShutdown = false;
    }
  }

  _updateQueue.length = 0;

  if (worker) {
    worker.postMessage({ type: 'shutdown' });
    worker = null;
  }
}

module.exports = { enqueueEvent, enqueueIp, getQueueSize, getUpdateQueueSize, backfillFromCache, shutdownWorker, setCacheAccessors, setUpdateEnrichment, setBatchUpdateEnrichment, queueEnrichmentUpdate };
