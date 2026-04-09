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
let _updateDrainTimer = null;
let _shuttingDown = false;
const UPDATE_BATCH_DELAY_MS = 500;  // Accumulate for 500ms before draining
const UPDATE_BATCH_MAX_IPS = 50;    // Or drain when 50 IPs queued per direction
const UPDATE_BATCH_DRAIN_LIMIT = 200; // Max items to drain per cycle (prevents mega-batches)

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
  _updateQueue.push({ ip, direction, data });

  // Drain immediately if we have enough items, otherwise debounce
  if (_updateQueue.length >= UPDATE_BATCH_MAX_IPS * 2) {
    if (_updateDrainTimer) { clearTimeout(_updateDrainTimer); _updateDrainTimer = null; }
    drainUpdateQueue();
  } else if (!_updateDrainTimer && !_updateRunning) {
    _updateDrainTimer = setTimeout(() => { _updateDrainTimer = null; drainUpdateQueue(); }, UPDATE_BATCH_DELAY_MS);
  }
}

async function drainUpdateQueue() {
  if (_updateRunning || _shuttingDown) return;
  _updateRunning = true;

  while (_updateQueue.length > 0 && !_shuttingDown) {
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

  _updateRunning = false;
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

function backfillFromCache() {
  initWorker();
  setTimeout(() => {
    sendToWorker({ type: 'backfill' });
  }, 1000);
}

function shutdownWorker() {
  _shuttingDown = true;
  // Clear pending update queue and drain timer
  _updateQueue.length = 0;
  if (_updateDrainTimer) { clearTimeout(_updateDrainTimer); _updateDrainTimer = null; }
  if (worker) {
    worker.postMessage({ type: 'shutdown' });
    worker = null;
  }
}

module.exports = { enqueueEvent, enqueueIp, getQueueSize, backfillFromCache, shutdownWorker, setCacheAccessors, setUpdateEnrichment, setBatchUpdateEnrichment, queueEnrichmentUpdate };
