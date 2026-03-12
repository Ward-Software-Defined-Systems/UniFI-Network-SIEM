const express = require('express');
const fs = require('fs');
const config = require('../../config');
const storage = require('../../db/storage');
const { isGeoIpAvailable } = require('../../enrichment/geoip');
const { isAbuseIpDbConfigured } = require('../../enrichment/abuseipdb');
const { getQueueSize } = require('../../enrichment/enrichment-queue');

const { getResetGraceStatus } = require('./settings');

const router = express.Router();
const startTime = Date.now();

// Race a promise against a timeout — returns fallback on timeout or error
function withTimeout(promise, ms, fallback) {
  return Promise.race([
    Promise.resolve(promise).catch(() => fallback),
    new Promise(resolve => setTimeout(() => resolve(fallback), ms)),
  ]);
}

const HEALTH_TIMEOUT_MS = 30000; // Timeout for backend health queries (generous for remote/VPN + large datasets)

router.get('/', async (req, res) => {
  try {
    const backend = storage.getBackend();
    const backendName = storage.getBackendName();
    const graceStatus = getResetGraceStatus();

    let dbSizeMB = 0;
    if (backendName === 'SQLite') {
      try {
        const stat = fs.statSync(config.db.path);
        dbSizeMB = Math.round(stat.size / 1024 / 1024 * 100) / 100;
      } catch {}
    }

    // Wrap backend calls with a timeout for WardSONDB (prevents hang when DB is overloaded)
    // SQLite is synchronous/fast — no timeout needed
    const useTimeout = backendName === 'WardSONDB';
    const TIMEOUT = '_TIMEOUT_';
    const wrap = (p) => useTimeout ? withTimeout(p, HEALTH_TIMEOUT_MS, TIMEOUT) : p;

    if (backendName === 'WardSONDB') {
      // Optimized path for WardSONDB: reuse data from healthCheck() to avoid
      // expensive full-scan queries (getEventCount, getLastEventTime).
      // healthCheck() already calls /_health, /_stats, and /{collection}/storage
      // which provide totalDocuments, newestDoc, and oldestDoc in O(1).
      const [healthCheck, eventsToday, eventTypeCounts] = await Promise.all([
        wrap(backend.healthCheck()),
        wrap(backend.getEventCountToday()),
        wrap(backend.getEventTypeCounts()),
      ]);

      const timedOut = [healthCheck, eventsToday, eventTypeCounts].some(r => r === TIMEOUT);
      const hc = healthCheck !== TIMEOUT ? healthCheck : null;
      const writePressure = hc?.writePressure || (timedOut ? 'high' : null);
      // Only show rebuilding during grace period (post-reset) or if health check
      // itself timed out (truly overloaded). WardSONDB's write_pressure can remain
      // "high" after compaction even with zero writes — don't treat that as rebuilding.
      const isRebuilding = !!(graceStatus || (!hc && timedOut));

      // Derive eventsTotal and lastEventAt from healthCheck data (O(1) lookups)
      const eventsTotal = hc?.details?.eventsStorage?.docCount ?? null;
      const lastEventAt = hc?.details?.eventsStorage?.newestDoc ?? null;

      return res.json({
        status: 'ok',
        backend: backendName,
        uptime: Math.floor((Date.now() - startTime) / 1000),
        eventsTotal,
        eventsToday: eventsToday !== TIMEOUT ? eventsToday : null,
        dbSizeMB: null,
        totalDocuments: hc?.details?.totalDocuments || null,
        lastEventAt,
        eventTypeCounts: eventTypeCounts !== TIMEOUT ? eventTypeCounts : {},
        enrichment: {
          geoip: isGeoIpAvailable(),
          abuseipdb: isAbuseIpDbConfigured(),
          queueSize: getQueueSize(),
        },
        backendHealth: hc?.details || null,
        ...(isRebuilding ? { rebuilding: true, writePressure } : {}),
      });
    }

    // SQLite path — original logic (all queries are fast/synchronous)
    const [eventsTotal, eventsToday, lastEventAt, eventTypeCounts, healthCheck] = await Promise.all([
      backend.getEventCount(),
      backend.getEventCountToday(),
      backend.getLastEventTime(),
      backend.getEventTypeCounts(),
      backend.healthCheck(),
    ]);

    const writePressure = healthCheck.writePressure || null;
    const isRebuilding = !!(graceStatus || writePressure === 'high');

    res.json({
      status: 'ok',
      backend: backendName,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      eventsTotal,
      eventsToday,
      dbSizeMB,
      totalDocuments: healthCheck.details?.totalDocuments || null,
      lastEventAt,
      eventTypeCounts,
      enrichment: {
        geoip: isGeoIpAvailable(),
        abuseipdb: isAbuseIpDbConfigured(),
        queueSize: getQueueSize(),
      },
      backendHealth: healthCheck.details,
      ...(isRebuilding ? { rebuilding: true, writePressure } : {}),
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

module.exports = router;
