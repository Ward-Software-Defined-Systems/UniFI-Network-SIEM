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

const HEALTH_TIMEOUT_MS = 5000; // If backend doesn't respond in 5s, assume overloaded

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

    const [eventsTotal, eventsToday, lastEventAt, eventTypeCounts, healthCheck] = await Promise.all([
      wrap(backend.getEventCount()),
      wrap(backend.getEventCountToday()),
      wrap(backend.getLastEventTime()),
      wrap(backend.getEventTypeCounts()),
      wrap(backend.healthCheck()),
    ]);

    // If any call timed out (WardSONDB only), the backend is overloaded — show rebuilding state
    const timedOut = useTimeout && [eventsTotal, eventsToday, lastEventAt, eventTypeCounts, healthCheck].some(r => r === TIMEOUT);

    if (timedOut) {
      return res.json({
        status: 'ok',
        backend: backendName,
        uptime: Math.floor((Date.now() - startTime) / 1000),
        eventsTotal: eventsTotal !== TIMEOUT ? eventsTotal : null,
        eventsToday: eventsToday !== TIMEOUT ? eventsToday : null,
        dbSizeMB: null,
        totalDocuments: null,
        lastEventAt: lastEventAt !== TIMEOUT ? lastEventAt : null,
        eventTypeCounts: eventTypeCounts !== TIMEOUT ? eventTypeCounts : {},
        enrichment: {
          geoip: isGeoIpAvailable(),
          abuseipdb: isAbuseIpDbConfigured(),
          queueSize: getQueueSize(),
        },
        backendHealth: null,
        rebuilding: true,
        writePressure: 'high',
      });
    }

    // For WardSONDB, show document count and time range instead of file size
    if (backendName === 'WardSONDB' && healthCheck.details?.eventsStorage) {
      const es = healthCheck.details.eventsStorage;
      dbSizeMB = null; // No file-based size for WardSONDB
    }

    const writePressure = healthCheck.writePressure || null;

    // Rebuilding state: either in grace period after reset, or WardSONDB reports high write pressure
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
