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

// Debounce write_pressure === 'high' — require two consecutive high readings
// (~20s at the 10s poll cadence) before we report rebuilding due to pressure.
// Clears instantly on any non-high reading. Eliminates single-poll flickers
// from WardSONDB's volatile write_pressure signal while preserving the signal
// for sustained heavy load. Module-level because the route is a singleton.
let _consecutiveHighPressure = 0;
const HIGH_PRESSURE_DEBOUNCE_POLLS = 2;

// Race a promise against a timeout — returns fallback on timeout or error
function withTimeout(promise, ms, fallback) {
  return Promise.race([
    Promise.resolve(promise).catch(() => fallback),
    new Promise(resolve => setTimeout(() => resolve(fallback), ms)),
  ]);
}

// Must be longer than the backend's own health timeout to avoid the wrapper timing out first
const HEALTH_TIMEOUT_MS = Math.max(config.wardsondb.healthTimeoutMs, 5000) + 3000;

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

    // Wrap backend calls with a timeout for networked backends (prevents hang when DB is overloaded)
    // SQLite is synchronous/fast — no timeout needed
    const isNetworkedBackend = backendName === 'WardSONDB' || backendName === 'OpenSearch';
    const TIMEOUT = '_TIMEOUT_';
    const wrap = (p) => isNetworkedBackend ? withTimeout(p, HEALTH_TIMEOUT_MS, TIMEOUT) : p;

    if (isNetworkedBackend) {
      // Sequential approach for networked backends: run healthCheck() FIRST, then
      // decide whether to query further. This prevents connection pile-ups when the
      // DB is empty, unreachable, or overloaded.
      const healthCheck = await wrap(backend.healthCheck());
      const hc = healthCheck !== TIMEOUT ? healthCheck : null;
      const docCount = hc?.details?.eventsStorage?.docCount ?? hc?.details?.totalDocuments ?? null;
      const isEmpty = docCount === 0;
      const healthTimedOut = healthCheck === TIMEOUT;

      const writePressure = hc?.writePressure || null;
      if (writePressure === 'high') _consecutiveHighPressure++;
      else _consecutiveHighPressure = 0;
      const pressureSustained = _consecutiveHighPressure >= HIGH_PRESSURE_DEBOUNCE_POLLS;
      // Only show rebuilding when WardSONDB reports sustained high write pressure
      // (two consecutive polls) or during the post-reset grace period. Query timeouts
      // alone should not trigger the banner — the dashboard can render with partial data.
      const isRebuilding = !isEmpty && !!(graceStatus || pressureSustained);

      // Derive eventsTotal and lastEventAt from healthCheck data (O(1) lookups)
      const eventsTotal = hc?.details?.eventsStorage?.docCount ?? null;
      const lastEventAt = hc?.details?.eventsStorage?.newestDoc ?? null;

      // Only fetch extra stats if DB is non-empty AND healthCheck succeeded.
      // On empty DB or timeout, skip to avoid cascading connection pile-ups.
      let eventsToday = isEmpty ? 0 : null;
      let eventTypeCounts = isEmpty ? {} : {};
      if (!isEmpty && !healthTimedOut) {
        const [todayResult, typeResult] = await Promise.all([
          wrap(backend.getEventCountToday()),
          wrap(backend.getEventTypeCounts()),
        ]);
        eventsToday = todayResult !== TIMEOUT ? todayResult : null;
        eventTypeCounts = typeResult !== TIMEOUT ? typeResult : {};
      }

      return res.json({
        status: 'ok',
        backend: backendName,
        uptime: Math.floor((Date.now() - startTime) / 1000),
        eventsTotal,
        eventsToday,
        dbSizeMB: null,
        totalDocuments: hc?.details?.totalDocuments || null,
        lastEventAt,
        eventTypeCounts,
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
