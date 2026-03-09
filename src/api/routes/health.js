const express = require('express');
const fs = require('fs');
const config = require('../../config');
const storage = require('../../db/storage');
const { isGeoIpAvailable } = require('../../enrichment/geoip');
const { isAbuseIpDbConfigured } = require('../../enrichment/abuseipdb');
const { getQueueSize } = require('../../enrichment/enrichment-queue');

const router = express.Router();
const startTime = Date.now();

router.get('/', async (req, res) => {
  try {
    const backend = storage.getBackend();
    const backendName = storage.getBackendName();

    let dbSizeMB = 0;
    if (backendName === 'SQLite') {
      try {
        const stat = fs.statSync(config.db.path);
        dbSizeMB = Math.round(stat.size / 1024 / 1024 * 100) / 100;
      } catch {}
    }

    const [eventsTotal, eventsToday, lastEventAt, eventTypeCounts, healthCheck] = await Promise.all([
      backend.getEventCount(),
      backend.getEventCountToday(),
      backend.getLastEventTime(),
      backend.getEventTypeCounts(),
      backend.healthCheck(),
    ]);

    res.json({
      status: 'ok',
      backend: backendName,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      eventsTotal,
      eventsToday,
      dbSizeMB,
      lastEventAt,
      eventTypeCounts,
      enrichment: {
        geoip: isGeoIpAvailable(),
        abuseipdb: isAbuseIpDbConfigured(),
        queueSize: getQueueSize(),
      },
      backendHealth: healthCheck.details,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

module.exports = router;
