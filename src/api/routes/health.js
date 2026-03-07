const express = require('express');
const fs = require('fs');
const config = require('../../config');
const { getEventCount, getEventCountToday, getLastEventTime, getEventTypeCounts } = require('../../db/events');
const { isGeoIpAvailable } = require('../../enrichment/geoip');
const { isAbuseIpDbConfigured } = require('../../enrichment/abuseipdb');
const { getQueueSize } = require('../../enrichment/enrichment-queue');

const router = express.Router();
const startTime = Date.now();

router.get('/', (req, res) => {
  try {
    let dbSizeMB = 0;
    try {
      const stat = fs.statSync(config.db.path);
      dbSizeMB = Math.round(stat.size / 1024 / 1024 * 100) / 100;
    } catch {}

    res.json({
      status: 'ok',
      uptime: Math.floor((Date.now() - startTime) / 1000),
      eventsTotal: getEventCount(),
      eventsToday: getEventCountToday(),
      dbSizeMB,
      lastEventAt: getLastEventTime(),
      eventTypeCounts: getEventTypeCounts(),
      enrichment: {
        geoip: isGeoIpAvailable(),
        abuseipdb: isAbuseIpDbConfigured(),
        queueSize: getQueueSize(),
      },
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

module.exports = router;
