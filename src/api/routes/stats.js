const express = require('express');
const storage = require('../../db/storage');

const router = express.Router();

function periodToInterval(period) {
  const map = {
    '1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours',
    '7d': '-7 days', '30d': '-30 days',
  };
  return map[period] || '-24 hours';
}

function bucketToFormat(bucket) {
  const map = {
    '5m': '%Y-%m-%dT%H:%M:00Z',
    '15m': '%Y-%m-%dT%H:%M:00Z',
    '1h': '%Y-%m-%dT%H:00:00Z',
    '1d': '%Y-%m-%dT00:00:00Z',
  };
  return map[bucket] || '%Y-%m-%dT%H:00:00Z';
}

function getSince(period) {
  const ms = {
    '1h': 3600000, '6h': 21600000, '24h': 86400000,
    '7d': 604800000, '30d': 2592000000,
  };
  const offset = ms[period] || 86400000;
  return new Date(Date.now() - offset).toISOString();
}

router.get('/overview', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const backend = storage.getBackend();
    const result = await backend.getOverviewStats(since);
    res.json(result);
  } catch (err) {
    console.error('[stats/overview] Error:', err.message || err);
    res.status(500).json({ error: 'Failed to get overview stats', detail: err.message });
  }
});

router.get('/timeline', async (req, res) => {
  try {
    const period = req.query.period || '24h';
    const bucket = req.query.bucket || '1h';
    const since = getSince(period);
    const backend = storage.getBackend();
    const rows = await backend.getTimeline(since, bucketToFormat(bucket), req.query.event_type, bucket);
    res.json(rows);
  } catch (err) {
    console.error('[stats/timeline] Error:', err.message || err);
    res.status(500).json({ error: 'Failed to get timeline', detail: err.message });
  }
});

router.get('/top-talkers', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const direction = req.query.direction || 'src';
    const excludePrivate = req.query.exclude_private === '1';
    const backend = storage.getBackend();
    const rows = await backend.getTopTalkers(since, direction, limit, excludePrivate);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top talkers' });
  }
});

router.get('/top-blocked', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const direction = req.query.direction || 'src';
    const excludePrivate = req.query.exclude_private === '1';
    const backend = storage.getBackend();
    const rows = await backend.getTopBlocked(since, direction, limit, excludePrivate);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top blocked' });
  }
});

router.get('/top-ports', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const backend = storage.getBackend();
    const rows = await backend.getTopPorts(since, limit);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top ports' });
  }
});

router.get('/top-clients', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const backend = storage.getBackend();
    const rows = await backend.getTopClients(since, limit);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top clients' });
  }
});

router.get('/top-threats', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const backend = storage.getBackend();
    const rows = await backend.getTopThreats(since, limit);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top threats' });
  }
});

router.get('/threat-intel', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const backend = storage.getBackend();
    const result = await backend.getThreatIntel(since, limit);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get threat intel' });
  }
});

router.get('/geo-events', async (req, res) => {
  try {
    const since = getSince(req.query.period || '24h');
    const limit = Math.min(parseInt(req.query.limit || '500', 10), 1000);
    const backend = storage.getBackend();
    const rows = await backend.getGeoEvents(since, limit);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get geo events' });
  }
});

router.get('/recent-geo-events', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const backend = storage.getBackend();
    const rows = await backend.getRecentGeoEvents(limit);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get recent geo events' });
  }
});

module.exports = router;
