const express = require('express');
const { getDb } = require('../../db/database');
const { getEventTypeCounts } = require('../../db/events');

const router = express.Router();

// SQL condition to exclude RFC1918, CGNAT, loopback, link-local, multicast
function privateIpFilter(col) {
  return `${col} NOT LIKE '10.%'
    AND ${col} NOT LIKE '192.168.%'
    AND ${col} NOT LIKE '172.16.%' AND ${col} NOT LIKE '172.17.%' AND ${col} NOT LIKE '172.18.%' AND ${col} NOT LIKE '172.19.%'
    AND ${col} NOT LIKE '172.2_.%' AND ${col} NOT LIKE '172.30.%' AND ${col} NOT LIKE '172.31.%'
    AND ${col} NOT LIKE '100.64.%' AND ${col} NOT LIKE '100.65.%' AND ${col} NOT LIKE '100.66.%' AND ${col} NOT LIKE '100.67.%'
    AND ${col} NOT LIKE '100.68.%' AND ${col} NOT LIKE '100.69.%' AND ${col} NOT LIKE '100.7_.%'
    AND ${col} NOT LIKE '100.8_.%' AND ${col} NOT LIKE '100.9_.%' AND ${col} NOT LIKE '100.1__.%'
    AND ${col} NOT LIKE '100.12_.%'
    AND ${col} NOT LIKE '127.%'
    AND ${col} NOT LIKE '169.254.%'`;
}

function periodToInterval(period) {
  const map = {
    '1h': '-1 hour', '6h': '-6 hours', '24h': '-24 hours',
    '7d': '-7 days', '30d': '-30 days',
  };
  return map[period] || '-24 hours';
}

function bucketToFormat(bucket) {
  const map = {
    '5m': '%Y-%m-%dT%H:%M:00Z',   // truncate to nearest 5 min handled differently
    '15m': '%Y-%m-%dT%H:%M:00Z',
    '1h': '%Y-%m-%dT%H:00:00Z',
    '1d': '%Y-%m-%dT00:00:00Z',
  };
  return map[bucket] || '%Y-%m-%dT%H:00:00Z';
}

router.get('/overview', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const interval = periodToInterval(period);
    const db = getDb();

    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;
    const total = db.prepare('SELECT COUNT(*) as c FROM events WHERE received_at >= ?').get(since).c;
    const byType = getEventTypeCounts(since);

    const firewall = {
      allowed: db.prepare("SELECT COUNT(*) as c FROM events WHERE event_type='firewall' AND action='allow' AND received_at >= ?").get(since).c,
      blocked: db.prepare("SELECT COUNT(*) as c FROM events WHERE event_type='firewall' AND action='block' AND received_at >= ?").get(since).c,
      threats: db.prepare("SELECT COUNT(*) as c FROM events WHERE event_type='threat' AND received_at >= ?").get(since).c,
    };

    res.json({ total, byType, firewall });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get overview stats' });
  }
});

router.get('/timeline', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const bucket = req.query.bucket || '1h';
    const interval = periodToInterval(period);
    const fmt = bucketToFormat(bucket);
    const db = getDb();

    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;

    let sql;
    if (req.query.event_type === 'firewall') {
      sql = `SELECT strftime('${fmt}', received_at) as ts,
              SUM(CASE WHEN action='allow' THEN 1 ELSE 0 END) as allowed,
              SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked
             FROM events WHERE event_type='firewall' AND received_at >= ?
             GROUP BY ts ORDER BY ts`;
    } else {
      sql = `SELECT strftime('${fmt}', received_at) as ts,
              SUM(CASE WHEN event_type='firewall' THEN 1 ELSE 0 END) as firewall,
              SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threat,
              SUM(CASE WHEN event_type='dhcp' THEN 1 ELSE 0 END) as dhcp,
              SUM(CASE WHEN event_type='dns_filter' THEN 1 ELSE 0 END) as dns_filter,
              SUM(CASE WHEN event_type='wifi' THEN 1 ELSE 0 END) as wifi,
              SUM(CASE WHEN event_type='admin' THEN 1 ELSE 0 END) as admin,
              SUM(CASE WHEN event_type='system' THEN 1 ELSE 0 END) as system,
              COUNT(*) as total
             FROM events WHERE received_at >= ?
             GROUP BY ts ORDER BY ts`;
    }

    const rows = db.prepare(sql).all(since);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

router.get('/top-talkers', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const direction = req.query.direction || 'src';
    const excludePriv = req.query.exclude_private === '1';
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;
    const col = direction === 'dst' ? 'dst_ip' : 'src_ip';
    const geoCol = direction === 'dst' ? 'dst_geo_country' : 'src_geo_country';
    const hostCol = direction === 'dst' ? 'dst_hostname' : 'src_hostname';
    const privFilter = excludePriv ? `AND ${privateIpFilter(col)}` : '';

    const rows = db.prepare(`
      SELECT ${col} as ip, COUNT(*) as count, MAX(received_at) as lastSeen,
             ${geoCol} as country, ${hostCol} as hostname
      FROM events WHERE ${col} IS NOT NULL AND received_at >= ? ${privFilter}
      GROUP BY ${col} ORDER BY count DESC LIMIT ?
    `).all(since, limit);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top talkers' });
  }
});

router.get('/top-blocked', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const direction = req.query.direction || 'src';
    const excludePriv = req.query.exclude_private === '1';
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;
    const col = direction === 'dst' ? 'dst_ip' : 'src_ip';
    const geoCol = direction === 'dst' ? 'dst_geo_country' : 'src_geo_country';
    const abuseCol = direction === 'dst' ? 'dst_abuse_score' : 'src_abuse_score';
    const hostCol = direction === 'dst' ? 'dst_hostname' : 'src_hostname';
    const privFilter = excludePriv ? `AND ${privateIpFilter(col)}` : '';

    const rows = db.prepare(`
      SELECT ${col} as ip, COUNT(*) as count, MAX(received_at) as lastSeen,
             ${geoCol} as country, ${abuseCol} as abuseScore, ${hostCol} as hostname
      FROM events WHERE action='block' AND ${col} IS NOT NULL AND received_at >= ? ${privFilter}
      GROUP BY ${col} ORDER BY count DESC LIMIT ?
    `).all(since, limit);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top blocked' });
  }
});

router.get('/top-ports', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;

    const rows = db.prepare(`
      SELECT dst_port as port, protocol, COUNT(*) as count
      FROM events WHERE dst_port IS NOT NULL AND received_at >= ?
      GROUP BY dst_port, protocol ORDER BY count DESC LIMIT ?
    `).all(since, limit);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top ports' });
  }
});

router.get('/top-clients', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;

    const rows = db.prepare(`
      SELECT
        COALESCE(client_mac, wifi_client_mac, dhcp_mac) as mac,
        MAX(client_alias) as alias,
        MAX(COALESCE(client_ip, dhcp_ip, src_ip)) as ip,
        COUNT(*) as eventCount,
        SUM(CASE WHEN event_type='wifi' THEN 1 ELSE 0 END) as wifiEvents,
        SUM(CASE WHEN event_type='dhcp' THEN 1 ELSE 0 END) as dhcpEvents,
        SUM(CASE WHEN event_type='firewall' THEN 1 ELSE 0 END) as firewallEvents
      FROM events
      WHERE COALESCE(client_mac, wifi_client_mac, dhcp_mac) IS NOT NULL AND received_at >= ?
      GROUP BY mac ORDER BY eventCount DESC LIMIT ?
    `).all(since, limit);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top clients' });
  }
});

router.get('/top-threats', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;

    const rows = db.prepare(`
      SELECT ids_signature as signature, ids_classification as classification,
             COUNT(*) as count, MAX(received_at) as lastSeen
      FROM events WHERE event_type='threat' AND ids_signature IS NOT NULL AND received_at >= ?
      GROUP BY ids_signature ORDER BY count DESC LIMIT ?
    `).all(since, limit);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get top threats' });
  }
});

router.get('/threat-intel', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;

    // Get enriched IPs with event counts in this period
    const rows = db.prepare(`
      SELECT
        ip, country, city, lat, lon, abuse_score, hostname,
        SUM(count) as event_count,
        SUM(blocked) as blocked_count,
        SUM(threats) as threat_count,
        MAX(lastSeen) as lastSeen
      FROM (
        SELECT src_ip as ip, src_geo_country as country, src_geo_city as city,
               src_geo_lat as lat, src_geo_lon as lon, src_abuse_score as abuse_score,
               src_hostname as hostname,
               COUNT(*) as count,
               SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
               SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threats,
               MAX(received_at) as lastSeen
        FROM events
        WHERE src_ip IS NOT NULL AND (src_geo_country IS NOT NULL OR src_abuse_score IS NOT NULL) AND received_at >= ?
        GROUP BY src_ip
        UNION ALL
        SELECT dst_ip, dst_geo_country, dst_geo_city,
               dst_geo_lat, dst_geo_lon, dst_abuse_score,
               dst_hostname,
               COUNT(*),
               SUM(CASE WHEN action='block' THEN 1 ELSE 0 END),
               SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END),
               MAX(received_at)
        FROM events
        WHERE dst_ip IS NOT NULL AND (dst_geo_country IS NOT NULL OR dst_abuse_score IS NOT NULL) AND received_at >= ?
        GROUP BY dst_ip
      )
      GROUP BY ip
      ORDER BY event_count DESC, abuse_score DESC
      LIMIT ?
    `).all(since, since, limit);

    // Summary stats from cache
    const totalEnriched = db.prepare(
      "SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE is_private = 0"
    ).get().c;

    const withAbuseScore = db.prepare(
      "SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE abuse_score > 0 AND is_private = 0"
    ).get().c;

    const highThreat = db.prepare(
      "SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE abuse_score >= 50 AND is_private = 0"
    ).get().c;

    const countries = db.prepare(
      "SELECT COUNT(DISTINCT geo_country) as c FROM ip_enrichment_cache WHERE geo_country IS NOT NULL AND is_private = 0"
    ).get().c;

    // Period-filtered summary — query the full dataset, not the limited rows
    const periodStats = db.prepare(`
      SELECT
        COUNT(DISTINCT ip) as enriched,
        COUNT(DISTINCT CASE WHEN abuse_score > 0 THEN ip END) as flagged,
        COUNT(DISTINCT CASE WHEN abuse_score >= 50 THEN ip END) as highThreat,
        COUNT(DISTINCT country) as countries
      FROM (
        SELECT src_ip as ip, src_abuse_score as abuse_score, src_geo_country as country
        FROM events
        WHERE src_ip IS NOT NULL AND (src_geo_country IS NOT NULL OR src_abuse_score IS NOT NULL) AND received_at >= ?
        UNION
        SELECT dst_ip, dst_abuse_score, dst_geo_country
        FROM events
        WHERE dst_ip IS NOT NULL AND (dst_geo_country IS NOT NULL OR dst_abuse_score IS NOT NULL) AND received_at >= ?
      )
    `).get(since, since);
    const periodEnriched = periodStats.enriched;
    const periodFlagged = periodStats.flagged;
    const periodHighThreat = periodStats.highThreat;
    const periodCountries = periodStats.countries;

    res.json({
      summary: { totalEnriched, withAbuseScore, highThreat, countries },
      periodSummary: { enriched: periodEnriched, flagged: periodFlagged, highThreat: periodHighThreat, countries: periodCountries },
      ips: rows,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get threat intel' });
  }
});

router.get('/geo-events', (req, res) => {
  try {
    const period = req.query.period || '24h';
    const limit = Math.min(parseInt(req.query.limit || '500', 10), 1000);
    const interval = periodToInterval(period);
    const db = getDb();
    const since = db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;
    const half = Math.ceil(limit / 2);

    // Query src and dst separately with individual limits to ensure
    // both blocked sources and normal destinations are represented
    const srcRows = db.prepare(`
      SELECT
        src_ip as ip, src_geo_country as country, src_geo_city as city,
        src_geo_lat as lat, src_geo_lon as lon, src_abuse_score as abuseScore,
        COUNT(*) as count,
        SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threats,
        MAX(received_at) as lastSeen, 'src' as direction
      FROM events
      WHERE src_geo_lat IS NOT NULL AND src_geo_lon IS NOT NULL AND received_at >= ?
      GROUP BY src_ip ORDER BY count DESC LIMIT ?
    `).all(since, half);

    const dstRows = db.prepare(`
      SELECT
        dst_ip as ip, dst_geo_country as country, dst_geo_city as city,
        dst_geo_lat as lat, dst_geo_lon as lon, dst_abuse_score as abuseScore,
        COUNT(*) as count,
        SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threats,
        MAX(received_at) as lastSeen, 'dst' as direction
      FROM events
      WHERE dst_geo_lat IS NOT NULL AND dst_geo_lon IS NOT NULL AND received_at >= ?
      GROUP BY dst_ip ORDER BY count DESC LIMIT ?
    `).all(since, half);

    res.json([...srcRows, ...dstRows]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get geo events' });
  }
});

router.get('/recent-geo-events', (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const db = getDb();

    // Get recent individual events with geo data for live animation
    const rows = db.prepare(`
      SELECT id, event_type, action, received_at,
        src_ip, src_geo_lat, src_geo_lon, src_geo_country, src_geo_city, src_abuse_score,
        dst_ip, dst_geo_lat, dst_geo_lon, dst_geo_country, dst_geo_city, dst_abuse_score,
        message, dst_port, protocol
      FROM events
      WHERE (src_geo_lat IS NOT NULL OR dst_geo_lat IS NOT NULL)
      ORDER BY id DESC
      LIMIT ?
    `).all(limit);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get recent geo events' });
  }
});

module.exports = router;
