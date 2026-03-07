const { getDb } = require('./database');
const config = require('../config');

function getCachedEnrichment(ip) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM ip_enrichment_cache WHERE ip = ?').get(ip);
  if (!row) return null;

  // Check if cache is stale
  const updatedAt = new Date(row.updated_at).getTime();
  const maxAge = config.enrichment.abuseIpDbCacheHours * 60 * 60 * 1000;
  if (Date.now() - updatedAt > maxAge) return null;

  return row;
}

function setCachedEnrichment(ip, data) {
  const db = getDb();
  db.prepare(`
    INSERT OR REPLACE INTO ip_enrichment_cache
    (ip, geo_country, geo_city, geo_lat, geo_lon, abuse_score, hostname, is_private, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
  `).run(
    ip,
    data.geo_country || null,
    data.geo_city || null,
    data.geo_lat || null,
    data.geo_lon || null,
    data.abuse_score ?? null,
    data.hostname || null,
    data.is_private ? 1 : 0,
  );
}

function markPrivate(ip) {
  setCachedEnrichment(ip, { is_private: true });
}

module.exports = { getCachedEnrichment, setCachedEnrichment, markPrivate };
