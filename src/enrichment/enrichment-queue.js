const { isPrivateIp } = require('../utils/ip-utils');
const { lookupGeoIp, isGeoIpAvailable } = require('./geoip');
const { checkIp, isAbuseIpDbAvailable } = require('./abuseipdb');
const { reverseLookup } = require('./rdns');
const { getCachedEnrichment, setCachedEnrichment, markPrivate } = require('../db/cache');
const { getDb } = require('../db/database');
const config = require('../config');
const logger = require('../utils/logger');

const ipQueue = new Set();
let processing = false;
let activeCount = 0;

function enqueueIp(ip) {
  if (!ip || ipQueue.has(ip)) return;
  if (isPrivateIp(ip)) return;

  // Check cache first — if fresh, apply cached data to any new un-enriched events
  const cached = getCachedEnrichment(ip);
  if (cached) {
    // Apply cached enrichment to any events that don't have it yet
    if (cached.geo_country || cached.abuse_score != null) {
      updateEventsWithEnrichment(ip, {
        geo_country: cached.geo_country,
        geo_city: cached.geo_city,
        geo_lat: cached.geo_lat,
        geo_lon: cached.geo_lon,
        abuse_score: cached.abuse_score,
        hostname: cached.hostname,
      });
    }
    // Re-queue if missing abuse score and AbuseIPDB is available
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
  // Only enrich external IPs from firewall/threat events
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
      markPrivate(ip);
      return;
    }

    // Start with existing cached data (if any) to avoid overwriting
    const existing = getCachedEnrichment(ip);
    const enrichment = {
      geo_country: existing?.geo_country || null,
      geo_city: existing?.geo_city || null,
      geo_lat: existing?.geo_lat || null,
      geo_lon: existing?.geo_lon || null,
      abuse_score: existing?.abuse_score ?? null,
      hostname: existing?.hostname || null,
    };

    // GeoIP lookup (sync, fast) — only if not already cached
    if (!enrichment.geo_country && isGeoIpAvailable()) {
      const geo = lookupGeoIp(ip);
      if (geo) {
        enrichment.geo_country = geo.country;
        enrichment.geo_city = geo.city;
        enrichment.geo_lat = geo.lat;
        enrichment.geo_lon = geo.lon;
      }
    }

    // AbuseIPDB lookup (async, rate-limited)
    if (isAbuseIpDbAvailable()) {
      const abuse = await checkIp(ip);
      if (abuse) {
        enrichment.abuse_score = abuse.abuseScore;
        // Use country from AbuseIPDB if GeoIP didn't have it
        if (!enrichment.geo_country && abuse.countryCode) {
          enrichment.geo_country = abuse.countryCode;
        }
      }
    }

    // rDNS lookup (async, optional)
    if (config.enrichment.rdnsEnabled) {
      enrichment.hostname = await reverseLookup(ip);
    }

    // Cache the result
    setCachedEnrichment(ip, enrichment);

    // Update existing events with this IP
    updateEventsWithEnrichment(ip, enrichment);

    logger.debug({ ip, country: enrichment.geo_country, abuse: enrichment.abuse_score }, 'Enriched IP');
  } catch (err) {
    logger.warn({ err, ip }, 'Failed to enrich IP');
  }
}

function updateEventsWithEnrichment(ip, data) {
  const db = getDb();

  // Update events where this IP is the source
  db.prepare(`
    UPDATE events SET
      src_geo_country = ?, src_geo_city = ?, src_geo_lat = ?, src_geo_lon = ?,
      src_abuse_score = ?, src_hostname = ?
    WHERE src_ip = ? AND src_geo_country IS NULL
  `).run(
    data.geo_country, data.geo_city, data.geo_lat, data.geo_lon,
    data.abuse_score, data.hostname,
    ip,
  );

  // Update events where this IP is the destination
  db.prepare(`
    UPDATE events SET
      dst_geo_country = ?, dst_geo_city = ?, dst_geo_lat = ?, dst_geo_lon = ?,
      dst_abuse_score = ?, dst_hostname = ?
    WHERE dst_ip = ? AND dst_geo_country IS NULL
  `).run(
    data.geo_country, data.geo_city, data.geo_lat, data.geo_lon,
    data.abuse_score, data.hostname,
    ip,
  );
}

function getQueueSize() {
  return ipQueue.size;
}

// Backfill geo data for events that have IPs in the cache but NULL geo fields
function backfillFromCache() {
  try {
    const db = getDb();
    const cached = db.prepare(
      'SELECT ip, geo_country, geo_city, geo_lat, geo_lon, abuse_score, hostname FROM ip_enrichment_cache WHERE is_private = 0 AND (geo_country IS NOT NULL OR abuse_score IS NOT NULL)'
    ).all();

    if (cached.length === 0) return;

    const updateSrc = db.prepare(`
      UPDATE events SET
        src_geo_country = ?, src_geo_city = ?, src_geo_lat = ?, src_geo_lon = ?,
        src_abuse_score = ?, src_hostname = ?
      WHERE src_ip = ? AND src_geo_country IS NULL
    `);
    const updateDst = db.prepare(`
      UPDATE events SET
        dst_geo_country = ?, dst_geo_city = ?, dst_geo_lat = ?, dst_geo_lon = ?,
        dst_abuse_score = ?, dst_hostname = ?
      WHERE dst_ip = ? AND dst_geo_country IS NULL
    `);

    const txn = db.transaction(() => {
      for (const c of cached) {
        updateSrc.run(c.geo_country, c.geo_city, c.geo_lat, c.geo_lon, c.abuse_score, c.hostname, c.ip);
        updateDst.run(c.geo_country, c.geo_city, c.geo_lat, c.geo_lon, c.abuse_score, c.hostname, c.ip);
      }
    });
    txn();
    logger.info({ ips: cached.length }, 'Backfilled enrichment data from cache to events');
  } catch (err) {
    logger.warn({ err }, 'Failed to backfill enrichment from cache');
  }
}

module.exports = { enqueueEvent, enqueueIp, getQueueSize, backfillFromCache };
