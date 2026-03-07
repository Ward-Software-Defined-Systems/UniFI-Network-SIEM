const fs = require('fs');
const path = require('path');
const config = require('../config');
const logger = require('../utils/logger');

let reader = null;
let available = false;

async function initGeoIp() {
  const dbPath = path.resolve(config.enrichment.geoipDbPath);
  if (!fs.existsSync(dbPath)) {
    logger.warn({ path: dbPath }, 'GeoIP database not found — GeoIP enrichment disabled. Download GeoLite2-City.mmdb from MaxMind.');
    return;
  }

  try {
    const maxmind = require('maxmind');
    reader = await maxmind.open(dbPath);
    available = true;
    logger.info('GeoIP database loaded');
  } catch (err) {
    logger.warn({ err }, 'Failed to load GeoIP database — enrichment disabled');
  }
}

function lookupGeoIp(ip) {
  if (!available || !reader) return null;

  try {
    const result = reader.get(ip);
    if (!result) return null;

    return {
      country: result.country?.iso_code || null,
      city: result.city?.names?.en || null,
      lat: result.location?.latitude || null,
      lon: result.location?.longitude || null,
    };
  } catch {
    return null;
  }
}

function isGeoIpAvailable() {
  return available;
}

module.exports = { initGeoIp, lookupGeoIp, isGeoIpAvailable };
