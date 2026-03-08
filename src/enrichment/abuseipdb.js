const config = require('../config');
const logger = require('../utils/logger');

let rateLimitedUntil = 0;

function isAbuseIpDbConfigured() {
  return !!config.enrichment.abuseIpDbKey;
}

function isAbuseIpDbAvailable() {
  if (!config.enrichment.abuseIpDbKey) return false;
  if (rateLimitedUntil > Date.now()) return false;
  return true;
}

async function checkIp(ip) {
  if (!config.enrichment.abuseIpDbKey) return null;

  // Skip if still in rate limit backoff
  if (rateLimitedUntil > Date.now()) return null;

  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const res = await fetch(url, {
      headers: {
        'Key': config.enrichment.abuseIpDbKey,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      if (res.status === 429) {
        // Back off for 1 hour
        rateLimitedUntil = Date.now() + 60 * 60 * 1000;
        const resumeTime = new Date(rateLimitedUntil).toLocaleTimeString();
        logger.warn(`AbuseIPDB rate limit reached. Backing off until ${resumeTime} (1 hour)`);
        return null;
      }
      logger.warn({ status: res.status }, 'AbuseIPDB API error');
      return null;
    }

    const data = await res.json();
    const d = data.data;
    if (!d) return null;

    return {
      abuseScore: d.abuseConfidenceScore ?? null,
      totalReports: d.totalReports ?? 0,
      countryCode: d.countryCode || null,
      isp: d.isp || null,
      domain: d.domain || null,
    };
  } catch (err) {
    logger.warn({ err, ip }, 'AbuseIPDB lookup failed');
    return null;
  }
}

module.exports = { checkIp, isAbuseIpDbConfigured, isAbuseIpDbAvailable };
