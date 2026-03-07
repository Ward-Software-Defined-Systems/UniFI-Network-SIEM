require('dotenv').config();

const config = {
  syslog: {
    port: parseInt(process.env.SYSLOG_PORT || '5514', 10),
  },
  http: {
    port: parseInt(process.env.HTTP_PORT || '3000', 10),
  },
  db: {
    path: process.env.DB_PATH || './data/events.db',
    retentionDays: parseInt(process.env.RETENTION_DAYS || '60', 10),
  },
  enrichment: {
    geoipDbPath: process.env.GEOIP_DB_PATH || './data/GeoLite2-City.mmdb',
    abuseIpDbKey: process.env.ABUSEIPDB_API_KEY || '',
    abuseIpDbCacheHours: parseInt(process.env.ABUSEIPDB_CACHE_HOURS || '24', 10),
    rdnsEnabled: process.env.RDNS_ENABLED === 'true',
    rdnsTimeoutMs: parseInt(process.env.RDNS_TIMEOUT_MS || '2000', 10),
    concurrency: parseInt(process.env.ENRICHMENT_CONCURRENCY || '5', 10),
  },
  performance: {
    insertBatchSize: parseInt(process.env.INSERT_BATCH_SIZE || '50', 10),
    insertBatchIntervalMs: parseInt(process.env.INSERT_BATCH_INTERVAL_MS || '500', 10),
    wsBroadcastThrottleMs: parseInt(process.env.WS_BROADCAST_THROTTLE_MS || '100', 10),
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    logRawMessages: process.env.LOG_RAW_MESSAGES === 'true',
  },
};

module.exports = config;
