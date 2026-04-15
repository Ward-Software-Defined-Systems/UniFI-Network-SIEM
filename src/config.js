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
  wardsondb: {
    healthTimeoutMs: parseInt(process.env.WARDSONDB_HEALTH_TIMEOUT_MS || '5000', 10),
    // TCP connect timeout. Default 60s because a saturated WardSONDB server
    // under heavy flush/backfill load takes longer than undici's 10s default
    // to accept new connections, causing spurious `Connect Timeout Error`s.
    connectTimeoutMs: parseInt(process.env.WARDSONDB_CONNECT_TIMEOUT_MS || '60000', 10),
    // Client-side request timeout (body+headers). 0 = no timeout — let
    // WardSONDB's server-side --query-timeout flag govern duration.
    queryTimeoutMs: parseInt(process.env.WARDSONDB_QUERY_TIMEOUT_MS || '0', 10),
    // Concurrency for the rollup flush worker pool. Lower values reduce
    // pressure on WardSONDB's connection accept loop when ingest is heavy.
    flushConcurrency: parseInt(process.env.WARDSONDB_FLUSH_CONCURRENCY || '4', 10),
  },
  opensearch: {
    host: process.env.OPENSEARCH_HOST || 'localhost',
    port: parseInt(process.env.OPENSEARCH_PORT || '9200', 10),
    username: process.env.OPENSEARCH_USERNAME || '',
    password: process.env.OPENSEARCH_PASSWORD || '',
    useTls: process.env.OPENSEARCH_USE_TLS === 'true',
    verifyCerts: process.env.OPENSEARCH_VERIFY_CERTS !== 'false',
    indexPrefix: process.env.OPENSEARCH_INDEX_PREFIX || 'siem-',
    bulkSize: parseInt(process.env.OPENSEARCH_BULK_SIZE || '50', 10),
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    logRawMessages: process.env.LOG_RAW_MESSAGES === 'true',
  },
};

module.exports = config;
