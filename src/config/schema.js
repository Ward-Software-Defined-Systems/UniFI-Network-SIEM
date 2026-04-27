/**
 * Settings schema — single source of truth for every operator-facing setting.
 *
 * Each entry maps a dotted config key (e.g. `wardsondb.healthTimeoutMs`) onto
 * a default, an optional .env var for first-run seeding, a type for parsing
 * and validation, and metadata for the Settings UI.
 *
 * Resolution order at startup:
 *   1. defaults (from this schema)
 *   2. .env overlay (if `envVar` is set and present in process.env)
 *   3. DB overlay (after storage.initialize()) — sensitive values decrypted
 *      via src/utils/crypto.js
 *
 * Sensitivity:
 *   - 'public'  → visible in UI, stored plaintext
 *   - 'private' → masked in UI (last 4 chars), stored encrypted via
 *     `src/utils/crypto.js` (AES-256-GCM, format: `v1:iv:tag:ct`)
 */

const SCHEMA = [
  // ----------------------------------------------------------------- network
  { key: 'syslog.port', envVar: 'SYSLOG_PORT', type: 'number', default: 5514,
    category: 'network', description: 'UDP port for syslog listener',
    requiresRestart: true },
  { key: 'http.port', envVar: 'HTTP_PORT', type: 'number', default: 3000,
    category: 'network', description: 'HTTPS dashboard port',
    requiresRestart: true },
  { key: 'http.host', envVar: 'HTTP_HOST', type: 'string', default: '127.0.0.1',
    category: 'network',
    description: 'HTTPS bind address (127.0.0.1 = localhost only; set to your LAN IP or 0.0.0.0 for remote access)',
    requiresRestart: true },
  { key: 'network.syslogAllowedSources', envVar: 'SYSLOG_ALLOWED_SOURCES',
    type: 'string', default: '', category: 'network',
    description: 'Comma-separated list of source IPs or IPv4 CIDRs allowed to send syslog (e.g. "10.0.0.0/8,172.16.4.1"). Empty = allow all (default). Live-reloaded — no restart needed.' },

  // ----------------------------------------------------------------- storage
  { key: 'db.path', envVar: 'DB_PATH', type: 'string', default: './data/events.db',
    category: 'storage', description: 'SQLite database path',
    requiresRestart: true },
  { key: 'db.retentionDays', envVar: 'RETENTION_DAYS', type: 'number', default: 60,
    category: 'storage', description: 'Auto-delete events older than N days' },

  // -------------------------------------------------------------- enrichment
  { key: 'enrichment.geoipDbPath', envVar: 'GEOIP_DB_PATH', type: 'string',
    default: './data/GeoLite2-City.mmdb',
    category: 'enrichment', description: 'Path to MaxMind GeoLite2 database' },
  { key: 'enrichment.abuseIpDbKey', envVar: 'ABUSEIPDB_API_KEY', type: 'string',
    default: '', category: 'enrichment', sensitivity: 'private',
    legacyKey: 'abuseIpDbKey',
    description: 'AbuseIPDB API key (free tier: 1000 lookups/day)' },
  { key: 'enrichment.abuseIpDbCacheHours', envVar: 'ABUSEIPDB_CACHE_HOURS',
    type: 'number', default: 24, category: 'enrichment',
    description: 'Cache duration for abuse scores (hours)' },
  { key: 'enrichment.rdnsEnabled', envVar: 'RDNS_ENABLED', type: 'boolean',
    default: false, category: 'enrichment',
    legacyKey: 'rdnsEnabled',
    description: 'Enable reverse DNS lookups for external IPs' },
  { key: 'enrichment.rdnsTimeoutMs', envVar: 'RDNS_TIMEOUT_MS', type: 'number',
    default: 2000, category: 'enrichment',
    description: 'Reverse DNS lookup timeout (ms)' },
  { key: 'enrichment.concurrency', envVar: 'ENRICHMENT_CONCURRENCY', type: 'number',
    default: 5, category: 'enrichment',
    description: 'Max parallel enrichment lookups' },

  // ------------------------------------------------------------- performance
  { key: 'performance.insertBatchSize', envVar: 'INSERT_BATCH_SIZE',
    type: 'number', default: 50, category: 'performance',
    description: 'Events buffered before flushing to storage' },
  { key: 'performance.insertBatchIntervalMs', envVar: 'INSERT_BATCH_INTERVAL_MS',
    type: 'number', default: 500, category: 'performance',
    description: 'Max wait before flushing a partial batch (ms)' },
  { key: 'performance.wsBroadcastThrottleMs', envVar: 'WS_BROADCAST_THROTTLE_MS',
    type: 'number', default: 100, category: 'performance',
    description: 'WebSocket event broadcast throttle (ms)' },
  { key: 'performance.syslogRateLimitPerSourcePerSec', envVar: 'SYSLOG_RATE_LIMIT_PER_SOURCE',
    type: 'number', default: 0, category: 'performance',
    description: 'Max syslog events/sec from a single source IP. 0 = no limit (default). When exceeded, packets are dropped and a per-minute summary is logged at warn level.' },
  { key: 'performance.httpServerTimeoutMs', type: 'number', default: 300000,
    category: 'performance',
    description: 'HTTPS request timeout (ms). Kills slow requests after this. Long Threat Hunt SSE streams may exceed 5 min — bump if needed.' },
  { key: 'performance.httpKeepAliveTimeoutMs', type: 'number', default: 65000,
    category: 'performance',
    description: 'HTTPS keep-alive timeout (ms). Must be above common proxy/LB defaults (60s) to avoid race conditions.' },
  { key: 'performance.httpHeadersTimeoutMs', type: 'number', default: 70000,
    category: 'performance',
    description: 'HTTPS headers timeout (ms). Must exceed keepAliveTimeout per Node.js docs.' },

  // -------------------------------------------------------------- threathunt
  { key: 'threathunt.anthropicModel', type: 'string', default: 'claude-opus-4-6',
    category: 'threathunt',
    description: 'Anthropic model ID for Threat Hunt (e.g. claude-opus-4-6, claude-opus-4-7)' },
  { key: 'threathunt.anthropicMaxTokens', type: 'number', default: 128000,
    category: 'threathunt',
    description: 'Anthropic max output tokens. Higher = longer analyses but more cost / longer streams' },
  { key: 'threathunt.openaiModel', type: 'string', default: 'gpt-5.4',
    category: 'threathunt',
    description: 'OpenAI model ID for Threat Hunt' },
  { key: 'threathunt.openaiMaxTokens', type: 'number', default: 128000,
    category: 'threathunt',
    description: 'OpenAI max output tokens' },
  { key: 'threathunt.geminiModel', type: 'string', default: 'gemini-3.1-pro',
    category: 'threathunt',
    description: 'Google Gemini model ID for Threat Hunt' },
  { key: 'threathunt.geminiMaxTokens', type: 'number', default: 65536,
    category: 'threathunt',
    description: 'Gemini max output tokens (Gemini caps lower than the others)' },

  // ---------------------------------------------------------------- WardSONDB
  { key: 'wardsondb.healthTimeoutMs', envVar: 'WARDSONDB_HEALTH_TIMEOUT_MS',
    type: 'number', default: 5000, category: 'wardsondb',
    description: 'Health-check request timeout (ms)' },
  { key: 'wardsondb.connectTimeoutMs', envVar: 'WARDSONDB_CONNECT_TIMEOUT_MS',
    type: 'number', default: 60000, category: 'wardsondb',
    description: 'TCP connect timeout for the per-client undici Agent (ms). Default 60s because saturated WardSONDB instances under heavy flush load take longer than undici\'s 10s default to accept connections' },
  { key: 'wardsondb.queryTimeoutMs', envVar: 'WARDSONDB_QUERY_TIMEOUT_MS',
    type: 'number', default: 0, category: 'wardsondb',
    description: 'Client-side request timeout (ms). 0 = no client-side timeout (server-side --query-timeout governs)' },
  { key: 'wardsondb.flushConcurrency', envVar: 'WARDSONDB_FLUSH_CONCURRENCY',
    type: 'number', default: 4, category: 'wardsondb',
    description: 'Rollup flush worker-pool size' },

  // --------------------------------------------------------------- OpenSearch
  { key: 'opensearch.host', envVar: 'OPENSEARCH_HOST', type: 'string',
    default: 'localhost', category: 'opensearch',
    description: 'OpenSearch host' },
  { key: 'opensearch.port', envVar: 'OPENSEARCH_PORT', type: 'number',
    default: 9200, category: 'opensearch',
    description: 'OpenSearch port' },
  { key: 'opensearch.username', envVar: 'OPENSEARCH_USERNAME', type: 'string',
    default: '', category: 'opensearch',
    description: 'Basic auth username (empty = no auth)' },
  { key: 'opensearch.password', envVar: 'OPENSEARCH_PASSWORD', type: 'string',
    default: '', category: 'opensearch', sensitivity: 'private',
    description: 'Basic auth password' },
  { key: 'opensearch.useTls', envVar: 'OPENSEARCH_USE_TLS', type: 'boolean',
    default: false, category: 'opensearch',
    description: 'Enable HTTPS' },
  { key: 'opensearch.verifyCerts', envVar: 'OPENSEARCH_VERIFY_CERTS',
    type: 'boolean', default: true, category: 'opensearch',
    description: 'Verify TLS certificates (set false for self-signed)' },
  { key: 'opensearch.indexPrefix', envVar: 'OPENSEARCH_INDEX_PREFIX',
    type: 'string', default: 'siem-', category: 'opensearch',
    description: 'Prefix for OpenSearch index names' },
  { key: 'opensearch.bulkSize', envVar: 'OPENSEARCH_BULK_SIZE',
    type: 'number', default: 50, category: 'opensearch',
    description: 'Bulk insert batch size' },

  // ------------------------------------------------------------------- health
  { key: 'health.rebuildingDebouncePolls', envVar: 'HEALTH_REBUILDING_DEBOUNCE_POLLS',
    type: 'number', default: 2, category: 'health',
    description: 'Consecutive write_pressure: "high" polls required before the Rebuilding banner fires (10s cadence; 2 ≈ 20s)' },

  // ------------------------------------------------------------------ logging
  { key: 'logging.level', envVar: 'LOG_LEVEL', type: 'string', default: 'info',
    category: 'logging',
    description: 'Log level (trace/debug/info/warn/error)',
    requiresRestart: true },
  { key: 'logging.logRawMessages', envVar: 'LOG_RAW_MESSAGES', type: 'boolean',
    default: false, category: 'logging',
    description: 'Store raw syslog text in DB' },

  // --------------------------------------------------------------------- auth
  { key: 'auth.apiToken', envVar: 'SIEM_API_TOKEN', type: 'string',
    default: '', category: 'auth', sensitivity: 'private',
    description: 'API/WebSocket auth token. Auto-generated on first run if neither this DB row nor SIEM_API_TOKEN env var is set; the generated value is logged to stdout once' },

  // ---------------------------------------------------------------- security
  { key: 'security.masterKey', envVar: 'SIEM_MASTER_KEY', type: 'string',
    default: '', category: 'security', sensitivity: 'private',
    noEncrypt: true,
    description: 'Master encryption key for sensitive settings (AES-256-GCM). Stored plaintext (it IS the encryption key — can\'t encrypt itself). Auto-generated on first run if neither this DB row nor SIEM_MASTER_KEY env var is set' },
];

// Quick lookups
const BY_KEY = new Map(SCHEMA.map((e) => [e.key, e]));
const BY_ENV = new Map(SCHEMA.filter((e) => e.envVar).map((e) => [e.envVar, e]));

function getEntry(key) {
  return BY_KEY.get(key) || null;
}

function getEntryByEnv(envVar) {
  return BY_ENV.get(envVar) || null;
}

function listEntries() {
  return SCHEMA.slice();
}

/**
 * Categories in display order for the Settings UI.
 */
const CATEGORY_ORDER = [
  'network',
  'storage',
  'enrichment',
  'threathunt',
  'performance',
  'wardsondb',
  'opensearch',
  'health',
  'logging',
  'auth',
  'security',
];

module.exports = { SCHEMA, getEntry, getEntryByEnv, listEntries, CATEGORY_ORDER };
