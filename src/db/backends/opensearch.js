/**
 * OpenSearch Storage Backend (Beta)
 *
 * Connects to an OpenSearch cluster for high-scale SIEM deployments.
 * Uses OpenSearch's native JSON document storage, aggregation pipeline,
 * and delete_by_query for retention.
 *
 * Key design choices:
 * - Flat document model (not nested like WardSONDB)
 * - Native aggregations replace all rollup tables
 * - IP as _id in enrichment cache for O(1) lookups
 * - update_by_query for server-side enrichment backfill
 */
const { Client } = require('@opensearch-project/opensearch');
const StorageBackend = require('./interface');
const logger = require('../../utils/logger');
const { isPrivateIp } = require('../../utils/ip-utils');

// --- Index Mappings ---

const EVENTS_MAPPING = {
  settings: {
    number_of_shards: 1,
    number_of_replicas: 0,
    'refresh_interval': '5s',
  },
  mappings: {
    properties: {
      received_at:      { type: 'date', format: 'strict_date_optional_time||epoch_millis' },
      event_type:       { type: 'keyword' },
      network_action:   { type: 'keyword' },
      src_ip:           { type: 'ip' },
      dst_ip:           { type: 'ip' },
      src_port:         { type: 'integer' },
      dst_port:         { type: 'integer' },
      protocol:         { type: 'keyword' },
      direction:        { type: 'keyword' },
      mac_address:      { type: 'keyword' },
      interface_in:     { type: 'keyword' },
      interface_out:    { type: 'keyword' },
      severity:         { type: 'keyword' },
      hostname:         { type: 'keyword' },
      source_format:    { type: 'keyword' },
      message:          { type: 'text' },
      timestamp:        { type: 'keyword' },
      // IDS
      ids_signature:    { type: 'keyword' },
      ids_signature_id: { type: 'keyword' },
      ids_category:     { type: 'keyword' },
      ids_severity:     { type: 'integer' },
      threat_type:      { type: 'keyword' },
      threat_category:  { type: 'keyword' },
      // DNS
      dns_query:        { type: 'keyword' },
      dns_answer:       { type: 'keyword' },
      dns_record_type:  { type: 'keyword' },
      dns_action:       { type: 'keyword' },
      dns_client_ip:    { type: 'ip' },
      dns_filter_type:  { type: 'keyword' },
      dns_filter_category: { type: 'keyword' },
      // DHCP
      dhcp_hostname:    { type: 'keyword' },
      dhcp_lease_ip:    { type: 'ip' },
      dhcp_mac:         { type: 'keyword' },
      dhcp_action:      { type: 'keyword' },
      dhcp_interface:   { type: 'keyword' },
      // WiFi
      wifi_ssid:        { type: 'keyword' },
      wifi_event:       { type: 'keyword' },
      wifi_client_mac:  { type: 'keyword' },
      wifi_radio:       { type: 'keyword' },
      wifi_channel:     { type: 'integer' },
      wifi_rssi:        { type: 'integer' },
      // CEF
      cef_event_class_id: { type: 'keyword' },
      cef_name:         { type: 'keyword' },
      cef_severity:     { type: 'integer' },
      unifi_category:   { type: 'keyword' },
      unifi_subcategory:{ type: 'keyword' },
      unifi_host:       { type: 'keyword' },
      // Client
      client_alias:     { type: 'keyword' },
      client_mac:       { type: 'keyword' },
      client_ip:        { type: 'ip' },
      // Raw
      raw_message:      { type: 'text', index: false },
      // Network extras
      packet_length:    { type: 'integer' },
      ttl:              { type: 'integer' },
      tcp_flags:        { type: 'keyword' },
      mac_src:          { type: 'keyword' },
      mac_dst:          { type: 'keyword' },
      rule_prefix:      { type: 'keyword' },
      // Enrichment — source
      src_country:      { type: 'keyword' },
      src_city:         { type: 'keyword' },
      src_latitude:     { type: 'float' },
      src_longitude:    { type: 'float' },
      src_hostname:     { type: 'keyword' },
      src_abuseScore:   { type: 'integer' },
      // Enrichment — destination
      dst_country:      { type: 'keyword' },
      dst_city:         { type: 'keyword' },
      dst_latitude:     { type: 'float' },
      dst_longitude:    { type: 'float' },
      dst_hostname:     { type: 'keyword' },
      dst_abuseScore:   { type: 'integer' },
    },
  },
};

const CACHE_MAPPING = {
  settings: {
    number_of_shards: 1,
    number_of_replicas: 0,
  },
  mappings: {
    properties: {
      ip:                   { type: 'ip' },
      country:              { type: 'keyword' },
      city:                 { type: 'keyword' },
      latitude:             { type: 'float' },
      longitude:            { type: 'float' },
      hostname:             { type: 'keyword' },
      abuseConfidenceScore: { type: 'integer' },
      is_private:           { type: 'boolean' },
      lastSeen:             { type: 'date' },
      createdAt:            { type: 'date' },
      updatedAt:            { type: 'date' },
    },
  },
};

// Phase 11A — Native OpenSearch Rollup jobs (H10).
//
// Five continuous rollup jobs mirror SQLite's five rollup tables. Each job
// reads from `${prefix}events` and writes pre-aggregated docs into a
// dedicated `${prefix}rollup-*` index. With `continuous: true` the IM
// plugin processes new ingest on the schedule cadence — no app-side flush
// worker.
//
// Field-name caveat: the SIEM's OpenSearch mapping is FLAT
// (`network_action`, `dst_port`, `ids_signature`, `ids_category`) — NOT
// nested. The dimension `source_field` paths below match the actual
// indexed fields, not the WardSONDB-style dotted paths.
//
// Backfill caveat: continuous rollup jobs do not retroactively process
// data that existed before job creation (per OpenSearch docs). Existing
// deployments will see rollup indexes accumulate forward-only. Phase 11B
// (a separate change) flips the 9 stats methods to query rollups via
// `_rollup_search` once enough history has accumulated for the longest
// dashboard window.
function buildRollupJobs(prefix) {
  const sourceIndex = `${prefix}events`;
  const mk = (id, targetSuffix, dimensions) => ({
    id: `${prefix}rollup-${id}`,
    body: {
      rollup: {
        source_index: sourceIndex,
        target_index: `${prefix}rollup-${targetSuffix}`,
        description: `SIEM ${id} rollup`,
        enabled: true,
        // Continuous mode still uses `schedule` to set the processing cadence.
        // 5-minute cadence keeps near-real-time freshness on the dashboards.
        schedule: { interval: { period: 5, unit: 'Minutes' } },
        // delay 60s lets late-arriving events (clock skew, syslog backlog)
        // land in the correct bucket before that bucket is rolled up.
        delay: 60_000,
        page_size: 1000,
        continuous: true,
        dimensions,
        // value_count on `received_at` gives the doc-count metric every
        // stats method needs. Adding extra metric types up-front is cheap
        // and avoids the "metrics are immutable once defined" trap.
        metrics: [
          {
            source_field: 'received_at',
            metrics: [{ value_count: {} }, { max: {} }, { min: {} }],
          },
        ],
      },
    },
  });

  return [
    // 5-minute event-type/action rollup — feeds getEventTypeCounts,
    // getOverviewStats, getEventCountToday.
    mk('5m', '5m', [
      { date_histogram: { source_field: 'received_at', fixed_interval: '5m' } },
      { terms: { source_field: 'event_type' } },
      { terms: { source_field: 'network_action' } },
    ]),
    // Hourly src/dst IP — feeds getTopTalkers, getTopBlocked.
    mk('ip-hourly', 'ip-hourly', [
      { date_histogram: { source_field: 'received_at', fixed_interval: '1h' } },
      { terms: { source_field: 'src_ip' } },
      { terms: { source_field: 'dst_ip' } },
      { terms: { source_field: 'direction' } },
    ]),
    // Hourly port/protocol — feeds getTopPorts.
    mk('port-hourly', 'port-hourly', [
      { date_histogram: { source_field: 'received_at', fixed_interval: '1h' } },
      { terms: { source_field: 'dst_port' } },
      { terms: { source_field: 'protocol' } },
    ]),
    // Hourly IDS signature — feeds getTopThreats.
    mk('sig-hourly', 'sig-hourly', [
      { date_histogram: { source_field: 'received_at', fixed_interval: '1h' } },
      { terms: { source_field: 'ids_signature' } },
      { terms: { source_field: 'ids_category' } },
    ]),
    // Hourly client MAC — feeds getTopClients. We register one rollup per
    // mac field rather than chaining all three terms aggs into one job
    // because docs typically have only one of {client_mac, wifi_client_mac,
    // dhcp_mac} populated, and combining them in a single rollup would
    // explode cardinality with mostly-empty bucket combinations.
    mk('client-hourly', 'client-hourly', [
      { date_histogram: { source_field: 'received_at', fixed_interval: '1h' } },
      { terms: { source_field: 'client_mac' } },
      { terms: { source_field: 'wifi_client_mac' } },
      { terms: { source_field: 'dhcp_mac' } },
    ]),
  ];
}

class OpenSearchBackend extends StorageBackend {
  constructor(config = {}) {
    super('OpenSearch', config);
    const host = config.host || 'localhost';
    const port = config.port || 9200;
    const protocol = config.useTls ? 'https' : 'http';
    this.baseUrl = `${protocol}://${host}:${port}`;

    const clientOpts = { node: this.baseUrl };
    if (config.username) {
      clientOpts.auth = { username: config.username, password: config.password || '' };
    }
    if (config.useTls && config.verifyCerts === false) {
      clientOpts.ssl = { rejectUnauthorized: false };
    }
    this.client = new Client(clientOpts);

    const prefix = config.indexPrefix || 'siem-';
    this.eventsIndex = `${prefix}events`;
    this.cacheIndex = `${prefix}enrichment-cache`;
    this.bulkSize = config.bulkSize || 50;
    this.docCount = null;
    this.ready = false;
    // M6: set true while resetData is dropping/recreating indexes so
    // stats methods short-circuit (mirrors WardSONDB's _isCollectionEmpty
    // pattern). Without this, queries during the reset window can hit
    // partially-deleted indexes and throw — and the rebuilding banner
    // wouldn't appear until the next health poll catches up.
    this._rebuilding = false;
  }

  static get metadata() {
    return {
      name: 'OpenSearch',
      description: 'Enterprise-grade search and analytics engine. Ideal for large-scale deployments with built-in dashboards, security analytics, and SIEM capabilities.',
      status: 'beta',
      configFields: [
        { key: 'host', label: 'Host', type: 'text', placeholder: 'localhost', default: 'localhost' },
        { key: 'port', label: 'Port', type: 'number', placeholder: '9200', default: 9200 },
        { key: 'username', label: 'Username', type: 'text', placeholder: 'admin', default: '' },
        { key: 'password', label: 'Password', type: 'password', placeholder: 'Required', default: '' },
        { key: 'useTls', label: 'Use TLS', type: 'boolean', default: true },
        { key: 'verifyCerts', label: 'Verify Certificates', type: 'boolean', default: false },
        { key: 'indexPrefix', label: 'Index Prefix', type: 'text', placeholder: 'siem-', default: 'siem-' },
      ],
    };
  }

  // --- Lifecycle ---

  async initialize() {
    // Verify connectivity
    try {
      await this.client.ping();
    } catch (err) {
      throw new Error(`OpenSearch ping failed at ${this.baseUrl}: ${err.message}`);
    }

    // Create indexes if they don't exist
    await this._ensureIndex(this.eventsIndex, EVENTS_MAPPING);
    await this._ensureIndex(this.cacheIndex, CACHE_MAPPING);

    // Seed doc count
    try {
      const { body } = await this.client.count({ index: this.eventsIndex });
      this.docCount = body.count;
    } catch {
      this.docCount = null;
    }

    this.indexesReady = Promise.resolve();
    this.ready = true;

    // Phase 11A: ensure native rollup jobs are registered + started.
    // Failures here are logged but non-fatal — the SIEM still works on
    // raw queries; the rollups are an optimization layer.
    this._setupRollupJobs().catch((err) =>
      logger.warn({ err: err.message }, 'OpenSearch rollup-job setup failed (non-fatal)'),
    );

    logger.info({ backend: 'opensearch', url: this.baseUrl, eventsIndex: this.eventsIndex }, 'OpenSearch backend initialized');
  }

  async _ensureIndex(name, mapping) {
    const { body: exists } = await this.client.indices.exists({ index: name });
    if (!exists) {
      await this.client.indices.create({ index: name, body: mapping });
      logger.info({ index: name }, 'Created OpenSearch index');
    }
  }

  // --- Phase 11A: Rollup jobs (H10) ---

  /**
   * Idempotently register + start the 5 continuous rollup jobs. Safe to
   * call on every startup: existing jobs are detected via GET and left
   * alone; missing jobs are PUT and started; already-running jobs are
   * not re-started.
   */
  async _setupRollupJobs() {
    const jobs = buildRollupJobs(this.config.indexPrefix || 'siem-');
    for (const job of jobs) {
      try {
        await this._ensureRollupJob(job);
      } catch (err) {
        // Log per-job — one failure shouldn't block the others.
        logger.warn({ err: err.message, jobId: job.id }, 'Rollup job setup failed');
      }
    }
  }

  async _ensureRollupJob({ id, body }) {
    // GET first. Two outcomes:
    //   1. 404 → job doesn't exist → PUT + _start.
    //   2. 200 → already exists → ensure it's running.
    let exists = false;
    try {
      await this.client.transport.request({
        method: 'GET',
        path: `/_plugins/_rollup/jobs/${encodeURIComponent(id)}`,
      });
      exists = true;
    } catch (err) {
      // opensearch-js wraps 404 in ResponseError; check statusCode.
      if (err.meta?.statusCode !== 404 && err.statusCode !== 404) {
        throw err;
      }
    }

    if (!exists) {
      await this.client.transport.request({
        method: 'PUT',
        path: `/_plugins/_rollup/jobs/${encodeURIComponent(id)}`,
        body,
      });
      logger.info({ jobId: id, target: body.rollup.target_index }, 'Created OpenSearch rollup job');
    }

    // Start the job. Per the docs, continuous jobs do NOT auto-start
    // after PUT — _start is required. Calling _start on an already-
    // running job is a no-op (returns 200 with "Failed to start job"
    // for some versions, but is safe).
    try {
      await this.client.transport.request({
        method: 'POST',
        path: `/_plugins/_rollup/jobs/${encodeURIComponent(id)}/_start`,
      });
    } catch (err) {
      // "already started" comes back as 4xx in some IM-plugin versions.
      // We tolerate that and keep going.
      const status = err.meta?.statusCode || err.statusCode;
      if (status && status >= 400 && status < 500) {
        logger.debug({ jobId: id, status }, 'Rollup _start returned 4xx (likely already running)');
      } else {
        throw err;
      }
    }
  }

  async close() {
    if (this.client) {
      await this.client.close();
    }
  }

  // --- Private Helpers ---

  _isCollectionEmpty() {
    // M6: treat the reset window as "no data yet" so stats endpoints
    // return empty payloads instead of trying to query indexes that
    // are mid-recreate.
    if (this._rebuilding) return true;
    return this.docCount === 0;
  }

  _timeRange(since) {
    return { range: { received_at: { gte: since } } };
  }

  // _isPrivateIp removed — call the authoritative isPrivateIp from
  // utils/ip-utils directly (hoisted require at file top to avoid the
  // per-call require lookup in hot paths).

  /** Validate that a string looks like an IP (v4 or v6). OpenSearch's ip type rejects bad values. */
  _isValidIp(val) {
    if (!val || typeof val !== 'string') return false;
    // Quick check: IPv4 or IPv6
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val) || val.includes(':');
  }

  /** Map flat SIEM event to OpenSearch document */
  _serializeEvent(event) {
    const doc = {};
    const set = (key, val) => { if (val !== undefined && val !== null && val !== '') doc[key] = val; };
    const setIp = (key, val) => { if (this._isValidIp(val)) doc[key] = val; };
    const setInt = (key, val) => { if (val != null && !isNaN(val)) doc[key] = parseInt(val, 10); };

    // Core fields
    doc.received_at = event.received_at || new Date().toISOString();
    set('event_type', event.event_type);
    set('network_action', event.action);
    set('direction', event.direction);
    set('protocol', event.protocol);
    set('severity', event.severity != null ? String(event.severity) : undefined);
    set('hostname', event.hostname);
    set('source_format', event.source_format);
    set('message', event.message);
    set('timestamp', event.timestamp);
    set('raw_message', event.raw_message);
    set('interface_in', event.interface_in);
    set('interface_out', event.interface_out);
    set('rule_prefix', event.rule_prefix);
    set('tcp_flags', event.tcp_flags);
    set('mac_src', event.mac_src);
    set('mac_dst', event.mac_dst);

    // IPs
    setIp('src_ip', event.src_ip);
    setIp('dst_ip', event.dst_ip);
    setIp('dns_client_ip', event.dns_client_ip);
    setIp('dhcp_lease_ip', event.dhcp_ip);
    setIp('client_ip', event.client_ip);

    // Integers
    setInt('src_port', event.src_port);
    setInt('dst_port', event.dst_port);
    setInt('packet_length', event.packet_length);
    setInt('ttl', event.ttl);

    // IDS
    set('ids_signature', event.ids_signature);
    set('ids_signature_id', event.ids_signature_id);
    set('ids_category', event.ids_classification);
    setInt('ids_severity', event.ids_priority);
    set('threat_type', event.threat_type);
    set('threat_category', event.threat_category);

    // DHCP
    set('dhcp_action', event.dhcp_action);
    set('dhcp_mac', event.dhcp_mac);
    set('dhcp_hostname', event.dhcp_hostname);
    set('dhcp_interface', event.dhcp_interface);

    // DNS
    set('dns_action', event.dns_action);
    set('dns_query', event.dns_name);
    set('dns_record_type', event.dns_type);
    set('dns_answer', event.dns_result);
    set('dns_filter_type', event.dns_filter_type);
    set('dns_filter_category', event.dns_filter_category);

    // WiFi
    set('wifi_event', event.wifi_action);
    set('wifi_client_mac', event.wifi_client_mac);
    set('wifi_radio', event.wifi_radio);
    set('wifi_ssid', event.wifi_ssid);
    setInt('wifi_channel', event.wifi_channel);
    setInt('wifi_rssi', event.wifi_rssi);

    // CEF
    set('cef_event_class_id', event.cef_event_class_id);
    set('cef_name', event.cef_name);
    setInt('cef_severity', event.cef_severity);
    set('unifi_category', event.unifi_category);
    set('unifi_subcategory', event.unifi_subcategory);
    set('unifi_host', event.unifi_host);

    // Client
    set('client_alias', event.client_alias);
    set('client_mac', event.client_mac);

    // MAC address — pick the most relevant one for the mac_address field
    const mac = event.client_mac || event.dhcp_mac || event.wifi_client_mac || event.mac_src || null;
    set('mac_address', mac);

    return doc;
  }

  /** Map OpenSearch hit back to flat SIEM event format */
  _documentToEvent(hit) {
    const s = hit._source || hit;
    const id = hit._id || null;
    return {
      id,
      event_type: s.event_type || null,
      severity: s.severity != null ? parseInt(s.severity, 10) : null,
      hostname: s.hostname || null,
      source_format: s.source_format || null,
      message: s.message || null,
      timestamp: s.timestamp || null,
      received_at: s.received_at || null,
      raw_message: s.raw_message || null,
      // Network
      action: s.network_action || null,
      direction: s.direction || null,
      interface_in: s.interface_in || null,
      interface_out: s.interface_out || null,
      protocol: s.protocol || null,
      src_ip: s.src_ip || null,
      src_port: s.src_port ?? null,
      dst_ip: s.dst_ip || null,
      dst_port: s.dst_port ?? null,
      packet_length: s.packet_length ?? null,
      ttl: s.ttl ?? null,
      tcp_flags: s.tcp_flags || null,
      mac_src: s.mac_src || null,
      mac_dst: s.mac_dst || null,
      rule_prefix: s.rule_prefix || null,
      // IDS
      ids_signature_id: s.ids_signature_id || null,
      ids_signature: s.ids_signature || null,
      ids_classification: s.ids_category || null,
      ids_priority: s.ids_severity ?? null,
      threat_type: s.threat_type || null,
      threat_category: s.threat_category || null,
      // DHCP
      dhcp_action: s.dhcp_action || null,
      dhcp_ip: s.dhcp_lease_ip || null,
      dhcp_mac: s.dhcp_mac || null,
      dhcp_hostname: s.dhcp_hostname || null,
      dhcp_interface: s.dhcp_interface || null,
      // DNS
      dns_action: s.dns_action || null,
      dns_name: s.dns_query || null,
      dns_type: s.dns_record_type || null,
      dns_result: s.dns_answer || null,
      dns_client_ip: s.dns_client_ip || null,
      dns_filter_type: s.dns_filter_type || null,
      dns_filter_category: s.dns_filter_category || null,
      // WiFi
      wifi_action: s.wifi_event || null,
      wifi_client_mac: s.wifi_client_mac || null,
      wifi_radio: s.wifi_radio || null,
      wifi_ssid: s.wifi_ssid || null,
      wifi_channel: s.wifi_channel ?? null,
      wifi_rssi: s.wifi_rssi ?? null,
      // CEF
      cef_event_class_id: s.cef_event_class_id || null,
      cef_name: s.cef_name || null,
      cef_severity: s.cef_severity ?? null,
      unifi_category: s.unifi_category || null,
      unifi_subcategory: s.unifi_subcategory || null,
      unifi_host: s.unifi_host || null,
      // Client
      client_alias: s.client_alias || null,
      client_mac: s.client_mac || null,
      client_ip: s.client_ip || null,
      // Enrichment
      src_geo_country: s.src_country || null,
      src_geo_city: s.src_city || null,
      src_geo_lat: s.src_latitude ?? null,
      src_geo_lon: s.src_longitude ?? null,
      src_abuse_score: s.src_abuseScore ?? null,
      src_hostname: s.src_hostname || null,
      dst_geo_country: s.dst_country || null,
      dst_geo_city: s.dst_city || null,
      dst_geo_lat: s.dst_latitude ?? null,
      dst_geo_lon: s.dst_longitude ?? null,
      dst_abuse_score: s.dst_abuseScore ?? null,
      dst_hostname: s.dst_hostname || null,
    };
  }

  // --- Write Operations ---

  async insertEvents(events) {
    if (!events || events.length === 0) return { inserted: 0 };

    let totalInserted = 0;
    for (let i = 0; i < events.length; i += this.bulkSize) {
      const chunk = events.slice(i, i + this.bulkSize);
      const body = chunk.flatMap(event => [
        { index: { _index: this.eventsIndex } },
        this._serializeEvent(event),
      ]);

      try {
        const { body: result } = await this.client.bulk({ body, refresh: 'wait_for' });
        if (result.errors) {
          let ok = 0;
          for (const item of result.items) {
            if (item.index && item.index.status >= 200 && item.index.status < 300) {
              ok++;
            } else if (item.index) {
              logger.warn({ error: item.index.error }, 'Bulk insert item failed');
            }
          }
          totalInserted += ok;
        } else {
          totalInserted += chunk.length;
        }
      } catch (err) {
        logger.error({ err }, 'OpenSearch bulk insert failed');
      }
    }

    if (totalInserted > 0) {
      if (this.docCount === 0 || this.docCount === null) {
        this.docCount = totalInserted;
      } else {
        this.docCount += totalInserted;
      }
    }
    return { inserted: totalInserted };
  }

  async updateEnrichment(ip, direction, data, limit = 1000) {
    const dir = direction === 'dst' ? 'dst' : 'src';
    const ipField = `${dir}_ip`;
    const countryField = `${dir}_country`;

    // Build painless script to set enrichment fields
    const params = {};
    const lines = [];
    const fields = {
      [`${dir}_country`]: data.geo_country,
      [`${dir}_city`]: data.geo_city,
      [`${dir}_latitude`]: data.geo_lat,
      [`${dir}_longitude`]: data.geo_lon,
      [`${dir}_abuseScore`]: data.abuse_score,
      [`${dir}_hostname`]: data.hostname,
    };
    for (const [field, val] of Object.entries(fields)) {
      if (val !== undefined && val !== null) {
        params[field] = val;
        lines.push(`ctx._source['${field}'] = params['${field}']`);
      }
    }
    if (lines.length === 0) return { updated: 0 };

    try {
      const { body } = await this.client.updateByQuery({
        index: this.eventsIndex,
        refresh: false,
        slices: 'auto',
        conflicts: 'proceed',
        body: {
          query: {
            bool: {
              filter: [{ term: { [ipField]: ip } }],
              must_not: [{ exists: { field: countryField } }],
            },
          },
          script: {
            source: lines.join('; '),
            lang: 'painless',
            params,
          },
        },
      });
      return { updated: body.updated || 0 };
    } catch (err) {
      logger.error({ err, ip, direction }, 'OpenSearch updateEnrichment failed');
      return { updated: 0 };
    }
  }

  /**
   * Batch version of updateEnrichment — updates multiple IPs with the same enrichment data
   * in a single update_by_query using a `terms` filter. Collapses N per-IP calls into 1.
   */
  async updateEnrichmentBatch(ips, direction, data) {
    if (!ips || ips.length === 0) return { updated: 0 };

    const dir = direction === 'dst' ? 'dst' : 'src';
    const ipField = `${dir}_ip`;
    const countryField = `${dir}_country`;

    const params = {};
    const lines = [];
    const fields = {
      [`${dir}_country`]: data.geo_country,
      [`${dir}_city`]: data.geo_city,
      [`${dir}_latitude`]: data.geo_lat,
      [`${dir}_longitude`]: data.geo_lon,
      [`${dir}_abuseScore`]: data.abuse_score,
      [`${dir}_hostname`]: data.hostname,
    };
    for (const [field, val] of Object.entries(fields)) {
      if (val !== undefined && val !== null) {
        params[field] = val;
        lines.push(`ctx._source['${field}'] = params['${field}']`);
      }
    }
    if (lines.length === 0) return { updated: 0 };

    try {
      const { body } = await this.client.updateByQuery({
        index: this.eventsIndex,
        refresh: false,
        slices: 'auto',
        conflicts: 'proceed',
        body: {
          query: {
            bool: {
              filter: [{ terms: { [ipField]: ips } }],
              must_not: [{ exists: { field: countryField } }],
            },
          },
          script: {
            source: lines.join('; '),
            lang: 'painless',
            params,
          },
        },
      });
      return { updated: body.updated || 0 };
    } catch (err) {
      logger.error({ err, ips: ips.length, direction }, 'OpenSearch updateEnrichmentBatch failed');
      return { updated: 0 };
    }
  }

  // --- Read Operations ---

  async queryEvents(filters = {}) {
    const must = [];
    const filterClauses = [];

    if (filters.event_type) {
      const types = filters.event_type.split(',').map(s => s.trim());
      if (types.length === 1) {
        filterClauses.push({ term: { event_type: types[0] } });
      } else {
        filterClauses.push({ terms: { event_type: types } });
      }
    }
    if (filters.action) {
      filterClauses.push({ term: { network_action: filters.action } });
    }
    if (filters.direction) {
      filterClauses.push({ term: { direction: filters.direction } });
    }
    if (filters.severity) {
      const sevs = filters.severity.split(',').map(s => String(s.trim()));
      filterClauses.push({ terms: { severity: sevs } });
    }
    if (filters.src_ip) {
      filterClauses.push({ term: { src_ip: filters.src_ip } });
    }
    if (filters.dst_ip) {
      filterClauses.push({ term: { dst_ip: filters.dst_ip } });
    }
    if (filters.dst_port) {
      filterClauses.push({ term: { dst_port: parseInt(filters.dst_port, 10) } });
    }
    if (filters.protocol) {
      filterClauses.push({ term: { protocol: filters.protocol.toUpperCase() } });
    }
    if (filters.mac) {
      filterClauses.push({
        bool: {
          should: [
            { term: { mac_address: filters.mac } },
            { term: { client_mac: filters.mac } },
            { term: { wifi_client_mac: filters.mac } },
            { term: { dhcp_mac: filters.mac } },
            { term: { mac_src: filters.mac } },
            { term: { mac_dst: filters.mac } },
          ],
          minimum_should_match: 1,
        },
      });
    }
    if (filters.since) {
      filterClauses.push({ range: { received_at: { gte: filters.since } } });
    }
    if (filters.until) {
      filterClauses.push({ range: { received_at: { lte: filters.until } } });
    }
    if (filters.search) {
      must.push({
        bool: {
          should: [
            { wildcard: { src_ip: { value: `*${filters.search}*` } } },
            { wildcard: { dst_ip: { value: `*${filters.search}*` } } },
            { match_phrase: { message: filters.search } },
            { match_phrase: { raw_message: filters.search } },
            { wildcard: { dns_query: { value: `*${filters.search}*` } } },
            { wildcard: { hostname: { value: `*${filters.search}*` } } },
          ],
          minimum_should_match: 1,
        },
      });
    }

    const limit = Math.min(parseInt(filters.limit || '50', 10), 500);
    const offset = parseInt(filters.offset || '0', 10);

    const query = { bool: {} };
    if (must.length) query.bool.must = must;
    if (filterClauses.length) query.bool.filter = filterClauses;
    if (!must.length && !filterClauses.length) query.bool.must = [{ match_all: {} }];

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          query,
          sort: [{ received_at: { order: 'desc' } }],
          from: offset,
          size: limit,
        },
      });
      const events = (body.hits?.hits || []).map(h => this._documentToEvent(h));
      return { events };
    } catch (err) {
      logger.error({ err }, 'OpenSearch queryEvents failed');
      return { events: [] };
    }
  }

  async getEventById(id) {
    try {
      const { body } = await this.client.get({ index: this.eventsIndex, id });
      return this._documentToEvent({ _id: body._id, _source: body._source });
    } catch (err) {
      if (err.statusCode === 404) return null;
      throw err;
    }
  }

  async getEventCount() {
    const { body } = await this.client.count({ index: this.eventsIndex });
    return body.count;
  }

  async getEventCountToday() {
    const now = new Date();
    const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const { body } = await this.client.count({
      index: this.eventsIndex,
      body: { query: { range: { received_at: { gte: midnight.toISOString() } } } },
    });
    return body.count;
  }

  async getLastEventTime() {
    const { body } = await this.client.search({
      index: this.eventsIndex,
      body: {
        size: 1,
        sort: [{ received_at: { order: 'desc' } }],
        _source: ['received_at'],
      },
    });
    const hits = body.hits?.hits || [];
    return hits.length > 0 ? hits[0]._source.received_at : null;
  }

  async getEventTypeCounts(since) {
    if (this._isCollectionEmpty()) return {};
    const query = since ? this._timeRange(since) : { match_all: {} };
    const { body } = await this.client.search({
      index: this.eventsIndex,
      body: {
        size: 0,
        query,
        aggs: { by_type: { terms: { field: 'event_type', size: 50 } } },
      },
    });
    const counts = {};
    for (const bucket of body.aggregations?.by_type?.buckets || []) {
      counts[bucket.key] = bucket.doc_count;
    }
    return counts;
  }

  // --- Stats / Aggregation ---

  async getOverviewStats(since) {
    const empty = { total: 0, byType: {}, firewall: { allowed: 0, blocked: 0, threats: 0 } };
    if (this._isCollectionEmpty()) return empty;

    try {
      const [{ body }, byType] = await Promise.all([
        this.client.search({
          index: this.eventsIndex,
          body: {
            size: 0,
            track_total_hits: true,
            query: this._timeRange(since),
            aggs: {
              allowed: {
                filter: {
                  bool: { filter: [
                    { term: { event_type: 'firewall' } },
                    { term: { network_action: 'allow' } },
                  ] },
                },
              },
              blocked: {
                filter: {
                  bool: { filter: [
                    { term: { event_type: 'firewall' } },
                    { term: { network_action: 'block' } },
                  ] },
                },
              },
              threats: {
                filter: { term: { event_type: 'threat' } },
              },
            },
          },
        }),
        this.getEventTypeCounts(since),
      ]);

      return {
        total: body.hits?.total?.value || 0,
        byType,
        firewall: {
          allowed: body.aggregations?.allowed?.doc_count || 0,
          blocked: body.aggregations?.blocked?.doc_count || 0,
          threats: body.aggregations?.threats?.doc_count || 0,
        },
      };
    } catch (err) {
      logger.error({ err }, 'OpenSearch getOverviewStats failed');
      return empty;
    }
  }

  async getTimeline(since, bucketFormat, eventType, bucketSize) {
    if (this._isCollectionEmpty()) return [];

    const interval = bucketSize || '1h';
    const isFirewall = eventType === 'firewall';

    // Build query with optional event_type filter
    const query = {
      bool: {
        filter: [this._timeRange(since)],
      },
    };
    if (isFirewall) {
      query.bool.filter.push({ term: { event_type: 'firewall' } });
    }

    const subAgg = isFirewall
      ? { by_action: { terms: { field: 'network_action', size: 10 } } }
      : { by_type: { terms: { field: 'event_type', size: 20 } } };

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query,
          aggs: {
            timeline: {
              date_histogram: {
                field: 'received_at',
                fixed_interval: interval,
                min_doc_count: 0,
                extended_bounds: { min: since, max: new Date().toISOString() },
              },
              aggs: subAgg,
            },
          },
        },
      });

      const buckets = body.aggregations?.timeline?.buckets || [];
      return buckets.map(b => {
        const ts = new Date(b.key).toISOString();
        if (isFirewall) {
          const actionMap = {};
          for (const ab of b.by_action?.buckets || []) actionMap[ab.key] = ab.doc_count;
          return {
            ts,
            allowed: actionMap['allow'] || 0,
            blocked: (actionMap['block'] || 0),
          };
        } else {
          const typeMap = {};
          for (const tb of b.by_type?.buckets || []) typeMap[tb.key] = tb.doc_count;
          return {
            ts,
            firewall: typeMap['firewall'] || 0,
            threat: typeMap['threat'] || 0,
            dhcp: typeMap['dhcp'] || 0,
            dns_filter: typeMap['dns_filter'] || 0,
            wifi: typeMap['wifi'] || 0,
            admin: typeMap['admin'] || 0,
            system: typeMap['system'] || 0,
            total: b.doc_count,
          };
        }
      });
    } catch (err) {
      logger.error({ err }, 'OpenSearch getTimeline failed');
      return [];
    }
  }

  async getTopTalkers(since, direction, limit, excludePrivate) {
    if (this._isCollectionEmpty()) return [];

    const dir = direction === 'dst' ? 'dst' : 'src';
    const ipField = `${dir}_ip`;
    const fetchLimit = excludePrivate ? limit * 5 : limit;

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query: {
            bool: { filter: [this._timeRange(since), { exists: { field: ipField } }] },
          },
          aggs: {
            top_ips: {
              terms: { field: ipField, size: fetchLimit },
              aggs: {
                last_seen: { max: { field: 'received_at' } },
              },
            },
          },
        },
      });

      const buckets = body.aggregations?.top_ips?.buckets || [];
      const ips = buckets.map(b => b.key);
      const cacheMap = await this._getCacheMap(ips);

      let rows = buckets.map(b => {
        const cached = cacheMap.get(b.key);
        return {
          ip: b.key,
          count: b.doc_count,
          lastSeen: b.last_seen?.value_as_string || null,
          country: cached?.country || null,
          hostname: cached?.hostname || null,
        };
      });

      if (excludePrivate) rows = rows.filter(r => !isPrivateIp(r.ip));
      return rows.slice(0, limit);
    } catch (err) {
      logger.error({ err }, 'OpenSearch getTopTalkers failed');
      return [];
    }
  }

  async getTopBlocked(since, direction, limit, excludePrivate) {
    if (this._isCollectionEmpty()) return [];

    const dir = direction === 'dst' ? 'dst' : 'src';
    const ipField = `${dir}_ip`;
    const fetchLimit = excludePrivate ? limit * 5 : limit;

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query: {
            bool: {
              filter: [
                this._timeRange(since),
                { exists: { field: ipField } },
                { term: { network_action: 'block' } },
              ],
            },
          },
          aggs: {
            top_ips: {
              terms: { field: ipField, size: fetchLimit },
              aggs: {
                last_seen: { max: { field: 'received_at' } },
              },
            },
          },
        },
      });

      const buckets = body.aggregations?.top_ips?.buckets || [];
      const ips = buckets.map(b => b.key);
      const cacheMap = await this._getCacheMap(ips);

      let rows = buckets.map(b => {
        const cached = cacheMap.get(b.key);
        return {
          ip: b.key,
          count: b.doc_count,
          lastSeen: b.last_seen?.value_as_string || null,
          country: cached?.country || null,
          hostname: cached?.hostname || null,
          abuseScore: cached?.abuseConfidenceScore ?? null,
        };
      });

      if (excludePrivate) rows = rows.filter(r => !isPrivateIp(r.ip));
      return rows.slice(0, limit);
    } catch (err) {
      logger.error({ err }, 'OpenSearch getTopBlocked failed');
      return [];
    }
  }

  async getTopPorts(since, limit) {
    if (this._isCollectionEmpty()) return [];

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query: {
            bool: {
              filter: [
                this._timeRange(since),
                { term: { event_type: 'firewall' } },
                { exists: { field: 'dst_port' } },
              ],
            },
          },
          aggs: {
            top_ports: {
              terms: { field: 'dst_port', size: limit },
              aggs: {
                proto: { terms: { field: 'protocol', size: 1 } },
              },
            },
          },
        },
      });

      return (body.aggregations?.top_ports?.buckets || []).map(b => ({
        port: b.key,
        protocol: b.proto?.buckets?.[0]?.key || null,
        count: b.doc_count,
      }));
    } catch (err) {
      logger.error({ err }, 'OpenSearch getTopPorts failed');
      return [];
    }
  }

  async getTopClients(since, limit) {
    if (this._isCollectionEmpty()) return [];

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query: {
            bool: {
              filter: [this._timeRange(since), { exists: { field: 'mac_address' } }],
            },
          },
          aggs: {
            top_macs: {
              terms: { field: 'mac_address', size: limit },
              aggs: {
                wifi: { filter: { term: { event_type: 'wifi' } } },
                dhcp: { filter: { term: { event_type: 'dhcp' } } },
                firewall: { filter: { term: { event_type: 'firewall' } } },
              },
            },
          },
        },
      });

      const rows = (body.aggregations?.top_macs?.buckets || []).map(b => ({
        mac: b.key,
        eventCount: b.doc_count,
        wifiEvents: b.wifi?.doc_count || 0,
        dhcpEvents: b.dhcp?.doc_count || 0,
        firewallEvents: b.firewall?.doc_count || 0,
        alias: null,
        ip: null,
      }));
      return rows;
    } catch (err) {
      logger.error({ err }, 'OpenSearch getTopClients failed');
      return [];
    }
  }

  async getTopThreats(since, limit) {
    if (this._isCollectionEmpty()) return [];

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query: {
            bool: {
              filter: [this._timeRange(since), { term: { event_type: 'threat' } }],
            },
          },
          aggs: {
            top_sigs: {
              terms: { field: 'ids_signature', size: limit, missing: '(no signature)' },
              aggs: {
                last_seen: { max: { field: 'received_at' } },
                classification: { terms: { field: 'ids_category', size: 1 } },
              },
            },
          },
        },
      });

      return (body.aggregations?.top_sigs?.buckets || []).map(b => ({
        signature: b.key,
        classification: b.classification?.buckets?.[0]?.key || null,
        count: b.doc_count,
        lastSeen: b.last_seen?.value_as_string || null,
      }));
    } catch (err) {
      logger.error({ err }, 'OpenSearch getTopThreats failed');
      return [];
    }
  }

  async getThreatIntel(since, limit) {
    const empty = {
      summary: { totalEnriched: 0, withAbuseScore: 0, highThreat: 0, countries: 0 },
      periodSummary: { enriched: 0, flagged: 0, highThreat: 0, countries: 0 },
      ips: [],
    };
    if (this._isCollectionEmpty()) return empty;

    try {
      // Top row (cache-wide totals) runs in parallel with the cache walk below.
      const summaryPromise = this._cacheGlobalSummary();

      // Walk the enriched cache fully — paginated by search_after, no 10K cap.
      // Collect rows into cacheMap and IP chunks for parallel period-stats
      // queries against the events index.
      const cacheMap = new Map();
      const ipChunks = [];
      for await (const batch of this._iterateEnrichedCacheEntries(1000)) {
        const ips = [];
        for (const c of batch) {
          cacheMap.set(c.ip, c);
          ips.push(c.ip);
        }
        ipChunks.push(ips);
      }

      // Each chunk's events query is independent — fan out in parallel.
      // Filtering with `terms.include` against cache IPs avoids the 5000-bucket
      // truncation bug of the previous top-N terms agg approach.
      const statsResults = await Promise.all(
        ipChunks.map(chunk => this._eventsStatsForIps(chunk, since)),
      );

      // Merge per-chunk maps. An IP may appear in multiple chunks only if cache
      // pagination rolls past it (shouldn't happen with stable ip-sort), but
      // merging is cheap insurance.
      const ipStats = new Map();
      for (const stats of statsResults) {
        for (const [ip, s] of stats) {
          const cur = ipStats.get(ip);
          if (cur) {
            cur.event_count += s.event_count;
            cur.blocked_count += s.blocked_count;
            cur.threat_count += s.threat_count;
            if (s.lastSeen && (!cur.lastSeen || s.lastSeen > cur.lastSeen)) cur.lastSeen = s.lastSeen;
          } else {
            ipStats.set(ip, { ...s });
          }
        }
      }

      // Period summary tallied directly from cache rows that had ≥1 event.
      let pEnriched = 0, pFlagged = 0, pHighThreat = 0;
      const pCountries = new Set();
      const ips = [];
      for (const [ip, stats] of ipStats) {
        const c = cacheMap.get(ip);
        if (!c) continue;
        if (!c.country && c.abuseConfidenceScore == null) continue;
        pEnriched++;
        if (c.abuseConfidenceScore > 0) pFlagged++;
        if (c.abuseConfidenceScore >= 50) pHighThreat++;
        if (c.country) pCountries.add(c.country);
        ips.push({
          ip,
          hostname: c.hostname || null,
          country: c.country || null,
          city: c.city || null,
          lat: c.latitude ?? null,
          lon: c.longitude ?? null,
          abuse_score: c.abuseConfidenceScore ?? null,
          event_count: stats.event_count,
          blocked_count: stats.blocked_count,
          threat_count: stats.threat_count,
          lastSeen: stats.lastSeen,
        });
      }
      ips.sort((a, b) => b.event_count - a.event_count || (b.abuse_score || 0) - (a.abuse_score || 0));

      const summary = await summaryPromise;
      return {
        summary,
        periodSummary: {
          enriched: pEnriched,
          flagged: pFlagged,
          highThreat: pHighThreat,
          countries: pCountries.size,
        },
        ips: ips.slice(0, limit),
      };
    } catch (err) {
      logger.error({ err }, 'OpenSearch getThreatIntel failed');
      return empty;
    }
  }

  async getGeoEvents(since, limit) {
    if (this._isCollectionEmpty()) return [];
    const half = Math.ceil(limit / 2);

    try {
      const [srcResult, dstResult] = await Promise.all([
        this.client.search({
          index: this.eventsIndex,
          body: {
            size: 0,
            query: {
              bool: {
                filter: [this._timeRange(since), { exists: { field: 'src_latitude' } }],
              },
            },
            aggs: {
              by_ip: {
                terms: { field: 'src_ip', size: half * 3 },
                aggs: {
                  geo: {
                    top_hits: {
                      size: 1,
                      _source: ['src_country', 'src_city', 'src_latitude', 'src_longitude', 'src_abuseScore', 'src_hostname'],
                    },
                  },
                  blocked: { filter: { term: { network_action: 'block' } } },
                  threats: { filter: { term: { event_type: 'threat' } } },
                },
              },
            },
          },
        }),
        this.client.search({
          index: this.eventsIndex,
          body: {
            size: 0,
            query: {
              bool: {
                filter: [this._timeRange(since), { exists: { field: 'dst_latitude' } }],
              },
            },
            aggs: {
              by_ip: {
                terms: { field: 'dst_ip', size: half * 3 },
                aggs: {
                  geo: {
                    top_hits: {
                      size: 1,
                      _source: ['dst_country', 'dst_city', 'dst_latitude', 'dst_longitude', 'dst_abuseScore', 'dst_hostname'],
                    },
                  },
                  blocked: { filter: { term: { network_action: 'block' } } },
                  threats: { filter: { term: { event_type: 'threat' } } },
                },
              },
            },
          },
        }),
      ]);

      const mapBuckets = (buckets, dir) => {
        return buckets.map(b => {
          const hit = b.geo?.hits?.hits?.[0]?._source || {};
          return {
            ip: b.key,
            country: hit[`${dir}_country`] || null,
            city: hit[`${dir}_city`] || null,
            lat: hit[`${dir}_latitude`] ?? null,
            lon: hit[`${dir}_longitude`] ?? null,
            count: b.doc_count,
            blocked: b.blocked?.doc_count || 0,
            threats: b.threats?.doc_count || 0,
            abuseScore: hit[`${dir}_abuseScore`] ?? null,
            hostname: hit[`${dir}_hostname`] || null,
            direction: dir,
            lastSeen: null,
          };
        }).filter(r => r.lat != null && r.lon != null);
      };

      const srcRows = mapBuckets(srcResult.body.aggregations?.by_ip?.buckets || [], 'src').slice(0, half);
      const dstRows = mapBuckets(dstResult.body.aggregations?.by_ip?.buckets || [], 'dst').slice(0, half);
      return [...srcRows, ...dstRows];
    } catch (err) {
      logger.error({ err }, 'OpenSearch getGeoEvents failed');
      return [];
    }
  }

  async getRecentGeoEvents(limit) {
    if (this._isCollectionEmpty()) return [];

    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: limit,
          query: {
            bool: {
              should: [
                { exists: { field: 'src_latitude' } },
                { exists: { field: 'dst_latitude' } },
              ],
              minimum_should_match: 1,
            },
          },
          sort: [{ received_at: { order: 'desc' } }],
        },
      });

      return (body.hits?.hits || []).map(h => this._documentToEvent(h));
    } catch (err) {
      logger.error({ err }, 'OpenSearch getRecentGeoEvents failed');
      return [];
    }
  }

  // --- Threat Hunt ---

  async gatherHuntIntel(target, since) {
    const { gatherHuntIntel } = require('../../threat-hunt/intel/opensearch');
    return gatherHuntIntel(this, target, since);
  }

  // --- Enrichment Cache ---

  /** Batch lookup cache entries by IP using mget */
  async _getCacheMap(ips) {
    if (!ips || ips.length === 0) return new Map();
    try {
      const { body } = await this.client.mget({
        index: this.cacheIndex,
        body: { ids: ips },
      });
      const map = new Map();
      for (const doc of body.docs || []) {
        if (doc.found) {
          map.set(doc._id, doc._source);
        }
      }
      return map;
    } catch {
      return new Map();
    }
  }

  /** Bool query matching non-private cache rows that carry geo or abuse data. */
  _enrichedCacheQuery() {
    return {
      bool: {
        must_not: [{ term: { is_private: true } }],
        should: [
          { exists: { field: 'country' } },
          { exists: { field: 'abuseConfidenceScore' } },
        ],
        minimum_should_match: 1,
      },
    };
  }

  /**
   * Single aggregation that returns the cache-wide summary (top-row cards).
   * Removes the 10K hits cap from the previous _getAllCacheEntries-then-iterate
   * pattern. cardinality precision_threshold is set to OpenSearch's max (40000)
   * — exact for ≤40K distinct values.
   */
  async _cacheGlobalSummary() {
    try {
      const { body } = await this.client.search({
        index: this.cacheIndex,
        body: {
          size: 0,
          track_total_hits: true,
          query: this._enrichedCacheQuery(),
          aggs: {
            withAbuseScore: { filter: { range: { abuseConfidenceScore: { gt: 0 } } } },
            highThreat:    { filter: { range: { abuseConfidenceScore: { gte: 50 } } } },
            countries:     { cardinality: { field: 'country', precision_threshold: 40000 } },
          },
        },
      });
      return {
        totalEnriched: body.hits?.total?.value ?? 0,
        withAbuseScore: body.aggregations?.withAbuseScore?.doc_count ?? 0,
        highThreat: body.aggregations?.highThreat?.doc_count ?? 0,
        countries: body.aggregations?.countries?.value ?? 0,
      };
    } catch (err) {
      logger.error({ err }, 'OpenSearch _cacheGlobalSummary failed');
      return { totalEnriched: 0, withAbuseScore: 0, highThreat: 0, countries: 0 };
    }
  }

  /**
   * Async generator that yields batches of enriched non-private cache rows.
   * Pages via sort + search_after on the `ip` field (== _id) — handles caches
   * larger than the 10K index.max_result_window cap.
   */
  async *_iterateEnrichedCacheEntries(batchSize = 1000) {
    const baseBody = {
      size: batchSize,
      query: this._enrichedCacheQuery(),
      sort: [{ ip: { order: 'asc' } }],
      track_total_hits: false,
    };
    let searchAfter;
    while (true) {
      const body = searchAfter ? { ...baseBody, search_after: searchAfter } : baseBody;
      let hits;
      try {
        const res = await this.client.search({ index: this.cacheIndex, body });
        hits = res.body?.hits?.hits || [];
      } catch (err) {
        logger.error({ err }, 'OpenSearch _iterateEnrichedCacheEntries page failed');
        break;
      }
      if (hits.length === 0) break;
      yield hits.map(h => ({ ip: h._id, ...h._source }));
      if (hits.length < batchSize) break;
      searchAfter = hits[hits.length - 1].sort;
    }
  }

  /**
   * Given a chunk of IPs, return per-IP stats for those that appeared in
   * events during [since, now) — uses `terms.include` to push the filter
   * down so we only get back the IPs we asked about (no top-N truncation).
   * Returns Map<ip, {event_count, blocked_count, threat_count, lastSeen}>.
   */
  async _eventsStatsForIps(ips, since) {
    const stats = new Map();
    if (!ips || ips.length === 0) return stats;
    const subAggs = {
      blocked:   { filter: { term: { network_action: 'block' } } },
      threats:   { filter: { term: { event_type: 'threat' } } },
      last_seen: { max: { field: 'received_at' } },
    };
    try {
      const { body } = await this.client.search({
        index: this.eventsIndex,
        body: {
          size: 0,
          query: {
            bool: {
              filter: [
                this._timeRange(since),
                {
                  bool: {
                    should: [
                      { terms: { src_ip: ips } },
                      { terms: { dst_ip: ips } },
                    ],
                    minimum_should_match: 1,
                  },
                },
              ],
            },
          },
          aggs: {
            by_src: { terms: { field: 'src_ip', include: ips, size: ips.length }, aggs: subAggs },
            by_dst: { terms: { field: 'dst_ip', include: ips, size: ips.length }, aggs: subAggs },
          },
        },
      });
      const merge = (buckets) => {
        for (const b of buckets) {
          const cur = stats.get(b.key) || { event_count: 0, blocked_count: 0, threat_count: 0, lastSeen: null };
          cur.event_count += b.doc_count;
          cur.blocked_count += b.blocked?.doc_count || 0;
          cur.threat_count += b.threats?.doc_count || 0;
          const ls = b.last_seen?.value_as_string;
          if (ls && (!cur.lastSeen || ls > cur.lastSeen)) cur.lastSeen = ls;
          stats.set(b.key, cur);
        }
      };
      merge(body.aggregations?.by_src?.buckets || []);
      merge(body.aggregations?.by_dst?.buckets || []);
    } catch (err) {
      logger.error({ err, count: ips.length }, 'OpenSearch _eventsStatsForIps failed');
    }
    return stats;
  }

  async getCachedEnrichment(ip) {
    try {
      const { body } = await this.client.get({ index: this.cacheIndex, id: ip });
      if (!body.found) return null;
      const doc = body._source;

      // Check staleness
      if (doc.updatedAt) {
        const updatedAt = new Date(doc.updatedAt).getTime();
        const maxAge = (this.config.abuseIpDbCacheHours || 24) * 60 * 60 * 1000;
        if (Date.now() - updatedAt > maxAge) return null;
      }

      // Return in the format expected by the enrichment pipeline
      return {
        ip: doc.ip || ip,
        geo_country: doc.country || null,
        geo_city: doc.city || null,
        geo_lat: doc.latitude ?? null,
        geo_lon: doc.longitude ?? null,
        abuse_score: doc.abuseConfidenceScore ?? null,
        hostname: doc.hostname || null,
        is_private: doc.is_private ? 1 : 0,
        updated_at: doc.updatedAt || null,
      };
    } catch (err) {
      if (err.statusCode === 404 || err.meta?.statusCode === 404) return null;
      logger.error({ err, ip }, 'OpenSearch getCachedEnrichment failed');
      return null;
    }
  }

  async setCachedEnrichment(ip, data) {
    // Read-then-write merge to preserve existing fields
    let existing = {};
    try {
      const { body } = await this.client.get({ index: this.cacheIndex, id: ip });
      if (body.found) existing = body._source;
    } catch {
      // Not found — fresh insert
    }

    const merged = {
      ip,
      country: data.geo_country ?? existing.country ?? null,
      city: data.geo_city ?? existing.city ?? null,
      latitude: data.geo_lat ?? existing.latitude ?? null,
      longitude: data.geo_lon ?? existing.longitude ?? null,
      hostname: data.hostname ?? existing.hostname ?? null,
      abuseConfidenceScore: data.abuse_score ?? existing.abuseConfidenceScore ?? null,
      is_private: data.is_private ?? existing.is_private ?? false,
      updatedAt: new Date().toISOString(),
      createdAt: existing.createdAt || new Date().toISOString(),
    };

    await this.client.index({
      index: this.cacheIndex,
      id: ip,
      body: merged,
      refresh: true,
    });
  }

  async markPrivate(ip) {
    await this.setCachedEnrichment(ip, { is_private: true });
  }

  async getAllCachedEnrichment() {
    const out = [];
    for await (const batch of this._iterateEnrichedCacheEntries(1000)) {
      for (const e of batch) {
        out.push({
          ip: e.ip,
          geo_country: e.country || null,
          geo_city: e.city || null,
          geo_lat: e.latitude ?? null,
          geo_lon: e.longitude ?? null,
          abuse_score: e.abuseConfidenceScore ?? null,
          hostname: e.hostname || null,
        });
      }
    }
    return out;
  }

  // --- Health & Maintenance ---

  async healthCheck() {
    try {
      const { body: health } = await this.client.cluster.health();
      const clusterStatus = health.status; // green, yellow, red

      // Update doc count
      try {
        const { body: countResult } = await this.client.count({ index: this.eventsIndex });
        this.docCount = countResult.count;
      } catch {
        // Index might not exist yet
      }

      // Yellow is expected for single-node (replicas can't be assigned)
      const ok = clusterStatus !== 'red';
      // M6: surface the reset-window rebuild as write_pressure: high so
      // the dashboard banner appears immediately (rather than waiting
      // for the next ingestion-driven write_pressure observation).
      const writePressure = (this._rebuilding || clusterStatus === 'red') ? 'high' : 'normal';

      return {
        ok,
        writePressure,
        rebuilding: this._rebuilding,
        details: {
          backend: 'opensearch',
          clusterStatus,
          url: this.baseUrl,
          totalDocuments: this.docCount ?? 0,
          eventsStorage: {
            docCount: this.docCount ?? 0,
            oldestDoc: null,
            newestDoc: null,
          },
        },
      };
    } catch (err) {
      logger.error({ err }, 'OpenSearch healthCheck failed');
      return {
        ok: false,
        writePressure: 'high',
        details: {
          backend: 'opensearch',
          error: err.message,
          totalDocuments: this.docCount ?? 0,
          eventsStorage: { docCount: this.docCount ?? 0 },
        },
      };
    }
  }

  async runRetention(days) {
    try {
      const { body } = await this.client.deleteByQuery({
        index: this.eventsIndex,
        refresh: true,
        body: {
          query: { range: { received_at: { lt: `now-${days}d` } } },
        },
      });
      const deleted = body.deleted || 0;
      if (deleted > 0 && this.docCount != null) {
        this.docCount = Math.max(0, this.docCount - deleted);
      }
      return { deleted };
    } catch (err) {
      logger.error({ err }, 'OpenSearch runRetention failed');
      return { deleted: 0 };
    }
  }

  async resetData() {
    // M6: flag the rebuild window so stats methods short-circuit and
    // healthCheck reports rebuilding. Cleared in the finally block —
    // even on failure, leaving the flag stuck would silently break
    // the dashboard.
    this._rebuilding = true;
    try {
      try {
        await this.client.indices.delete({
          index: [this.eventsIndex, this.cacheIndex],
          ignore_unavailable: true,
        });
      } catch {
        // Indexes may not exist
      }

      await this._ensureIndex(this.eventsIndex, EVENTS_MAPPING);
      await this._ensureIndex(this.cacheIndex, CACHE_MAPPING);
      this.docCount = 0;
      this.indexesReady = Promise.resolve();
    } finally {
      this._rebuilding = false;
    }
  }

  // --- Settings (delegated to SQLite by storage manager) ---

  async getSetting() { throw new Error('Settings are managed by SQLite'); }
  async setSetting() { throw new Error('Settings are managed by SQLite'); }
  async getAllSettings() { throw new Error('Settings are managed by SQLite'); }
}

module.exports = OpenSearchBackend;
// Exported for unit testing — the rollup-job specs are pure data, easy to
// verify against the OpenSearch IM-plugin schema without spinning up a cluster.
module.exports.buildRollupJobs = buildRollupJobs;
