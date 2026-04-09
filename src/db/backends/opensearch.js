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
    logger.info({ backend: 'opensearch', url: this.baseUrl, eventsIndex: this.eventsIndex }, 'OpenSearch backend initialized');
  }

  async _ensureIndex(name, mapping) {
    const { body: exists } = await this.client.indices.exists({ index: name });
    if (!exists) {
      await this.client.indices.create({ index: name, body: mapping });
      logger.info({ index: name }, 'Created OpenSearch index');
    }
  }

  async close() {
    if (this.client) {
      await this.client.close();
    }
  }

  // --- Private Helpers ---

  _isCollectionEmpty() {
    return this.docCount === 0;
  }

  _timeRange(since) {
    return { range: { received_at: { gte: since } } };
  }

  _isPrivateIp(ip) {
    if (!ip || typeof ip !== 'string') return true;
    // Reuse the authoritative check from ip-utils
    const { isPrivateIp } = require('../../utils/ip-utils');
    return isPrivateIp(ip);
  }

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
                    { terms: { network_action: ['block', 'drop'] } },
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
            blocked: (actionMap['block'] || 0) + (actionMap['drop'] || 0),
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

      if (excludePrivate) rows = rows.filter(r => !this._isPrivateIp(r.ip));
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
                { terms: { network_action: ['block', 'drop'] } },
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

      if (excludePrivate) rows = rows.filter(r => !this._isPrivateIp(r.ip));
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
      // Get all non-private enrichment cache entries
      const allCache = await this._getAllCacheEntries();

      // Summary from cache
      const totalEnriched = allCache.length;
      const withAbuseScore = allCache.filter(c => c.abuseConfidenceScore > 0).length;
      const highThreat = allCache.filter(c => c.abuseConfidenceScore >= 50).length;
      const countriesSet = new Set(allCache.filter(c => c.country).map(c => c.country));

      // IP aggregation from events in period — both src and dst directions
      const aggBody = {
        aggs: {
          events: { value_count: { field: 'received_at' } },
          blocked: { filter: { terms: { network_action: ['block', 'drop'] } } },
          threats: { filter: { term: { event_type: 'threat' } } },
          last_seen: { max: { field: 'received_at' } },
        },
      };
      const [srcResult, dstResult] = await Promise.all([
        this.client.search({
          index: this.eventsIndex,
          body: {
            size: 0,
            query: this._timeRange(since),
            aggs: { by_ip: { terms: { field: 'src_ip', size: 5000 }, ...aggBody } },
          },
        }),
        this.client.search({
          index: this.eventsIndex,
          body: {
            size: 0,
            query: this._timeRange(since),
            aggs: { by_ip: { terms: { field: 'dst_ip', size: 5000 }, ...aggBody } },
          },
        }),
      ]);

      // Merge src + dst buckets into combined per-IP stats
      const ipStats = new Map();
      const mergeBuckets = (buckets) => {
        for (const b of buckets) {
          const existing = ipStats.get(b.key);
          if (existing) {
            existing.event_count += b.doc_count;
            existing.blocked_count += b.blocked?.doc_count || 0;
            existing.threat_count += b.threats?.doc_count || 0;
            const ls = b.last_seen?.value_as_string;
            if (ls && (!existing.lastSeen || ls > existing.lastSeen)) existing.lastSeen = ls;
          } else {
            ipStats.set(b.key, {
              event_count: b.doc_count,
              blocked_count: b.blocked?.doc_count || 0,
              threat_count: b.threats?.doc_count || 0,
              lastSeen: b.last_seen?.value_as_string || null,
            });
          }
        }
      };
      mergeBuckets(srcResult.body?.aggregations?.by_ip?.buckets || []);
      mergeBuckets(dstResult.body?.aggregations?.by_ip?.buckets || []);

      // Build cache lookup
      const cacheMap = new Map(allCache.map(c => [c.ip, c]));

      // Merge event agg with cache
      const ips = [];
      const periodCountries = new Set();
      let periodFlagged = 0;
      let periodHighThreat = 0;

      for (const [ip, stats] of ipStats) {
        const cached = cacheMap.get(ip);
        if (!cached) continue; // only show enriched IPs
        if (!cached.country && cached.abuseConfidenceScore == null) continue;

        if (cached.country) periodCountries.add(cached.country);
        if (cached.abuseConfidenceScore > 0) periodFlagged++;
        if (cached.abuseConfidenceScore >= 50) periodHighThreat++;

        ips.push({
          ip,
          hostname: cached.hostname || null,
          country: cached.country || null,
          city: cached.city || null,
          lat: cached.latitude ?? null,
          lon: cached.longitude ?? null,
          abuse_score: cached.abuseConfidenceScore ?? null,
          event_count: stats.event_count,
          blocked_count: stats.blocked_count,
          threat_count: stats.threat_count,
          lastSeen: stats.lastSeen,
        });
      }

      // Sort by event count then abuse score
      ips.sort((a, b) => b.event_count - a.event_count || (b.abuse_score || 0) - (a.abuse_score || 0));

      return {
        summary: {
          totalEnriched,
          withAbuseScore,
          highThreat,
          countries: countriesSet.size,
        },
        periodSummary: {
          enriched: ips.length,
          flagged: periodFlagged,
          highThreat: periodHighThreat,
          countries: periodCountries.size,
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
                  blocked: { filter: { terms: { network_action: ['block', 'drop'] } } },
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
                  blocked: { filter: { terms: { network_action: ['block', 'drop'] } } },
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

  /** Get all non-private cache entries with enrichment data */
  async _getAllCacheEntries() {
    try {
      const { body } = await this.client.search({
        index: this.cacheIndex,
        body: {
          size: 10000,
          query: {
            bool: {
              must_not: [{ term: { is_private: true } }],
              should: [
                { exists: { field: 'country' } },
                { exists: { field: 'abuseConfidenceScore' } },
              ],
              minimum_should_match: 1,
            },
          },
        },
      });
      return (body.hits?.hits || []).map(h => ({ ip: h._id, ...h._source }));
    } catch {
      return [];
    }
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
    const entries = await this._getAllCacheEntries();
    return entries.map(e => ({
      ip: e.ip,
      geo_country: e.country || null,
      geo_city: e.city || null,
      geo_lat: e.latitude ?? null,
      geo_lon: e.longitude ?? null,
      abuse_score: e.abuseConfidenceScore ?? null,
      hostname: e.hostname || null,
    }));
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

      return {
        ok,
        writePressure: clusterStatus === 'red' ? 'high' : 'normal',
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
    // Delete and recreate both indexes
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
  }

  // --- Settings (delegated to SQLite by storage manager) ---

  async getSetting() { throw new Error('Settings are managed by SQLite'); }
  async setSetting() { throw new Error('Settings are managed by SQLite'); }
  async getAllSettings() { throw new Error('Settings are managed by SQLite'); }
}

module.exports = OpenSearchBackend;
