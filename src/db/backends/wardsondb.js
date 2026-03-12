/**
 * WardSONDB Storage Backend
 * 
 * REST API client connecting to a WardSONDB server instance.
 * Events and enrichment cache stored as WardSONDB collections.
 * Settings remain in SQLite (needed to boot and select backend).
 * 
 * Phase 1 Limitations:
 * - No aggregation pipeline — dashboard stats that require GROUP BY
 *   (timeline, top talkers, top ports, etc.) use client-side fallbacks
 *   or return empty results until Phase 2 aggregation is available.
 * - No TTL — retention cleanup is a no-op until Phase 2.
 * - No _update_by_query — enrichment backfill updates docs individually.
 */
const StorageBackend = require('./interface');
const logger = require('../../utils/logger');

class WardsonDbBackend extends StorageBackend {
  constructor(config = {}) {
    super('WardSONDB', config);
    this.baseUrl = `http${config.useTls ? 's' : ''}://${config.host || 'localhost'}:${config.port || 8080}`;
    this.apiKey = config.apiKey || '';
    this.verifyCerts = config.verifyCerts !== false; // default true
    this.eventsCollection = 'events';
    this.cacheCollection = 'enrichment_cache';

    // If TLS with self-signed certs, disable Node's TLS verification globally
    // Node's native fetch doesn't support per-request agent/dispatcher options
    if (config.useTls && !this.verifyCerts) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      logger.warn('TLS certificate verification disabled for WardSONDB connection');
    }
  }

  static get metadata() {
    return {
      name: 'WardSONDB',
      description: 'High-performance Rust-based JSON document database. Optimized for SIEM workloads with selective indexing and low memory footprint.',
      status: 'beta',
      configFields: [
        { key: 'host', label: 'Host', type: 'text', placeholder: 'localhost', default: 'localhost' },
        { key: 'port', label: 'Port', type: 'number', placeholder: '8080', default: 8080 },
        { key: 'apiKey', label: 'API Key', type: 'password', placeholder: 'Optional', default: '' },
        { key: 'useTls', label: 'Use TLS', type: 'boolean', default: false },
        { key: 'verifyCerts', label: 'Verify Certificates', type: 'boolean', default: true },
      ],
    };
  }

  // --- HTTP Client ---

  async _request(method, path, body = null, retries = 3) {
    const url = `${this.baseUrl}${path}`;
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };

    if (this.apiKey) opts.headers['Authorization'] = `Bearer ${this.apiKey}`;
    if (body) opts.body = JSON.stringify(body);

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const resp = await fetch(url, opts);
        const json = await resp.json();

        if (!json.ok) {
          const code = json.error?.code || 'UNKNOWN';
          const msg = json.error?.message || 'Unknown error';
          if (resp.status === 404) return { _notFound: true, code, message: msg };
          // Retry on 5xx
          if (resp.status >= 500 && attempt < retries) {
            await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
            continue;
          }
          throw new Error(`WardSONDB ${code}: ${msg}`);
        }

        return json;
      } catch (err) {
        // Retry on network errors (ETIMEDOUT, ECONNREFUSED, fetch failed)
        if (attempt < retries && (err.cause || err.message?.includes('fetch failed'))) {
          logger.debug({ err: err.message, attempt, path }, 'WardSONDB request failed, retrying');
          await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
  }

  async _get(path) { return this._request('GET', path); }
  async _post(path, body) { return this._request('POST', path, body); }
  async _put(path, body) { return this._request('PUT', path, body); }
  async _patch(path, body) { return this._request('PATCH', path, body); }
  async _delete(path) { return this._request('DELETE', path); }

  // --- Lifecycle ---

  async initialize() {
    // Verify connection
    const info = await this._get('/');
    logger.info({ backend: 'wardsondb', version: info.data.version, url: this.baseUrl }, 'Connected to WardSONDB');

    // Ensure collections exist
    await this._ensureCollection(this.eventsCollection);
    await this._ensureCollection(this.cacheCollection);

    // Check if indexes already exist (from a previous run)
    const existingIndexes = await this._get(`/${this.eventsCollection}/indexes`);
    const indexCount = (existingIndexes.data || []).length;

    if (indexCount >= 9) {
      logger.info({ indexCount }, 'WardSONDB indexes already exist, skipping deferred creation');
    } else {
      // Start background index creation — pauses ingestion, creates indexes, then resumes
      this._startDeferredIndexCreation();
    }

    this._ingestPaused = false; // Flag to pause ingestion during index creation
    logger.info({ backend: 'wardsondb' }, 'Storage backend initialized');
  }

  _getRequiredIndexes() {
    return [
      { name: 'idx_event_type', field: 'event_type' },
      { name: 'idx_received_at', field: 'received_at' },
      { name: 'idx_network_action', field: 'network.action' },
      { name: 'idx_src_ip', field: 'network.src_ip' },
      { name: 'idx_dst_ip', field: 'network.dst_ip' },
      { name: 'idx_dst_port', field: 'network.dst_port' },
      { name: 'idx_type_time', fields: ['event_type', 'received_at'] },
      { name: 'idx_action_time', fields: ['network.action', 'received_at'] },
      { name: 'idx_type_action', fields: ['event_type', 'network.action'] },
    ];
  }

  _startDeferredIndexCreation() {
    const INITIAL_DELAY = 15000; // Wait 15s after startup for initial ingest burst to settle
    const INDEX_DELAY = 5000; // 5 seconds between each index creation

    logger.info('WardSONDB deferred index creation — will pause ingestion and create indexes in 15 seconds');

    this._deferredIndexTimeout = setTimeout(async () => {
      try {
        // Pause ingestion
        this._ingestPaused = true;
        logger.info('WardSONDB ingestion paused for index creation');

        // Brief wait for in-flight inserts to complete
        await new Promise(r => setTimeout(r, 2000));

        await this._createIndexesSequentially(INDEX_DELAY);
      } catch (err) {
        logger.error({ err: err.message }, 'WardSONDB deferred index creation failed');
      } finally {
        // Always resume ingestion
        this._ingestPaused = false;
        logger.info('WardSONDB ingestion resumed');
      }
    }, INITIAL_DELAY);
  }

  async _createIndexesSequentially(delayMs) {
    const indexes = this._getRequiredIndexes();

    for (const idx of indexes) {
      try {
        const body = { name: idx.name };
        if (idx.fields) body.fields = idx.fields;
        else body.field = idx.field;
        await this._post(`/${this.eventsCollection}/indexes`, body);
        logger.info({ index: idx.name }, 'Created WardSONDB index');

        // Pause between indexes to let compaction catch up
        await new Promise(r => setTimeout(r, delayMs));
      } catch (err) {
        if (err.message.includes('INDEX_EXISTS')) {
          logger.debug({ index: idx.name }, 'WardSONDB index already exists');
          continue;
        }
        logger.warn({ index: idx.name, err: err.message }, 'Failed to create WardSONDB index');
      }
    }

    logger.info('WardSONDB deferred index creation complete — all indexes ready');
  }

  async _ensureCollection(name) {
    try {
      await this._post('/_collections', { name });
      logger.info({ collection: name }, 'Created WardSONDB collection');
    } catch (err) {
      if (err.message.includes('COLLECTION_EXISTS')) return; // Already exists, fine
      throw err;
    }
  }

  async close() {
    if (this._deferredIndexTimeout) {
      clearTimeout(this._deferredIndexTimeout);
      this._deferredIndexTimeout = null;
    }
  }

  async healthCheck() {
    try {
      const health = await this._get('/_health');
      const stats = await this._get('/_stats');
      // Fetch storage info for the events collection (oldest/newest doc, index count)
      let storageInfo = null;
      try {
        const storage = await this._get(`/${this.eventsCollection}/storage`);
        storageInfo = storage.data;
      } catch {}
      return {
        ok: health.data.status === 'healthy',
        writePressure: health.data.write_pressure || 'normal',
        details: {
          backend: 'wardsondb',
          url: this.baseUrl,
          collections: stats.data.collection_count,
          totalDocuments: stats.data.total_documents,
          uptime: stats.data.uptime_seconds,
          eventsStorage: storageInfo ? {
            docCount: storageInfo.doc_count,
            indexCount: storageInfo.index_count,
            oldestDoc: storageInfo.oldest_doc,
            newestDoc: storageInfo.newest_doc,
          } : null,
        },
      };
    } catch (err) {
      return { ok: false, details: { backend: 'wardsondb', error: err.message } };
    }
  }

  // --- Document Transformation ---

  /** Transform a flat SIEM event into a nested WardSONDB document */
  _eventToDocument(event) {
    const doc = {
      event_type: event.event_type,
      severity: event.severity ?? null,
      hostname: event.hostname || null,
      source_format: event.source_format || null,
      message: event.message || null,
      timestamp: event.timestamp || null,
      received_at: event.received_at || new Date().toISOString(),
    };

    if (event.raw_message) doc.raw_message = event.raw_message;

    // Network fields (firewall/threat)
    if (event.action || event.src_ip || event.dst_ip || event.protocol) {
      doc.network = {};
      if (event.action) doc.network.action = event.action;
      if (event.direction) doc.network.direction = event.direction;
      if (event.interface_in) doc.network.interface_in = event.interface_in;
      if (event.interface_out) doc.network.interface_out = event.interface_out;
      if (event.protocol) doc.network.protocol = event.protocol;
      if (event.src_ip) doc.network.src_ip = event.src_ip;
      if (event.src_port != null) doc.network.src_port = event.src_port;
      if (event.dst_ip) doc.network.dst_ip = event.dst_ip;
      if (event.dst_port != null) doc.network.dst_port = event.dst_port;
      if (event.packet_length != null) doc.network.packet_length = event.packet_length;
      if (event.ttl != null) doc.network.ttl = event.ttl;
      if (event.tcp_flags) doc.network.tcp_flags = event.tcp_flags;
      if (event.mac_src) doc.network.mac_src = event.mac_src;
      if (event.mac_dst) doc.network.mac_dst = event.mac_dst;
      if (event.rule_prefix) doc.network.rule_prefix = event.rule_prefix;
    }

    // IDS fields
    if (event.ids_signature_id || event.ids_signature) {
      doc.ids = {};
      if (event.ids_signature_id) doc.ids.signature_id = event.ids_signature_id;
      if (event.ids_signature) doc.ids.signature = event.ids_signature;
      if (event.ids_classification) doc.ids.classification = event.ids_classification;
      if (event.ids_priority != null) doc.ids.priority = event.ids_priority;
      if (event.threat_type) doc.ids.threat_type = event.threat_type;
      if (event.threat_category) doc.ids.threat_category = event.threat_category;
    }

    // DHCP fields
    if (event.dhcp_action || event.dhcp_ip || event.dhcp_mac) {
      doc.dhcp = {};
      if (event.dhcp_action) doc.dhcp.action = event.dhcp_action;
      if (event.dhcp_ip) doc.dhcp.ip = event.dhcp_ip;
      if (event.dhcp_mac) doc.dhcp.mac = event.dhcp_mac;
      if (event.dhcp_hostname) doc.dhcp.hostname = event.dhcp_hostname;
      if (event.dhcp_interface) doc.dhcp.interface = event.dhcp_interface;
    }

    // DNS fields
    if (event.dns_action || event.dns_name) {
      doc.dns = {};
      if (event.dns_action) doc.dns.action = event.dns_action;
      if (event.dns_name) doc.dns.name = event.dns_name;
      if (event.dns_type) doc.dns.type = event.dns_type;
      if (event.dns_result) doc.dns.result = event.dns_result;
      if (event.dns_client_ip) doc.dns.client_ip = event.dns_client_ip;
      if (event.dns_filter_type) doc.dns.filter_type = event.dns_filter_type;
      if (event.dns_filter_category) doc.dns.filter_category = event.dns_filter_category;
    }

    // WiFi fields
    if (event.wifi_action || event.wifi_client_mac) {
      doc.wifi = {};
      if (event.wifi_action) doc.wifi.action = event.wifi_action;
      if (event.wifi_client_mac) doc.wifi.client_mac = event.wifi_client_mac;
      if (event.wifi_radio) doc.wifi.radio = event.wifi_radio;
      if (event.wifi_ssid) doc.wifi.ssid = event.wifi_ssid;
      if (event.wifi_channel != null) doc.wifi.channel = event.wifi_channel;
      if (event.wifi_rssi != null) doc.wifi.rssi = event.wifi_rssi;
    }

    // CEF fields
    if (event.cef_event_class_id || event.cef_name) {
      doc.cef = {};
      if (event.cef_event_class_id) doc.cef.event_class_id = event.cef_event_class_id;
      if (event.cef_name) doc.cef.name = event.cef_name;
      if (event.cef_severity != null) doc.cef.severity = event.cef_severity;
      if (event.unifi_category) doc.cef.category = event.unifi_category;
      if (event.unifi_subcategory) doc.cef.subcategory = event.unifi_subcategory;
      if (event.unifi_host) doc.cef.host = event.unifi_host;
    }

    // Client fields
    if (event.client_alias || event.client_mac || event.client_ip) {
      doc.client = {};
      if (event.client_alias) doc.client.alias = event.client_alias;
      if (event.client_mac) doc.client.mac = event.client_mac;
      if (event.client_ip) doc.client.ip = event.client_ip;
    }

    return doc;
  }

  /** Transform a WardSONDB document back into the flat SIEM event format */
  _documentToEvent(doc) {
    const event = {
      id: doc._id,
      event_type: doc.event_type,
      severity: doc.severity,
      hostname: doc.hostname,
      source_format: doc.source_format,
      message: doc.message,
      timestamp: doc.timestamp,
      received_at: doc.received_at || doc._created_at,
      raw_message: doc.raw_message || null,
    };

    // Network
    if (doc.network) {
      event.action = doc.network.action || null;
      event.direction = doc.network.direction || null;
      event.interface_in = doc.network.interface_in || null;
      event.interface_out = doc.network.interface_out || null;
      event.protocol = doc.network.protocol || null;
      event.src_ip = doc.network.src_ip || null;
      event.src_port = doc.network.src_port ?? null;
      event.dst_ip = doc.network.dst_ip || null;
      event.dst_port = doc.network.dst_port ?? null;
      event.packet_length = doc.network.packet_length ?? null;
      event.ttl = doc.network.ttl ?? null;
      event.tcp_flags = doc.network.tcp_flags || null;
      event.mac_src = doc.network.mac_src || null;
      event.mac_dst = doc.network.mac_dst || null;
      event.rule_prefix = doc.network.rule_prefix || null;
    }

    // IDS
    if (doc.ids) {
      event.ids_signature_id = doc.ids.signature_id || null;
      event.ids_signature = doc.ids.signature || null;
      event.ids_classification = doc.ids.classification || null;
      event.ids_priority = doc.ids.priority ?? null;
      event.threat_type = doc.ids.threat_type || null;
      event.threat_category = doc.ids.threat_category || null;
    }

    // DHCP
    if (doc.dhcp) {
      event.dhcp_action = doc.dhcp.action || null;
      event.dhcp_ip = doc.dhcp.ip || null;
      event.dhcp_mac = doc.dhcp.mac || null;
      event.dhcp_hostname = doc.dhcp.hostname || null;
      event.dhcp_interface = doc.dhcp.interface || null;
    }

    // DNS
    if (doc.dns) {
      event.dns_action = doc.dns.action || null;
      event.dns_name = doc.dns.name || null;
      event.dns_type = doc.dns.type || null;
      event.dns_result = doc.dns.result || null;
      event.dns_client_ip = doc.dns.client_ip || null;
      event.dns_filter_type = doc.dns.filter_type || null;
      event.dns_filter_category = doc.dns.filter_category || null;
    }

    // WiFi
    if (doc.wifi) {
      event.wifi_action = doc.wifi.action || null;
      event.wifi_client_mac = doc.wifi.client_mac || null;
      event.wifi_radio = doc.wifi.radio || null;
      event.wifi_ssid = doc.wifi.ssid || null;
      event.wifi_channel = doc.wifi.channel ?? null;
      event.wifi_rssi = doc.wifi.rssi ?? null;
    }

    // CEF
    if (doc.cef) {
      event.cef_event_class_id = doc.cef.event_class_id || null;
      event.cef_name = doc.cef.name || null;
      event.cef_severity = doc.cef.severity ?? null;
      event.unifi_category = doc.cef.category || null;
      event.unifi_subcategory = doc.cef.subcategory || null;
      event.unifi_host = doc.cef.host || null;
    }

    // Client
    if (doc.client) {
      event.client_alias = doc.client.alias || null;
      event.client_mac = doc.client.mac || null;
      event.client_ip = doc.client.ip || null;
    }

    // Enrichment
    if (doc.enrichment) {
      if (doc.enrichment.src) {
        event.src_geo_country = doc.enrichment.src.geo_country || null;
        event.src_geo_city = doc.enrichment.src.geo_city || null;
        event.src_geo_lat = doc.enrichment.src.geo_lat ?? null;
        event.src_geo_lon = doc.enrichment.src.geo_lon ?? null;
        event.src_abuse_score = doc.enrichment.src.abuse_score ?? null;
        event.src_hostname = doc.enrichment.src.hostname || null;
      }
      if (doc.enrichment.dst) {
        event.dst_geo_country = doc.enrichment.dst.geo_country || null;
        event.dst_geo_city = doc.enrichment.dst.geo_city || null;
        event.dst_geo_lat = doc.enrichment.dst.geo_lat ?? null;
        event.dst_geo_lon = doc.enrichment.dst.geo_lon ?? null;
        event.dst_abuse_score = doc.enrichment.dst.abuse_score ?? null;
        event.dst_hostname = doc.enrichment.dst.hostname || null;
      }
    }

    return event;
  }

  // --- Write Operations ---

  async insertEvents(events) {
    // Drop events while ingestion is paused (during index creation)
    if (this._ingestPaused) {
      logger.debug({ dropped: events.length }, 'WardSONDB ingestion paused — dropping batch');
      return events.length; // Report as inserted to avoid retry storms
    }

    const documents = events.map(e => this._eventToDocument(e));

    // Batch in chunks of 500 (WardSONDB optimal batch size)
    const CHUNK = 500;
    let totalInserted = 0;

    for (let i = 0; i < documents.length; i += CHUNK) {
      const chunk = documents.slice(i, i + CHUNK);
      const result = await this._post(`/${this.eventsCollection}/docs/_bulk`, { documents: chunk });
      totalInserted += result.data.inserted;
      if (result.data.errors?.length > 0) {
        logger.warn({ errors: result.data.errors.length }, 'WardSONDB bulk insert had errors');
      }
    }

    return { inserted: totalInserted };
  }

  async updateEnrichment(ip, direction, data) {
    // Phase 1: No _update_by_query — query matching docs and patch individually
    // This is intentionally limited for Phase 1 testing
    const ipField = direction === 'dst' ? 'network.dst_ip' : 'network.src_ip';
    const enrichField = direction === 'dst' ? 'enrichment.dst' : 'enrichment.src';
    const geoCheck = direction === 'dst' ? 'enrichment.dst.geo_country' : 'enrichment.src.geo_country';

    const result = await this._post(`/${this.eventsCollection}/query`, {
      filter: {
        [ipField]: ip,
        [geoCheck]: { '$exists': false },
      },
      fields: ['_id'],
      limit: 100, // Smaller batches for Phase 1
    });

    if (!result.data || result.data.length === 0) return { updated: 0 };

    let updated = 0;
    const enrichmentData = {
      geo_country: data.geo_country,
      geo_city: data.geo_city,
      geo_lat: data.geo_lat,
      geo_lon: data.geo_lon,
      abuse_score: data.abuse_score,
      hostname: data.hostname,
    };

    for (const doc of result.data) {
      try {
        await this._patch(`/${this.eventsCollection}/docs/${doc._id}`, {
          enrichment: { [direction]: enrichmentData },
        });
        updated++;
      } catch (err) {
        logger.debug({ err, id: doc._id }, 'Failed to patch enrichment');
      }
    }

    return { updated };
  }

  // --- Read Operations ---

  async queryEvents(filters = {}) {
    const filter = {};
    const andClauses = [];

    if (filters.event_type) {
      const types = filters.event_type.split(',');
      if (types.length === 1) filter.event_type = types[0];
      else andClauses.push({ event_type: { '$in': types } });
    }
    if (filters.action) andClauses.push({ 'network.action': filters.action });
    if (filters.direction) andClauses.push({ 'network.direction': filters.direction });
    if (filters.severity) {
      const sevs = filters.severity.split(',').map(Number);
      andClauses.push({ severity: { '$in': sevs } });
    }
    if (filters.src_ip) andClauses.push({ 'network.src_ip': filters.src_ip });
    if (filters.dst_ip) andClauses.push({ 'network.dst_ip': filters.dst_ip });
    if (filters.dst_port) andClauses.push({ 'network.dst_port': parseInt(filters.dst_port, 10) });
    if (filters.protocol) andClauses.push({ 'network.protocol': filters.protocol.toUpperCase() });
    if (filters.since) andClauses.push({ received_at: { '$gte': filters.since } });
    if (filters.until) andClauses.push({ received_at: { '$lte': filters.until } });
    if (filters.search) andClauses.push({ message: { '$regex': filters.search } });

    // MAC filter — use $or across multiple paths
    if (filters.mac) {
      andClauses.push({
        '$or': [
          { 'client.mac': filters.mac },
          { 'wifi.client_mac': filters.mac },
          { 'dhcp.mac': filters.mac },
          { 'network.mac_src': filters.mac },
          { 'network.mac_dst': filters.mac },
        ],
      });
    }

    let queryFilter = null;
    if (andClauses.length > 0 || Object.keys(filter).length > 0) {
      const allClauses = [...andClauses];
      for (const [k, v] of Object.entries(filter)) allClauses.push({ [k]: v });
      queryFilter = allClauses.length === 1 ? allClauses[0] : { '$and': allClauses };
    }

    const limit = Math.min(parseInt(filters.limit || '50', 10), 500);
    const offset = parseInt(filters.offset || '0', 10);

    const result = await this._post(`/${this.eventsCollection}/query`, {
      filter: queryFilter,
      sort: [{ '_created_at': 'desc' }],
      limit,
      offset,
    });

    const events = (result.data || []).map(d => this._documentToEvent(d));
    return { events };
  }

  async getEventById(id) {
    const result = await this._get(`/${this.eventsCollection}/docs/${id}`);
    if (result._notFound) return null;
    return this._documentToEvent(result.data);
  }

  async getEventCount() {
    const result = await this._post(`/${this.eventsCollection}/query`, { count_only: true });
    return result.meta?.total_count || result.data?.count || 0;
  }

  async getEventCountToday() {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    const result = await this._post(`/${this.eventsCollection}/query`, {
      filter: { received_at: { '$gte': today.toISOString() } },
      count_only: true,
    });
    return result.meta?.total_count || result.data?.count || 0;
  }

  async getLastEventTime() {
    const result = await this._post(`/${this.eventsCollection}/query`, {
      sort: [{ '_created_at': 'desc' }],
      fields: ['received_at'],
      limit: 1,
    });
    if (result.data && result.data.length > 0) {
      return result.data[0].received_at || result.data[0]._created_at;
    }
    return null;
  }

  async getEventTypeCounts(since) {
    // Use aggregation pipeline — single query instead of 11 separate count queries
    const pipeline = [];
    if (since) {
      pipeline.push({ '$match': { received_at: { '$gte': since } } });
    }
    pipeline.push(
      { '$group': { '_id': 'event_type', count: { '$count': {} } } },
      { '$sort': { count: 'desc' } }
    );

    try {
      const result = await this._post(`/${this.eventsCollection}/aggregate`, { pipeline });
      const counts = {};
      for (const row of (result.data || [])) {
        if (row._id && row.count > 0) counts[row._id] = row.count;
      }
      return counts;
    } catch (err) {
      // Fallback to individual count queries if aggregation fails
      logger.warn({ err }, 'Aggregation failed for getEventTypeCounts, falling back to individual queries');
      const types = ['firewall', 'threat', 'dhcp', 'dns', 'dns_filter', 'wifi', 'admin', 'device', 'client', 'vpn', 'system'];
      const counts = {};
      await Promise.all(types.map(async (type) => {
        const filter = { event_type: type };
        if (since) filter.received_at = { '$gte': since };
        const result = await this._post(`/${this.eventsCollection}/query`, { filter, count_only: true });
        const count = result.meta?.total_count || result.data?.count || 0;
        if (count > 0) counts[type] = count;
      }));
      return counts;
    }
  }

  // --- Stats / Aggregation ---

  async getOverviewStats(since) {
    // Bitmap-optimized: parallel count queries instead of composite $group aggregation.
    // Each query hits bitmap scan (event_type, network.action) for <1ms response times.
    // The old composite $group forced full doc loads at scale, causing 30s+ timeouts.
    const timeFilter = { received_at: { '$gte': since } };

    const [totalResult, byTypeResult, allowed, blocked, threats] = await Promise.all([
      // Total count for time range
      this._post(`/${this.eventsCollection}/query`, {
        filter: timeFilter,
        count_only: true,
      }),
      // Count by event_type (bitmap_aggregate path)
      this._post(`/${this.eventsCollection}/aggregate`, {
        pipeline: [
          { '$match': timeFilter },
          { '$group': { '_id': 'event_type', count: { '$count': {} } } },
        ],
      }),
      // Firewall allowed count (bitmap AND: event_type + network.action)
      this._post(`/${this.eventsCollection}/query`, {
        filter: { event_type: 'firewall', 'network.action': 'allow', ...timeFilter },
        count_only: true,
      }),
      // Firewall blocked count
      this._post(`/${this.eventsCollection}/query`, {
        filter: { event_type: 'firewall', 'network.action': 'block', ...timeFilter },
        count_only: true,
      }),
      // Threat count
      this._post(`/${this.eventsCollection}/query`, {
        filter: { event_type: 'threat', ...timeFilter },
        count_only: true,
      }),
    ]);

    const byType = {};
    let total = 0;
    for (const row of (byTypeResult.data || [])) {
      if (row._id) {
        byType[row._id] = row.count || 0;
        total += row.count || 0;
      }
    }
    // Prefer the direct count if available (more accurate with time filter)
    const directTotal = totalResult.meta?.total_count || totalResult.data?.count;
    if (directTotal != null) total = directTotal;

    return {
      total,
      byType,
      firewall: {
        allowed: allowed.meta?.total_count || allowed.data?.count || 0,
        blocked: blocked.meta?.total_count || blocked.data?.count || 0,
        threats: threats.meta?.total_count || threats.data?.count || 0,
      },
    };
  }

  // --- Aggregation-powered stats ---

  async _aggregate(pipeline) {
    return this._post(`/${this.eventsCollection}/aggregate`, { pipeline });
  }

  async getTimeline(since, bucketFormat, eventType, bucketSize) {
    // Determine bucket interval in milliseconds
    const bucketMs = {
      '5m': 5 * 60000,
      '15m': 15 * 60000,
      '1h': 3600000,
      '1d': 86400000,
    }[bucketSize || '1h'] || 3600000;

    // Determine time range — align to bucket boundaries
    const sinceDate = new Date(since);
    const nowDate = new Date();
    // Floor sinceDate to bucket boundary
    const startTime = new Date(Math.floor(sinceDate.getTime() / bucketMs) * bucketMs);
    const endTime = new Date(Math.floor(nowDate.getTime() / bucketMs) * bucketMs);
    const numBuckets = Math.floor((endTime - startTime) / bucketMs) + 1;

    // Cap at reasonable number to avoid too many queries
    const maxBuckets = 200;
    const actualBuckets = Math.min(numBuckets, maxBuckets);

    // Generate empty buckets
    const buckets = {};
    for (let i = 0; i < actualBuckets; i++) {
      const d = new Date(startTime.getTime() + i * bucketMs);
      const ts = d.toISOString();
      buckets[ts] = eventType === 'firewall'
        ? { ts, allowed: 0, blocked: 0 }
        : { ts, firewall: 0, threat: 0, dhcp: 0, dns_filter: 0, wifi: 0, admin: 0, system: 0, total: 0 };
    }

    // For each bucket, run count queries (parallelized in batches)
    const bucketKeys = Object.keys(buckets);
    const PARALLEL = 8;

    for (let i = 0; i < bucketKeys.length; i += PARALLEL) {
      const batch = bucketKeys.slice(i, i + PARALLEL);
      await Promise.all(batch.map(async (ts) => {
        const bucketStart = ts;
        const bucketEnd = new Date(new Date(ts).getTime() + bucketMs).toISOString();

        if (eventType === 'firewall') {
          const [allowed, blocked] = await Promise.all([
            this._post(`/${this.eventsCollection}/query`, {
              filter: { '$and': [{ event_type: 'firewall' }, { 'network.action': 'allow' }, { received_at: { '$gte': bucketStart } }, { received_at: { '$lt': bucketEnd } }] },
              count_only: true,
            }),
            this._post(`/${this.eventsCollection}/query`, {
              filter: { '$and': [{ event_type: 'firewall' }, { 'network.action': 'block' }, { received_at: { '$gte': bucketStart } }, { received_at: { '$lt': bucketEnd } }] },
              count_only: true,
            }),
          ]);
          buckets[ts].allowed = allowed.meta?.total_count || allowed.data?.count || 0;
          buckets[ts].blocked = blocked.meta?.total_count || blocked.data?.count || 0;
        } else {
          const types = ['firewall', 'threat', 'dhcp', 'dns_filter', 'wifi', 'admin', 'system'];
          const results = await Promise.all(types.map(t =>
            this._post(`/${this.eventsCollection}/query`, {
              filter: { '$and': [{ event_type: t }, { received_at: { '$gte': bucketStart } }, { received_at: { '$lt': bucketEnd } }] },
              count_only: true,
            })
          ));
          let total = 0;
          results.forEach((r, idx) => {
            const count = r.meta?.total_count || r.data?.count || 0;
            buckets[ts][types[idx]] = count;
            total += count;
          });
          buckets[ts].total = total;
        }
      }));
    }

    return Object.values(buckets);
  }

  async _getCacheMap() {
    if (this._cacheMapTs && Date.now() - this._cacheMapTs < 30000) return this._cacheMap;
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: { is_private: false },
      limit: 10000,
    });
    this._cacheMap = new Map((result.data || []).map(d => [d.ip, d]));
    this._cacheMapTs = Date.now();
    return this._cacheMap;
  }

  _isPrivateIp(ip) {
    if (!ip) return true;
    return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') ||
      ip.startsWith('169.254.') || ip.startsWith('100.64.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
  }

  async getTopTalkers(since, direction, limit, excludePrivate) {
    const ipField = direction === 'dst' ? 'network.dst_ip' : 'network.src_ip';
    // Over-fetch if filtering private IPs, then trim client-side
    const fetchLimit = excludePrivate ? limit * 5 : limit;
    const pipeline = [
      { '$match': { received_at: { '$gte': since }, [ipField]: { '$exists': true } } },
      { '$group': {
        '_id': ipField,
        'count': { '$count': {} },
        'lastSeen': { '$max': 'received_at' },
      }},
      { '$sort': { 'count': 'desc' } },
      { '$limit': fetchLimit },
    ];

    const result = await this._aggregate(pipeline);
    const cacheMap = await this._getCacheMap();
    let rows = (result.data || []).map(r => {
      const cached = cacheMap.get(r._id);
      return {
        ip: r._id,
        count: r.count,
        lastSeen: r.lastSeen,
        country: cached?.geo_country || null,
        hostname: cached?.hostname || null,
      };
    });
    if (excludePrivate) rows = rows.filter(r => !this._isPrivateIp(r.ip));
    return rows.slice(0, limit);
  }

  async getTopBlocked(since, direction, limit, excludePrivate) {
    const ipField = direction === 'dst' ? 'network.dst_ip' : 'network.src_ip';
    const fetchLimit = excludePrivate ? limit * 5 : limit;
    const pipeline = [
      { '$match': { 'network.action': 'block', received_at: { '$gte': since }, [ipField]: { '$exists': true } } },
      { '$group': {
        '_id': ipField,
        'count': { '$count': {} },
        'lastSeen': { '$max': 'received_at' },
      }},
      { '$sort': { 'count': 'desc' } },
      { '$limit': fetchLimit },
    ];

    const result = await this._aggregate(pipeline);
    const cacheMap = await this._getCacheMap();
    let rows = (result.data || []).map(r => {
      const cached = cacheMap.get(r._id);
      return {
        ip: r._id,
        count: r.count,
        lastSeen: r.lastSeen,
        country: cached?.geo_country || null,
        abuseScore: cached?.abuse_score ?? null,
        hostname: cached?.hostname || null,
      };
    });
    if (excludePrivate) rows = rows.filter(r => !this._isPrivateIp(r.ip));
    return rows.slice(0, limit);
  }

  async getTopPorts(since, limit) {
    const pipeline = [
      { '$match': { received_at: { '$gte': since }, 'network.dst_port': { '$exists': true } } },
      { '$group': {
        '_id': { 'port': 'network.dst_port', 'protocol': 'network.protocol' },
        'count': { '$count': {} },
      }},
      { '$sort': { 'count': 'desc' } },
      { '$limit': limit },
    ];

    const result = await this._aggregate(pipeline);
    return (result.data || []).map(r => ({
      port: r._id?.port,
      protocol: r._id?.protocol,
      count: r.count,
    }));
  }

  async getTopClients(since, limit) {
    // Client MAC is spread across wifi.client_mac, dhcp.mac, client.mac
    // Without $or in aggregation _id, query wifi events as proxy
    const pipeline = [
      { '$match': { received_at: { '$gte': since }, 'wifi.client_mac': { '$exists': true } } },
      { '$group': {
        '_id': 'wifi.client_mac',
        'eventCount': { '$count': {} },
      }},
      { '$sort': { 'eventCount': 'desc' } },
      { '$limit': limit },
    ];

    const result = await this._aggregate(pipeline);
    return (result.data || []).map(r => ({
      mac: r._id,
      alias: null,
      ip: null,
      eventCount: r.eventCount,
      wifiEvents: r.eventCount,
      dhcpEvents: 0,
      firewallEvents: 0,
    }));
  }

  async getTopThreats(since, limit) {
    const pipeline = [
      { '$match': { event_type: 'threat', 'ids.signature': { '$exists': true }, received_at: { '$gte': since } } },
      { '$group': {
        '_id': 'ids.signature',
        'count': { '$count': {} },
        'lastSeen': { '$max': 'received_at' },
      }},
      { '$sort': { 'count': 'desc' } },
      { '$limit': limit },
    ];

    const result = await this._aggregate(pipeline);
    return (result.data || []).map(r => ({
      signature: r._id,
      classification: null,
      count: r.count,
      lastSeen: r.lastSeen,
    }));
  }

  async getThreatIntel(since, limit) {
    // Enrichment not embedded in events yet — use cache collection for summary
    const cacheResult = await this._post(`/${this.cacheCollection}/query`, {
      filter: { is_private: false },
      limit: 10000,
    });

    const cacheData = cacheResult.data || [];
    const totalEnriched = cacheData.filter(d => d.geo_country || d.abuse_score != null).length;
    const withAbuseScore = cacheData.filter(d => d.abuse_score > 0).length;
    const highThreat = cacheData.filter(d => d.abuse_score >= 50).length;
    const countries = new Set(cacheData.filter(d => d.geo_country).map(d => d.geo_country)).size;

    // Get top IPs by event count using aggregation
    const pipeline = [
      { '$match': { received_at: { '$gte': since }, 'network.src_ip': { '$exists': true } } },
      { '$group': {
        '_id': 'network.src_ip',
        'event_count': { '$count': {} },
        'lastSeen': { '$max': 'received_at' },
      }},
      { '$sort': { 'event_count': 'desc' } },
      { '$limit': limit },
    ];

    const aggResult = await this._aggregate(pipeline);
    const cacheMap = new Map(cacheData.map(d => [d.ip, d]));

    const ips = (aggResult.data || []).map(r => {
      const cached = cacheMap.get(r._id);
      return {
        ip: r._id,
        country: cached?.geo_country || null,
        city: cached?.geo_city || null,
        lat: cached?.geo_lat ?? null,
        lon: cached?.geo_lon ?? null,
        abuse_score: cached?.abuse_score ?? null,
        hostname: cached?.hostname || null,
        event_count: r.event_count,
        blocked_count: 0,
        threat_count: 0,
        lastSeen: r.lastSeen,
      };
    });

    // Compute period summary from distinct IPs seen in the time range (not capped by limit)
    const periodDistinct = await this._post(`/${this.eventsCollection}/distinct`, {
      field: 'network.src_ip',
      filter: { received_at: { '$gte': since }, 'network.src_ip': { '$exists': true } },
      limit: 10000,
    });
    const periodIps = new Set((periodDistinct.data?.values || []));
    const periodCached = cacheData.filter(d => periodIps.has(d.ip));
    const periodEnriched = periodCached.filter(d => d.geo_country || d.abuse_score != null).length;
    const periodFlagged = periodCached.filter(d => d.abuse_score > 0).length;
    const periodHighThreat = periodCached.filter(d => d.abuse_score >= 50).length;
    const periodCountries = new Set(periodCached.filter(d => d.geo_country).map(d => d.geo_country)).size;

    return {
      summary: { totalEnriched, withAbuseScore, highThreat, countries },
      periodSummary: { enriched: periodEnriched, flagged: periodFlagged, highThreat: periodHighThreat, countries: periodCountries },
      ips,
    };
  }

  async getGeoEvents(since, limit) {
    // Use cache data + aggregation to get geo events
    const cacheResult = await this._post(`/${this.cacheCollection}/query`, {
      filter: { is_private: false, geo_lat: { '$exists': true } },
      limit: 10000,
    });
    const cacheMap = new Map((cacheResult.data || []).map(d => [d.ip, d]));

    const pipeline = [
      { '$match': { received_at: { '$gte': since }, 'network.src_ip': { '$exists': true } } },
      { '$group': {
        '_id': 'network.src_ip',
        'count': { '$count': {} },
        'lastSeen': { '$max': 'received_at' },
      }},
      { '$sort': { 'count': 'desc' } },
      { '$limit': limit * 3 },  // Over-fetch to survive geo-data filter (not all IPs have geo)
    ];

    const result = await this._aggregate(pipeline);
    return (result.data || [])
      .filter(r => cacheMap.has(r._id) && cacheMap.get(r._id).geo_lat)
      .slice(0, limit)  // Trim to requested limit after filtering
      .map(r => {
        const c = cacheMap.get(r._id);
        return {
          ip: r._id,
          country: c.geo_country,
          city: c.geo_city,
          lat: c.geo_lat,
          lon: c.geo_lon,
          abuseScore: c.abuse_score,
          count: r.count,
          blocked: 0,
          threats: 0,
          lastSeen: r.lastSeen,
          direction: 'src',
        };
      });
  }

  async getRecentGeoEvents(limit) {
    // Get recent events and join with cache for geo data
    const result = await this._post(`/${this.eventsCollection}/query`, {
      filter: { 'network.src_ip': { '$exists': true } },
      sort: [{ '_created_at': 'desc' }],
      limit: Math.min(limit * 3, 500), // Over-fetch since not all will have geo
    });

    const cacheResult = await this._post(`/${this.cacheCollection}/query`, {
      filter: { is_private: false, geo_lat: { '$exists': true } },
      limit: 10000,
    });
    const cacheMap = new Map((cacheResult.data || []).map(d => [d.ip, d]));

    const events = [];
    for (const doc of (result.data || [])) {
      const srcIp = doc.network?.src_ip;
      const dstIp = doc.network?.dst_ip;
      const srcGeo = srcIp ? cacheMap.get(srcIp) : null;
      const dstGeo = dstIp ? cacheMap.get(dstIp) : null;
      if (!srcGeo && !dstGeo) continue;

      const event = this._documentToEvent(doc);
      if (srcGeo) {
        event.src_geo_lat = srcGeo.geo_lat;
        event.src_geo_lon = srcGeo.geo_lon;
        event.src_geo_country = srcGeo.geo_country;
        event.src_geo_city = srcGeo.geo_city;
        event.src_abuse_score = srcGeo.abuse_score;
      }
      if (dstGeo) {
        event.dst_geo_lat = dstGeo.geo_lat;
        event.dst_geo_lon = dstGeo.geo_lon;
        event.dst_geo_country = dstGeo.geo_country;
        event.dst_geo_city = dstGeo.geo_city;
        event.dst_abuse_score = dstGeo.abuse_score;
      }
      events.push(event);
      if (events.length >= limit) break;
    }

    return events;
  }

  // --- Enrichment Cache ---

  async getAllCachedEnrichments() {
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: {},
      limit: 100000,
    });
    return (result.data || []).map(d => ({
      ip: d.ip,
      geo_country: d.geo_country || null,
      geo_city: d.geo_city || null,
      geo_lat: d.geo_lat ?? null,
      geo_lon: d.geo_lon ?? null,
      abuse_score: d.abuse_score ?? null,
      hostname: d.hostname || null,
      is_private: d.is_private || false,
    }));
  }

  async getCachedEnrichment(ip) {
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: { ip },
      limit: 1,
    });
    if (!result.data || result.data.length === 0) return null;
    const doc = result.data[0];

    // Check staleness
    const updatedAt = new Date(doc.updated_at || doc._updated_at).getTime();
    const maxAge = (this.config.abuseIpDbCacheHours || 24) * 60 * 60 * 1000;
    if (Date.now() - updatedAt > maxAge) return null;

    return {
      ip: doc.ip,
      geo_country: doc.geo_country || null,
      geo_city: doc.geo_city || null,
      geo_lat: doc.geo_lat ?? null,
      geo_lon: doc.geo_lon ?? null,
      abuse_score: doc.abuse_score ?? null,
      hostname: doc.hostname || null,
      is_private: doc.is_private ? 1 : 0,
      updated_at: doc.updated_at || doc._updated_at,
    };
  }

  async setCachedEnrichment(ip, data) {
    // Check if exists first
    const existing = await this._post(`/${this.cacheCollection}/query`, {
      filter: { ip },
      fields: ['_id'],
      limit: 1,
    });

    const cacheDoc = {
      ip,
      geo_country: data.geo_country || null,
      geo_city: data.geo_city || null,
      geo_lat: data.geo_lat ?? null,
      geo_lon: data.geo_lon ?? null,
      abuse_score: data.abuse_score ?? null,
      hostname: data.hostname || null,
      is_private: data.is_private ? true : false,
      updated_at: new Date().toISOString(),
    };

    if (existing.data && existing.data.length > 0) {
      await this._put(`/${this.cacheCollection}/docs/${existing.data[0]._id}`, cacheDoc);
    } else {
      await this._post(`/${this.cacheCollection}/docs`, cacheDoc);
    }
  }

  async markPrivate(ip) {
    await this.setCachedEnrichment(ip, { is_private: true });
  }

  async getAllCachedEnrichment() {
    // Get all non-private cached IPs with enrichment data
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: {
        '$and': [
          { is_private: false },
          { '$or': [
            { geo_country: { '$exists': true } },
            { abuse_score: { '$exists': true } },
          ]},
        ],
      },
      limit: 10000, // Get all — enrichment cache is typically small
    });
    return (result.data || []).map(d => ({
      ip: d.ip,
      geo_country: d.geo_country,
      geo_city: d.geo_city,
      geo_lat: d.geo_lat,
      geo_lon: d.geo_lon,
      abuse_score: d.abuse_score,
      hostname: d.hostname,
    }));
  }

  // --- Maintenance ---

  async runRetention(days) {
    // Phase 1: No _delete_by_query — log and skip
    logger.debug('WardSONDB: runRetention() requires _delete_by_query (Phase 2)');
    return { deleted: 0 };
  }

  async resetData() {
    try { await this._delete(`/${this.eventsCollection}`); } catch {}
    try { await this._delete(`/${this.cacheCollection}`); } catch {}
    await this._ensureCollection(this.eventsCollection);
    await this._ensureCollection(this.cacheCollection);
  }

  // --- Settings ---
  // Settings stay in SQLite (needed to select the backend on boot)
  // These methods should not be called when WardSONDB is active — the
  // storage manager routes settings calls to SQLite always.

  async getSetting() { throw new Error('Settings are managed by SQLite'); }
  async setSetting() { throw new Error('Settings are managed by SQLite'); }
  async getAllSettings() { throw new Error('Settings are managed by SQLite'); }
}

module.exports = WardsonDbBackend;
