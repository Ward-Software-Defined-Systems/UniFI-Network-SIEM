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

    // If TLS with self-signed certs, disable Node's cert verification
    if (config.useTls && !this.verifyCerts) {
      this.agent = new (require('https').Agent)({ rejectUnauthorized: false });
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

  async _request(method, path, body = null) {
    const url = `${this.baseUrl}${path}`;
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (this.agent) opts.agent = this.agent;
    if (this.apiKey) opts.headers['Authorization'] = `Bearer ${this.apiKey}`;
    if (body) opts.body = JSON.stringify(body);

    const resp = await fetch(url, opts);
    const json = await resp.json();

    if (!json.ok) {
      const code = json.error?.code || 'UNKNOWN';
      const msg = json.error?.message || 'Unknown error';
      // Don't throw on 404 for get operations — caller handles null
      if (resp.status === 404) return { _notFound: true, code, message: msg };
      throw new Error(`WardSONDB ${code}: ${msg}`);
    }

    return json;
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

    logger.info({ backend: 'wardsondb' }, 'Storage backend initialized');
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
    // HTTP client — nothing to close
  }

  async healthCheck() {
    try {
      const health = await this._get('/_health');
      const stats = await this._get('/_stats');
      return {
        ok: health.data.status === 'healthy',
        details: {
          backend: 'wardsondb',
          url: this.baseUrl,
          collections: stats.data.collection_count,
          totalDocuments: stats.data.total_documents,
          uptime: stats.data.uptime_seconds,
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
    // Phase 1: No aggregation — use multiple count queries
    const types = ['firewall', 'threat', 'dhcp', 'dns', 'dns_filter', 'wifi', 'admin', 'device', 'client', 'vpn', 'system'];
    const counts = {};

    await Promise.all(types.map(async (type) => {
      const filter = { event_type: type };
      if (since) filter.received_at = { '$gte': since };
      const result = await this._post(`/${this.eventsCollection}/query`, {
        filter,
        count_only: true,
      });
      const count = result.meta?.total_count || result.data?.count || 0;
      if (count > 0) counts[type] = count;
    }));

    return counts;
  }

  // --- Stats / Aggregation ---
  // Phase 1: Limited — no server-side aggregation available

  async getOverviewStats(since) {
    const [total, byType, allowed, blocked, threats] = await Promise.all([
      this._post(`/${this.eventsCollection}/query`, {
        filter: { received_at: { '$gte': since } },
        count_only: true,
      }),
      this.getEventTypeCounts(since),
      this._post(`/${this.eventsCollection}/query`, {
        filter: { '$and': [{ event_type: 'firewall' }, { 'network.action': 'allow' }, { received_at: { '$gte': since } }] },
        count_only: true,
      }),
      this._post(`/${this.eventsCollection}/query`, {
        filter: { '$and': [{ event_type: 'firewall' }, { 'network.action': 'block' }, { received_at: { '$gte': since } }] },
        count_only: true,
      }),
      this._post(`/${this.eventsCollection}/query`, {
        filter: { '$and': [{ event_type: 'threat' }, { received_at: { '$gte': since } }] },
        count_only: true,
      }),
    ]);

    return {
      total: total.meta?.total_count || total.data?.count || 0,
      byType,
      firewall: {
        allowed: allowed.meta?.total_count || allowed.data?.count || 0,
        blocked: blocked.meta?.total_count || blocked.data?.count || 0,
        threats: threats.meta?.total_count || threats.data?.count || 0,
      },
    };
  }

  // Phase 1 stubs — return empty results with a note
  async getTimeline() {
    logger.debug('WardSONDB: getTimeline() requires aggregation (Phase 2)');
    return [];
  }

  async getTopTalkers() {
    logger.debug('WardSONDB: getTopTalkers() requires aggregation (Phase 2)');
    return [];
  }

  async getTopBlocked() {
    logger.debug('WardSONDB: getTopBlocked() requires aggregation (Phase 2)');
    return [];
  }

  async getTopPorts() {
    logger.debug('WardSONDB: getTopPorts() requires aggregation (Phase 2)');
    return [];
  }

  async getTopClients() {
    logger.debug('WardSONDB: getTopClients() requires aggregation (Phase 2)');
    return [];
  }

  async getTopThreats() {
    logger.debug('WardSONDB: getTopThreats() requires aggregation (Phase 2)');
    return [];
  }

  async getThreatIntel() {
    logger.debug('WardSONDB: getThreatIntel() requires aggregation (Phase 2)');
    return { summary: { totalEnriched: 0, withAbuseScore: 0, highThreat: 0, countries: 0 }, periodSummary: { enriched: 0, flagged: 0, highThreat: 0, countries: 0 }, ips: [] };
  }

  async getGeoEvents() {
    logger.debug('WardSONDB: getGeoEvents() requires aggregation (Phase 2)');
    return [];
  }

  async getRecentGeoEvents(limit) {
    // This one we can partially support — get recent events with enrichment
    const result = await this._post(`/${this.eventsCollection}/query`, {
      filter: { 'enrichment.src.geo_lat': { '$exists': true } },
      sort: [{ '_created_at': 'desc' }],
      limit: Math.min(limit, 200),
    });
    return (result.data || []).map(d => this._documentToEvent(d));
  }

  // --- Enrichment Cache ---

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
