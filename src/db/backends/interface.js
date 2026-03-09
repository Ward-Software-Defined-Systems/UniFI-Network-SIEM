/**
 * StorageBackend Interface
 * 
 * All storage backends must implement these methods.
 * The active backend is selected via Settings > Database Engine.
 */
class StorageBackend {
  constructor(name, config = {}) {
    this.name = name;
    this.config = config;
  }

  /** Initialize connection/resources. Called once on startup. */
  async initialize() {
    throw new Error(`${this.name}: initialize() not implemented`);
  }

  /** Graceful shutdown. Called on SIGINT/SIGTERM. */
  async close() {
    throw new Error(`${this.name}: close() not implemented`);
  }

  /** Check if backend is connected and healthy. Returns { ok: boolean, details: {} } */
  async healthCheck() {
    throw new Error(`${this.name}: healthCheck() not implemented`);
  }

  // --- Write Operations ---

  /** Insert a batch of event objects. Returns { inserted: number } */
  async insertEvents(events) {
    throw new Error(`${this.name}: insertEvents() not implemented`);
  }

  /** Update events matching an IP with enrichment data. Returns { updated: number } */
  async updateEnrichment(ip, direction, data, limit) {
    throw new Error(`${this.name}: updateEnrichment() not implemented`);
  }

  // --- Read Operations ---

  /** Query events with filters. Returns { events: [], total: number } */
  async queryEvents(filters) {
    throw new Error(`${this.name}: queryEvents() not implemented`);
  }

  /** Get a single event by ID. Returns event object or null. */
  async getEventById(id) {
    throw new Error(`${this.name}: getEventById() not implemented`);
  }

  /** Get total event count. Returns number. */
  async getEventCount() {
    throw new Error(`${this.name}: getEventCount() not implemented`);
  }

  /** Get event count for today. Returns number. */
  async getEventCountToday() {
    throw new Error(`${this.name}: getEventCountToday() not implemented`);
  }

  /** Get the most recent event timestamp. Returns ISO string or null. */
  async getLastEventTime() {
    throw new Error(`${this.name}: getLastEventTime() not implemented`);
  }

  /** Get event counts grouped by type, optionally since a timestamp. Returns { type: count } */
  async getEventTypeCounts(since) {
    throw new Error(`${this.name}: getEventTypeCounts() not implemented`);
  }

  // --- Stats / Aggregation ---

  /** Overview stats for a period. Returns { total, byType, firewall: { allowed, blocked, threats } } */
  async getOverviewStats(since) {
    throw new Error(`${this.name}: getOverviewStats() not implemented`);
  }

  /** Timeline buckets for charting. Returns [{ ts, ...counts }] */
  async getTimeline(since, bucketFormat, eventType) {
    throw new Error(`${this.name}: getTimeline() not implemented`);
  }

  /** Top talkers (source or dest). Returns [{ ip, count, lastSeen, country, hostname }] */
  async getTopTalkers(since, direction, limit, excludePrivate) {
    throw new Error(`${this.name}: getTopTalkers() not implemented`);
  }

  /** Top blocked IPs. Returns [{ ip, count, lastSeen, country, abuseScore, hostname }] */
  async getTopBlocked(since, direction, limit, excludePrivate) {
    throw new Error(`${this.name}: getTopBlocked() not implemented`);
  }

  /** Top destination ports. Returns [{ port, protocol, count }] */
  async getTopPorts(since, limit) {
    throw new Error(`${this.name}: getTopPorts() not implemented`);
  }

  /** Top clients by MAC. Returns [{ mac, alias, ip, eventCount, ... }] */
  async getTopClients(since, limit) {
    throw new Error(`${this.name}: getTopClients() not implemented`);
  }

  /** Top IDS/IPS threats. Returns [{ signature, classification, count, lastSeen }] */
  async getTopThreats(since, limit) {
    throw new Error(`${this.name}: getTopThreats() not implemented`);
  }

  /** Threat intel — enriched IPs with abuse scores. Returns { summary, periodSummary, ips } */
  async getThreatIntel(since, limit) {
    throw new Error(`${this.name}: getThreatIntel() not implemented`);
  }

  /** Geo-aggregated events for map view. Returns [{ ip, country, lat, lon, count, ... }] */
  async getGeoEvents(since, limit) {
    throw new Error(`${this.name}: getGeoEvents() not implemented`);
  }

  /** Recent individual events with geo data for live map. Returns [event] */
  async getRecentGeoEvents(limit) {
    throw new Error(`${this.name}: getRecentGeoEvents() not implemented`);
  }

  // --- Enrichment Cache ---

  /** Get cached enrichment for an IP. Returns cache row or null. */
  async getCachedEnrichment(ip) {
    throw new Error(`${this.name}: getCachedEnrichment() not implemented`);
  }

  /** Set/update cached enrichment for an IP. */
  async setCachedEnrichment(ip, data) {
    throw new Error(`${this.name}: setCachedEnrichment() not implemented`);
  }

  /** Mark an IP as private in the cache. */
  async markPrivate(ip) {
    throw new Error(`${this.name}: markPrivate() not implemented`);
  }

  /** Get all non-private cached IPs with enrichment data. Returns [{ ip, geo_country, ... }] */
  async getAllCachedEnrichment() {
    throw new Error(`${this.name}: getAllCachedEnrichment() not implemented`);
  }

  // --- Maintenance ---

  /** Delete events older than the given interval string. Returns { deleted: number } */
  async runRetention(days) {
    throw new Error(`${this.name}: runRetention() not implemented`);
  }

  /** Reset all event and enrichment data (keep settings). */
  async resetData() {
    throw new Error(`${this.name}: resetData() not implemented`);
  }

  // --- Settings ---

  /** Get a setting value. Returns parsed value or null. */
  async getSetting(key) {
    throw new Error(`${this.name}: getSetting() not implemented`);
  }

  /** Set a setting value. */
  async setSetting(key, value) {
    throw new Error(`${this.name}: setSetting() not implemented`);
  }

  /** Get all settings. Returns [{ key, value }] */
  async getAllSettings() {
    throw new Error(`${this.name}: getAllSettings() not implemented`);
  }
}

module.exports = StorageBackend;
