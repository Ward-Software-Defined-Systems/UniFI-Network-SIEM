/**
 * SQLite Storage Backend
 * 
 * Wraps the existing better-sqlite3 implementation behind the StorageBackend interface.
 * This is the default, zero-dependency backend.
 */
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const StorageBackend = require('./interface');
const logger = require('../../utils/logger');

class SqliteBackend extends StorageBackend {
  constructor(config = {}) {
    super('SQLite', config);
    this.db = null;
    this.insertStmt = null;
    this.insertManyTxn = null;
  }

  async initialize() {
    const dbPath = path.resolve(this.config.path || './data/events.db');
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('cache_size = -128000');
    this.db.pragma('busy_timeout = 5000');

    this._initSchema();
    logger.info({ path: dbPath, backend: 'sqlite' }, 'Storage backend initialized');
  }

  async close() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async healthCheck() {
    try {
      const row = this.db.prepare('SELECT 1 as ok').get();
      const dbPath = path.resolve(this.config.path || './data/events.db');
      const stats = fs.statSync(dbPath);
      return {
        ok: row.ok === 1,
        details: {
          backend: 'sqlite',
          dbSizeMB: Math.round(stats.size / 1024 / 1024 * 100) / 100,
          walMode: this.db.pragma('journal_mode', { simple: true }) === 'wal',
        },
      };
    } catch (err) {
      return { ok: false, details: { error: err.message } };
    }
  }

  // --- Schema ---

  _initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        raw_message TEXT,
        event_type TEXT NOT NULL,
        severity INTEGER,
        hostname TEXT,
        source_format TEXT,
        message TEXT,
        action TEXT,
        direction TEXT,
        interface_in TEXT,
        interface_out TEXT,
        protocol TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER,
        packet_length INTEGER,
        ttl INTEGER,
        tcp_flags TEXT,
        mac_src TEXT,
        mac_dst TEXT,
        rule_prefix TEXT,
        ids_signature_id TEXT,
        ids_signature TEXT,
        ids_classification TEXT,
        ids_priority INTEGER,
        threat_type TEXT,
        threat_category TEXT,
        dhcp_action TEXT,
        dhcp_ip TEXT,
        dhcp_mac TEXT,
        dhcp_hostname TEXT,
        dhcp_interface TEXT,
        dns_action TEXT,
        dns_name TEXT,
        dns_type TEXT,
        dns_result TEXT,
        dns_client_ip TEXT,
        dns_filter_type TEXT,
        dns_filter_category TEXT,
        wifi_action TEXT,
        wifi_client_mac TEXT,
        wifi_radio TEXT,
        wifi_ssid TEXT,
        wifi_channel INTEGER,
        wifi_rssi INTEGER,
        cef_event_class_id TEXT,
        cef_name TEXT,
        cef_severity INTEGER,
        unifi_category TEXT,
        unifi_subcategory TEXT,
        unifi_host TEXT,
        client_alias TEXT,
        client_mac TEXT,
        client_ip TEXT,
        src_geo_country TEXT,
        src_geo_city TEXT,
        src_geo_lat REAL,
        src_geo_lon REAL,
        dst_geo_country TEXT,
        dst_geo_city TEXT,
        dst_geo_lat REAL,
        dst_geo_lon REAL,
        src_abuse_score INTEGER,
        dst_abuse_score INTEGER,
        src_hostname TEXT,
        dst_hostname TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
      CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
      CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
      CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);
      CREATE INDEX IF NOT EXISTS idx_events_src_unenriched ON events(src_ip) WHERE src_geo_country IS NULL;
      CREATE INDEX IF NOT EXISTS idx_events_dst_unenriched ON events(dst_ip) WHERE dst_geo_country IS NULL;
      CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port);
      CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
      CREATE INDEX IF NOT EXISTS idx_events_client_mac ON events(client_mac);
      CREATE INDEX IF NOT EXISTS idx_events_dhcp_mac ON events(dhcp_mac);
      CREATE INDEX IF NOT EXISTS idx_events_wifi_client_mac ON events(wifi_client_mac);

      CREATE TABLE IF NOT EXISTS ip_enrichment_cache (
        ip TEXT PRIMARY KEY,
        geo_country TEXT,
        geo_city TEXT,
        geo_lat REAL,
        geo_lon REAL,
        abuse_score INTEGER,
        hostname TEXT,
        is_private INTEGER DEFAULT 0,
        updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);
  }

  // --- Event Columns (for inserts) ---

  static get EVENT_COLUMNS() {
    return [
      'timestamp', 'received_at', 'raw_message', 'event_type', 'severity', 'hostname',
      'source_format', 'message', 'action', 'direction', 'interface_in', 'interface_out',
      'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'packet_length', 'ttl',
      'tcp_flags', 'mac_src', 'mac_dst', 'rule_prefix',
      'ids_signature_id', 'ids_signature', 'ids_classification', 'ids_priority',
      'threat_type', 'threat_category',
      'dhcp_action', 'dhcp_ip', 'dhcp_mac', 'dhcp_hostname', 'dhcp_interface',
      'dns_action', 'dns_name', 'dns_type', 'dns_result', 'dns_client_ip',
      'dns_filter_type', 'dns_filter_category',
      'wifi_action', 'wifi_client_mac', 'wifi_radio', 'wifi_ssid', 'wifi_channel', 'wifi_rssi',
      'cef_event_class_id', 'cef_name', 'cef_severity', 'unifi_category', 'unifi_subcategory',
      'unifi_host', 'client_alias', 'client_mac', 'client_ip',
    ];
  }

  _getInsertStmt() {
    if (this.insertStmt) return;
    const cols = SqliteBackend.EVENT_COLUMNS;
    const placeholders = cols.map(() => '?').join(', ');
    const sql = `INSERT INTO events (${cols.join(', ')}) VALUES (${placeholders})`;
    this.insertStmt = this.db.prepare(sql);
    this.insertManyTxn = this.db.transaction((events) => {
      for (const evt of events) {
        const values = cols.map(col => evt[col] ?? null);
        this.insertStmt.run(values);
      }
    });
  }

  // --- Write Operations ---

  async insertEvents(events) {
    this._getInsertStmt();
    this.insertManyTxn(events);
    return { inserted: events.length };
  }

  async updateEnrichment(ip, direction, data, limit = 1000) {
    const col = direction === 'dst' ? 'dst' : 'src';
    const result = this.db.prepare(`
      UPDATE events SET
        ${col}_geo_country = ?, ${col}_geo_city = ?, ${col}_geo_lat = ?, ${col}_geo_lon = ?,
        ${col}_abuse_score = ?, ${col}_hostname = ?
      WHERE rowid IN (
        SELECT rowid FROM events WHERE ${col}_ip = ? AND ${col}_geo_country IS NULL
        ORDER BY rowid DESC LIMIT ?
      )
    `).run(
      data.geo_country, data.geo_city, data.geo_lat, data.geo_lon,
      data.abuse_score, data.hostname,
      ip, limit,
    );
    return { updated: result.changes };
  }

  // --- Read Operations ---

  async queryEvents(filters = {}) {
    const conditions = [];
    const params = [];

    if (filters.event_type) {
      const types = filters.event_type.split(',');
      conditions.push(`event_type IN (${types.map(() => '?').join(',')})`);
      params.push(...types);
    }
    if (filters.action) { conditions.push('action = ?'); params.push(filters.action); }
    if (filters.direction) { conditions.push('direction = ?'); params.push(filters.direction); }
    if (filters.severity) {
      const sevs = filters.severity.split(',').map(Number);
      conditions.push(`severity IN (${sevs.map(() => '?').join(',')})`);
      params.push(...sevs);
    }
    if (filters.src_ip) { conditions.push('src_ip = ?'); params.push(filters.src_ip); }
    if (filters.dst_ip) { conditions.push('dst_ip = ?'); params.push(filters.dst_ip); }
    if (filters.dst_port) { conditions.push('dst_port = ?'); params.push(parseInt(filters.dst_port, 10)); }
    if (filters.protocol) { conditions.push('protocol = ?'); params.push(filters.protocol.toUpperCase()); }
    if (filters.mac) {
      conditions.push('(client_mac = ? OR wifi_client_mac = ? OR dhcp_mac = ? OR mac_src = ? OR mac_dst = ?)');
      params.push(filters.mac, filters.mac, filters.mac, filters.mac, filters.mac);
    }
    if (filters.since) { conditions.push('received_at >= ?'); params.push(filters.since); }
    if (filters.until) { conditions.push('received_at <= ?'); params.push(filters.until); }
    if (filters.search) {
      conditions.push('(message LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dns_name LIKE ? OR hostname LIKE ?)');
      const term = `%${filters.search}%`;
      params.push(term, term, term, term, term);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(parseInt(filters.limit || '50', 10), 500);
    const offset = parseInt(filters.offset || '0', 10);

    const sql = `SELECT * FROM events ${where} ORDER BY id DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    return { events: this.db.prepare(sql).all(...params) };
  }

  async getEventById(id) {
    return this.db.prepare('SELECT * FROM events WHERE id = ?').get(id) || null;
  }

  async getEventCount() {
    return this.db.prepare('SELECT COUNT(*) as count FROM events').get().count;
  }

  async getEventCountToday() {
    return this.db.prepare("SELECT COUNT(*) as count FROM events WHERE received_at >= date('now')").get().count;
  }

  async getLastEventTime() {
    const row = this.db.prepare('SELECT received_at FROM events ORDER BY id DESC LIMIT 1').get();
    return row ? row.received_at : null;
  }

  async getEventTypeCounts(since) {
    let sql = 'SELECT event_type, COUNT(*) as count FROM events';
    const params = [];
    if (since) { sql += ' WHERE received_at >= ?'; params.push(since); }
    sql += ' GROUP BY event_type';
    const rows = this.db.prepare(sql).all(...params);
    const counts = {};
    for (const row of rows) counts[row.event_type] = row.count;
    return counts;
  }

  // --- Stats / Aggregation ---

  _since(interval) {
    return this.db.prepare("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) as t").get(interval).t;
  }

  _privateIpFilter(col) {
    return `${col} NOT LIKE '10.%'
      AND ${col} NOT LIKE '192.168.%'
      AND ${col} NOT LIKE '172.16.%' AND ${col} NOT LIKE '172.17.%' AND ${col} NOT LIKE '172.18.%' AND ${col} NOT LIKE '172.19.%'
      AND ${col} NOT LIKE '172.2_.%' AND ${col} NOT LIKE '172.30.%' AND ${col} NOT LIKE '172.31.%'
      AND ${col} NOT LIKE '100.64.%' AND ${col} NOT LIKE '100.65.%' AND ${col} NOT LIKE '100.66.%' AND ${col} NOT LIKE '100.67.%'
      AND ${col} NOT LIKE '100.68.%' AND ${col} NOT LIKE '100.69.%' AND ${col} NOT LIKE '100.7_.%'
      AND ${col} NOT LIKE '100.8_.%' AND ${col} NOT LIKE '100.9_.%' AND ${col} NOT LIKE '100.1__.%'
      AND ${col} NOT LIKE '100.12_.%'
      AND ${col} NOT LIKE '127.%'
      AND ${col} NOT LIKE '169.254.%'`;
  }

  async getOverviewStats(since) {
    const total = this.db.prepare('SELECT COUNT(*) as c FROM events WHERE received_at >= ?').get(since).c;
    const byType = await this.getEventTypeCounts(since);
    const firewall = {
      allowed: this.db.prepare("SELECT COUNT(*) as c FROM events WHERE event_type='firewall' AND action='allow' AND received_at >= ?").get(since).c,
      blocked: this.db.prepare("SELECT COUNT(*) as c FROM events WHERE event_type='firewall' AND action='block' AND received_at >= ?").get(since).c,
      threats: this.db.prepare("SELECT COUNT(*) as c FROM events WHERE event_type='threat' AND received_at >= ?").get(since).c,
    };
    return { total, byType, firewall };
  }

  async getTimeline(since, bucketFormat, eventType) {
    let sql;
    if (eventType === 'firewall') {
      sql = `SELECT strftime('${bucketFormat}', received_at) as ts,
              SUM(CASE WHEN action='allow' THEN 1 ELSE 0 END) as allowed,
              SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked
             FROM events WHERE event_type='firewall' AND received_at >= ?
             GROUP BY ts ORDER BY ts`;
    } else {
      sql = `SELECT strftime('${bucketFormat}', received_at) as ts,
              SUM(CASE WHEN event_type='firewall' THEN 1 ELSE 0 END) as firewall,
              SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threat,
              SUM(CASE WHEN event_type='dhcp' THEN 1 ELSE 0 END) as dhcp,
              SUM(CASE WHEN event_type='dns_filter' THEN 1 ELSE 0 END) as dns_filter,
              SUM(CASE WHEN event_type='wifi' THEN 1 ELSE 0 END) as wifi,
              SUM(CASE WHEN event_type='admin' THEN 1 ELSE 0 END) as admin,
              SUM(CASE WHEN event_type='system' THEN 1 ELSE 0 END) as system,
              COUNT(*) as total
             FROM events WHERE received_at >= ?
             GROUP BY ts ORDER BY ts`;
    }
    return this.db.prepare(sql).all(since);
  }

  async getTopTalkers(since, direction, limit, excludePrivate) {
    const col = direction === 'dst' ? 'dst_ip' : 'src_ip';
    const geoCol = direction === 'dst' ? 'dst_geo_country' : 'src_geo_country';
    const hostCol = direction === 'dst' ? 'dst_hostname' : 'src_hostname';
    const privFilter = excludePrivate ? `AND ${this._privateIpFilter(col)}` : '';
    return this.db.prepare(`
      SELECT ${col} as ip, COUNT(*) as count, MAX(received_at) as lastSeen,
             ${geoCol} as country, ${hostCol} as hostname
      FROM events WHERE ${col} IS NOT NULL AND received_at >= ? ${privFilter}
      GROUP BY ${col} ORDER BY count DESC LIMIT ?
    `).all(since, limit);
  }

  async getTopBlocked(since, direction, limit, excludePrivate) {
    const col = direction === 'dst' ? 'dst_ip' : 'src_ip';
    const geoCol = direction === 'dst' ? 'dst_geo_country' : 'src_geo_country';
    const abuseCol = direction === 'dst' ? 'dst_abuse_score' : 'src_abuse_score';
    const hostCol = direction === 'dst' ? 'dst_hostname' : 'src_hostname';
    const privFilter = excludePrivate ? `AND ${this._privateIpFilter(col)}` : '';
    return this.db.prepare(`
      SELECT ${col} as ip, COUNT(*) as count, MAX(received_at) as lastSeen,
             ${geoCol} as country, ${abuseCol} as abuseScore, ${hostCol} as hostname
      FROM events WHERE action='block' AND ${col} IS NOT NULL AND received_at >= ? ${privFilter}
      GROUP BY ${col} ORDER BY count DESC LIMIT ?
    `).all(since, limit);
  }

  async getTopPorts(since, limit) {
    return this.db.prepare(`
      SELECT dst_port as port, protocol, COUNT(*) as count
      FROM events WHERE dst_port IS NOT NULL AND received_at >= ?
      GROUP BY dst_port, protocol ORDER BY count DESC LIMIT ?
    `).all(since, limit);
  }

  async getTopClients(since, limit) {
    return this.db.prepare(`
      SELECT
        COALESCE(client_mac, wifi_client_mac, dhcp_mac) as mac,
        MAX(client_alias) as alias,
        MAX(COALESCE(client_ip, dhcp_ip, src_ip)) as ip,
        COUNT(*) as eventCount,
        SUM(CASE WHEN event_type='wifi' THEN 1 ELSE 0 END) as wifiEvents,
        SUM(CASE WHEN event_type='dhcp' THEN 1 ELSE 0 END) as dhcpEvents,
        SUM(CASE WHEN event_type='firewall' THEN 1 ELSE 0 END) as firewallEvents
      FROM events
      WHERE COALESCE(client_mac, wifi_client_mac, dhcp_mac) IS NOT NULL AND received_at >= ?
      GROUP BY mac ORDER BY eventCount DESC LIMIT ?
    `).all(since, limit);
  }

  async getTopThreats(since, limit) {
    return this.db.prepare(`
      SELECT ids_signature as signature, ids_classification as classification,
             COUNT(*) as count, MAX(received_at) as lastSeen
      FROM events WHERE event_type='threat' AND ids_signature IS NOT NULL AND received_at >= ?
      GROUP BY ids_signature ORDER BY count DESC LIMIT ?
    `).all(since, limit);
  }

  async getThreatIntel(since, limit) {
    const rows = this.db.prepare(`
      SELECT ip, country, city, lat, lon, abuse_score, hostname,
        SUM(count) as event_count, SUM(blocked) as blocked_count,
        SUM(threats) as threat_count, MAX(lastSeen) as lastSeen
      FROM (
        SELECT src_ip as ip, src_geo_country as country, src_geo_city as city,
               src_geo_lat as lat, src_geo_lon as lon, src_abuse_score as abuse_score,
               src_hostname as hostname, COUNT(*) as count,
               SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
               SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threats,
               MAX(received_at) as lastSeen
        FROM events
        WHERE src_ip IS NOT NULL AND (src_geo_country IS NOT NULL OR src_abuse_score IS NOT NULL) AND received_at >= ?
        GROUP BY src_ip
        UNION ALL
        SELECT dst_ip, dst_geo_country, dst_geo_city, dst_geo_lat, dst_geo_lon, dst_abuse_score,
               dst_hostname, COUNT(*),
               SUM(CASE WHEN action='block' THEN 1 ELSE 0 END),
               SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END),
               MAX(received_at)
        FROM events
        WHERE dst_ip IS NOT NULL AND (dst_geo_country IS NOT NULL OR dst_abuse_score IS NOT NULL) AND received_at >= ?
        GROUP BY dst_ip
      )
      GROUP BY ip ORDER BY event_count DESC, abuse_score DESC LIMIT ?
    `).all(since, since, limit);

    const summary = {
      totalEnriched: this.db.prepare("SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE is_private = 0").get().c,
      withAbuseScore: this.db.prepare("SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE abuse_score > 0 AND is_private = 0").get().c,
      highThreat: this.db.prepare("SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE abuse_score >= 50 AND is_private = 0").get().c,
      countries: this.db.prepare("SELECT COUNT(DISTINCT geo_country) as c FROM ip_enrichment_cache WHERE geo_country IS NOT NULL AND is_private = 0").get().c,
    };

    const periodStats = this.db.prepare(`
      SELECT
        COUNT(DISTINCT ip) as enriched,
        COUNT(DISTINCT CASE WHEN abuse_score > 0 THEN ip END) as flagged,
        COUNT(DISTINCT CASE WHEN abuse_score >= 50 THEN ip END) as highThreat,
        COUNT(DISTINCT country) as countries
      FROM (
        SELECT src_ip as ip, src_abuse_score as abuse_score, src_geo_country as country
        FROM events WHERE src_ip IS NOT NULL AND (src_geo_country IS NOT NULL OR src_abuse_score IS NOT NULL) AND received_at >= ?
        UNION
        SELECT dst_ip, dst_abuse_score, dst_geo_country
        FROM events WHERE dst_ip IS NOT NULL AND (dst_geo_country IS NOT NULL OR dst_abuse_score IS NOT NULL) AND received_at >= ?
      )
    `).get(since, since);

    return {
      summary,
      periodSummary: {
        enriched: periodStats.enriched,
        flagged: periodStats.flagged,
        highThreat: periodStats.highThreat,
        countries: periodStats.countries,
      },
      ips: rows,
    };
  }

  async getGeoEvents(since, limit) {
    const half = Math.ceil(limit / 2);
    const srcRows = this.db.prepare(`
      SELECT src_ip as ip, src_geo_country as country, src_geo_city as city,
        src_geo_lat as lat, src_geo_lon as lon, src_abuse_score as abuseScore,
        COUNT(*) as count,
        SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threats,
        MAX(received_at) as lastSeen, 'src' as direction
      FROM events WHERE src_geo_lat IS NOT NULL AND src_geo_lon IS NOT NULL AND received_at >= ?
      GROUP BY src_ip ORDER BY count DESC LIMIT ?
    `).all(since, half);

    const dstRows = this.db.prepare(`
      SELECT dst_ip as ip, dst_geo_country as country, dst_geo_city as city,
        dst_geo_lat as lat, dst_geo_lon as lon, dst_abuse_score as abuseScore,
        COUNT(*) as count,
        SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threats,
        MAX(received_at) as lastSeen, 'dst' as direction
      FROM events WHERE dst_geo_lat IS NOT NULL AND dst_geo_lon IS NOT NULL AND received_at >= ?
      GROUP BY dst_ip ORDER BY count DESC LIMIT ?
    `).all(since, half);

    return [...srcRows, ...dstRows];
  }

  async getRecentGeoEvents(limit) {
    return this.db.prepare(`
      SELECT id, event_type, action, received_at,
        src_ip, src_geo_lat, src_geo_lon, src_geo_country, src_geo_city, src_abuse_score,
        dst_ip, dst_geo_lat, dst_geo_lon, dst_geo_country, dst_geo_city, dst_abuse_score,
        message, dst_port, protocol
      FROM events
      WHERE (src_geo_lat IS NOT NULL OR dst_geo_lat IS NOT NULL)
      ORDER BY id DESC LIMIT ?
    `).all(limit);
  }

  // --- Enrichment Cache ---

  async getCachedEnrichment(ip) {
    const row = this.db.prepare('SELECT * FROM ip_enrichment_cache WHERE ip = ?').get(ip);
    if (!row) return null;
    const updatedAt = new Date(row.updated_at).getTime();
    const maxAge = (this.config.abuseIpDbCacheHours || 24) * 60 * 60 * 1000;
    if (Date.now() - updatedAt > maxAge) return null;
    return row;
  }

  async setCachedEnrichment(ip, data) {
    this.db.prepare(`
      INSERT OR REPLACE INTO ip_enrichment_cache
      (ip, geo_country, geo_city, geo_lat, geo_lon, abuse_score, hostname, is_private, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    `).run(ip, data.geo_country || null, data.geo_city || null, data.geo_lat || null,
      data.geo_lon || null, data.abuse_score ?? null, data.hostname || null,
      data.is_private ? 1 : 0);
  }

  async markPrivate(ip) {
    await this.setCachedEnrichment(ip, { is_private: true });
  }

  async getAllCachedEnrichment() {
    return this.db.prepare(
      'SELECT ip, geo_country, geo_city, geo_lat, geo_lon, abuse_score, hostname FROM ip_enrichment_cache WHERE is_private = 0 AND (geo_country IS NOT NULL OR abuse_score IS NOT NULL)'
    ).all();
  }

  // --- Maintenance ---

  async runRetention(days) {
    const result = this.db.prepare(
      "DELETE FROM events WHERE received_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)"
    ).run(`-${days} days`);
    return { deleted: result.changes };
  }

  async resetData() {
    this.db.exec('DROP TABLE IF EXISTS events');
    this.db.exec('DROP TABLE IF EXISTS ip_enrichment_cache');
    this._initSchema();
  }

  // --- Settings ---

  async getSetting(key) {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    if (!row) return null;
    try { return JSON.parse(row.value); } catch { return row.value; }
  }

  async setSetting(key, value) {
    this.db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, JSON.stringify(value));
  }

  async getAllSettings() {
    return this.db.prepare('SELECT key, value FROM settings').all();
  }

  // --- Direct DB access (for backward compatibility) ---

  getDb() {
    return this.db;
  }
}

module.exports = SqliteBackend;
