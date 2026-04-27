/**
 * SQLite Storage Backend
 * 
 * Wraps the existing better-sqlite3 implementation behind the StorageBackend interface.
 * This is the default, zero-dependency backend.
 */
const Database = require('better-sqlite3');
const { Worker } = require('worker_threads');
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
    this._statsWorker = null;
    this._pendingQueries = new Map();
    this._queryIdCounter = 0;
    this._dbPath = null;
  }

  async initialize() {
    const dbPath = path.resolve(this.config.path || './data/events.db');
    this._dbPath = dbPath;
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('cache_size = -128000');
    this.db.pragma('busy_timeout = 30000');

    this._initSchema();
    this._initStatsWorker();
    logger.info({ path: dbPath, backend: 'sqlite' }, 'Storage backend initialized');
  }

  async close() {
    if (this._statsWorker) {
      this._statsWorker.postMessage({ type: 'shutdown' });
      this._statsWorker = null;
      for (const [id, pending] of this._pendingQueries) {
        clearTimeout(pending.timer);
        pending.reject(new Error('Stats worker shutting down'));
      }
      this._pendingQueries.clear();
    }
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  // --- Stats Worker ---

  _initStatsWorker() {
    if (this._statsWorker) return;

    this._statsWorker = new Worker(path.join(__dirname, '../stats-worker.js'), {
      workerData: { dbPath: this._dbPath },
    });

    this._statsWorker.on('message', (msg) => {
      if (msg.type === 'ready') {
        logger.info('Stats worker thread started');
        return;
      }
      const pending = this._pendingQueries.get(msg.id);
      if (pending) {
        this._pendingQueries.delete(msg.id);
        clearTimeout(pending.timer);
        if (msg.error) pending.reject(new Error(msg.error));
        else pending.resolve(msg.result);
      }
    });

    this._statsWorker.on('error', (err) => {
      logger.error({ err }, 'Stats worker error');
    });

    this._statsWorker.on('exit', (code) => {
      if (code !== 0) {
        logger.warn({ code }, 'Stats worker exited unexpectedly, restarting...');
        this._statsWorker = null;
        for (const [id, pending] of this._pendingQueries) {
          clearTimeout(pending.timer);
          pending.reject(new Error('Stats worker crashed'));
        }
        this._pendingQueries.clear();
        setTimeout(() => this._initStatsWorker(), 1000);
      }
    });
  }

  _queryAsync(sql, params = [], method = 'all') {
    return new Promise((resolve, reject) => {
      if (!this._statsWorker) {
        // Fallback to main thread if worker not available
        try {
          const stmt = this.db.prepare(sql);
          const result = method === 'get' ? stmt.get(...params) : stmt.all(...params);
          return resolve(result);
        } catch (err) { return reject(err); }
      }

      const id = String(++this._queryIdCounter);
      const timer = setTimeout(() => {
        this._pendingQueries.delete(id);
        reject(new Error(`Stats query timed out after 300s: ${sql.slice(0, 80)}`));
      }, 300000);

      this._pendingQueries.set(id, { resolve, reject, timer });
      this._statsWorker.postMessage({ id, sql, params, method });
    });
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

      DROP INDEX IF EXISTS idx_events_timestamp;
      DROP INDEX IF EXISTS idx_events_type_timestamp;

      CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
      CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
      CREATE INDEX IF NOT EXISTS idx_events_type_received_at ON events(event_type, received_at);
      CREATE INDEX IF NOT EXISTS idx_events_action_received_at ON events(action, received_at);
      CREATE INDEX IF NOT EXISTS idx_events_type_action ON events(event_type, action);
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

      -- Rollup tables for pre-aggregated stats
      CREATE TABLE IF NOT EXISTS event_stats_5m (
        bucket TEXT NOT NULL,
        event_type TEXT NOT NULL,
        action TEXT NOT NULL DEFAULT '',
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket, event_type, action)
      );

      CREATE TABLE IF NOT EXISTS ip_stats_hourly (
        bucket TEXT NOT NULL,
        ip TEXT NOT NULL,
        direction TEXT NOT NULL,
        event_count INTEGER NOT NULL DEFAULT 0,
        blocked_count INTEGER NOT NULL DEFAULT 0,
        threat_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket, ip, direction)
      );

      CREATE TABLE IF NOT EXISTS port_stats_hourly (
        bucket TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL DEFAULT '',
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket, port, protocol)
      );

      CREATE TABLE IF NOT EXISTS sig_stats_hourly (
        bucket TEXT NOT NULL,
        signature TEXT NOT NULL,
        classification TEXT NOT NULL DEFAULT '',
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket, signature, classification)
      );

      CREATE TABLE IF NOT EXISTS client_stats_hourly (
        bucket TEXT NOT NULL,
        mac TEXT NOT NULL,
        event_count INTEGER NOT NULL DEFAULT 0,
        wifi_count INTEGER NOT NULL DEFAULT 0,
        dhcp_count INTEGER NOT NULL DEFAULT 0,
        firewall_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket, mac)
      );
    `);

    // One-time rollup backfill if tables are empty but events exist
    const hasEvents = this.db.prepare('SELECT 1 FROM events LIMIT 1').get();
    const hasRollups = this.db.prepare('SELECT 1 FROM event_stats_5m LIMIT 1').get();
    if (hasEvents && !hasRollups) {
      logger.info('Populating rollup tables from existing events (one-time migration)...');
      this._backfillRollups();
      logger.info('Rollup backfill complete');
    } else if (hasRollups) {
      // Re-backfill individual rollup tables that may be empty due to prior bugs
      const hasSigStats = this.db.prepare('SELECT 1 FROM sig_stats_hourly LIMIT 1').get();
      const hasThreats = this.db.prepare("SELECT 1 FROM events WHERE event_type='threat' LIMIT 1").get();
      if (hasThreats && !hasSigStats) {
        logger.info('Backfilling sig_stats_hourly (one-time fix)...');
        this._backfillSigStats();
        logger.info('sig_stats_hourly backfill complete');
      }
    }
  }

  _backfillSigStats() {
    this.db.exec(`
      INSERT OR IGNORE INTO sig_stats_hourly (bucket, signature, classification, count)
      SELECT
        strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket,
        COALESCE(ids_signature, '(no signature)') as signature,
        COALESCE(ids_classification, '') as classification, COUNT(*) as count
      FROM events WHERE event_type='threat'
      GROUP BY bucket, signature, classification
    `);
  }

  _backfillRollups() {
    // Populate event_stats_5m from events
    this.db.exec(`
      INSERT OR IGNORE INTO event_stats_5m (bucket, event_type, action, count)
      SELECT
        strftime('%Y-%m-%dT%H:', received_at) || CASE
          WHEN CAST(strftime('%M', received_at) AS INTEGER) / 5 * 5 < 10
          THEN '0' || (CAST(strftime('%M', received_at) AS INTEGER) / 5 * 5)
          ELSE '' || (CAST(strftime('%M', received_at) AS INTEGER) / 5 * 5)
        END || ':00.000Z' as bucket,
        event_type,
        COALESCE(action, '') as action,
        COUNT(*) as count
      FROM events
      GROUP BY bucket, event_type, action
    `);

    // Populate ip_stats_hourly from events (src direction)
    this.db.exec(`
      INSERT OR IGNORE INTO ip_stats_hourly (bucket, ip, direction, event_count, blocked_count, threat_count)
      SELECT
        strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket,
        src_ip as ip, 'src' as direction,
        COUNT(*) as event_count,
        SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked_count,
        SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threat_count
      FROM events WHERE src_ip IS NOT NULL
      GROUP BY bucket, src_ip
    `);
    // dst direction
    this.db.exec(`
      INSERT OR IGNORE INTO ip_stats_hourly (bucket, ip, direction, event_count, blocked_count, threat_count)
      SELECT
        strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket,
        dst_ip as ip, 'dst' as direction,
        COUNT(*) as event_count,
        SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) as blocked_count,
        SUM(CASE WHEN event_type='threat' THEN 1 ELSE 0 END) as threat_count
      FROM events WHERE dst_ip IS NOT NULL
      GROUP BY bucket, dst_ip
    `);

    // Populate port_stats_hourly
    this.db.exec(`
      INSERT OR IGNORE INTO port_stats_hourly (bucket, port, protocol, count)
      SELECT
        strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket,
        dst_port as port, COALESCE(protocol, '') as protocol, COUNT(*) as count
      FROM events WHERE dst_port IS NOT NULL
      GROUP BY bucket, dst_port, protocol
    `);

    // Populate sig_stats_hourly — include all threats, fallback signature for missing
    this.db.exec(`
      INSERT OR IGNORE INTO sig_stats_hourly (bucket, signature, classification, count)
      SELECT
        strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket,
        COALESCE(ids_signature, '(no signature)') as signature,
        COALESCE(ids_classification, '') as classification, COUNT(*) as count
      FROM events WHERE event_type='threat'
      GROUP BY bucket, signature, classification
    `);

    // Populate client_stats_hourly
    this.db.exec(`
      INSERT OR IGNORE INTO client_stats_hourly (bucket, mac, event_count, wifi_count, dhcp_count, firewall_count)
      SELECT
        strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket,
        mac, SUM(c) as event_count,
        SUM(CASE WHEN et='wifi' THEN c ELSE 0 END) as wifi_count,
        SUM(CASE WHEN et='dhcp' THEN c ELSE 0 END) as dhcp_count,
        SUM(CASE WHEN et='firewall' THEN c ELSE 0 END) as firewall_count
      FROM (
        SELECT strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z' as bucket, client_mac as mac, event_type as et, COUNT(*) as c
        FROM events WHERE client_mac IS NOT NULL GROUP BY bucket, client_mac, event_type
        UNION ALL
        SELECT strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z', wifi_client_mac, event_type, COUNT(*)
        FROM events WHERE wifi_client_mac IS NOT NULL GROUP BY 1, wifi_client_mac, event_type
        UNION ALL
        SELECT strftime('%Y-%m-%dT%H', received_at) || ':00:00.000Z', dhcp_mac, event_type, COUNT(*)
        FROM events WHERE dhcp_mac IS NOT NULL GROUP BY 1, dhcp_mac, event_type
      )
      GROUP BY bucket, mac
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

    // Rollup UPSERT statements
    this._rollupEventStats = this.db.prepare(`
      INSERT INTO event_stats_5m (bucket, event_type, action, count) VALUES (?, ?, ?, ?)
      ON CONFLICT(bucket, event_type, action) DO UPDATE SET count = count + excluded.count
    `);
    this._rollupIpStats = this.db.prepare(`
      INSERT INTO ip_stats_hourly (bucket, ip, direction, event_count, blocked_count, threat_count) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(bucket, ip, direction) DO UPDATE SET
        event_count = event_count + excluded.event_count,
        blocked_count = blocked_count + excluded.blocked_count,
        threat_count = threat_count + excluded.threat_count
    `);
    this._rollupPortStats = this.db.prepare(`
      INSERT INTO port_stats_hourly (bucket, port, protocol, count) VALUES (?, ?, ?, ?)
      ON CONFLICT(bucket, port, protocol) DO UPDATE SET count = count + excluded.count
    `);
    this._rollupSigStats = this.db.prepare(`
      INSERT INTO sig_stats_hourly (bucket, signature, classification, count) VALUES (?, ?, ?, ?)
      ON CONFLICT(bucket, signature, classification) DO UPDATE SET count = count + excluded.count
    `);
    this._rollupClientStats = this.db.prepare(`
      INSERT INTO client_stats_hourly (bucket, mac, event_count, wifi_count, dhcp_count, firewall_count) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(bucket, mac) DO UPDATE SET
        event_count = event_count + excluded.event_count,
        wifi_count = wifi_count + excluded.wifi_count,
        dhcp_count = dhcp_count + excluded.dhcp_count,
        firewall_count = firewall_count + excluded.firewall_count
    `);

    this.insertManyTxn = this.db.transaction((events) => {
      for (const evt of events) {
        const values = cols.map(col => evt[col] ?? null);
        this.insertStmt.run(values);
      }
      this._updateRollups(events);
    });
  }

  _updateRollups(events) {
    const nowMs = Date.now();

    // Pre-aggregate batch in JS, keyed by per-event bucket
    const eventCounts = new Map();  // key: bucket5m|event_type|action → count
    const ipCounts = new Map();     // key: bucket1h|ip|direction → { event, blocked, threat }
    const portCounts = new Map();   // key: bucket1h|port|protocol → count
    const sigCounts = new Map();    // key: bucket1h|signature|classification → count
    const clientCounts = new Map(); // key: bucket1h|mac → { event, wifi, dhcp, firewall }

    for (const evt of events) {
      // Use event's received_at for bucket, fall back to now
      const evtMs = evt.received_at ? new Date(evt.received_at).getTime() : nowMs;
      const b5m = new Date(Math.floor(evtMs / 300000) * 300000).toISOString();
      const b1h = new Date(Math.floor(evtMs / 3600000) * 3600000).toISOString();

      const type = evt.event_type || 'unknown';
      const action = evt.action || '';

      // event_stats_5m
      const ek = `${b5m}|${type}|${action}`;
      eventCounts.set(ek, (eventCounts.get(ek) || 0) + 1);

      // ip_stats_hourly
      const isBlocked = action === 'block' ? 1 : 0;
      const isThreat = type === 'threat' ? 1 : 0;
      if (evt.src_ip) {
        const sk = `${b1h}|${evt.src_ip}|src`;
        const s = ipCounts.get(sk) || { event: 0, blocked: 0, threat: 0 };
        s.event++; s.blocked += isBlocked; s.threat += isThreat;
        ipCounts.set(sk, s);
      }
      if (evt.dst_ip) {
        const dk = `${b1h}|${evt.dst_ip}|dst`;
        const d = ipCounts.get(dk) || { event: 0, blocked: 0, threat: 0 };
        d.event++; d.blocked += isBlocked; d.threat += isThreat;
        ipCounts.set(dk, d);
      }

      // port_stats_hourly
      if (evt.dst_port) {
        const pk = `${b1h}|${evt.dst_port}|${evt.protocol || ''}`;
        portCounts.set(pk, (portCounts.get(pk) || 0) + 1);
      }

      // sig_stats_hourly — include all threats, fallback signature for missing
      if (type === 'threat') {
        const sig = evt.ids_signature || '(no signature)';
        const cls = evt.ids_classification || '';
        const sigk = `${b1h}|${sig}|${cls}`;
        sigCounts.set(sigk, (sigCounts.get(sigk) || 0) + 1);
      }

      // client_stats_hourly
      const mac = evt.client_mac || evt.wifi_client_mac || evt.dhcp_mac;
      if (mac) {
        const ck = `${b1h}|${mac}`;
        const c = clientCounts.get(ck) || { event: 0, wifi: 0, dhcp: 0, firewall: 0 };
        c.event++;
        if (type === 'wifi') c.wifi++;
        if (type === 'dhcp') c.dhcp++;
        if (type === 'firewall') c.firewall++;
        clientCounts.set(ck, c);
      }
    }

    // UPSERT aggregated counts
    for (const [key, count] of eventCounts) {
      const [bucket, type, action] = key.split('|');
      this._rollupEventStats.run(bucket, type, action, count);
    }
    for (const [key, counts] of ipCounts) {
      const [bucket, ip, dir] = key.split('|');
      this._rollupIpStats.run(bucket, ip, dir, counts.event, counts.blocked, counts.threat);
    }
    for (const [key, count] of portCounts) {
      const [bucket, port, protocol] = key.split('|');
      this._rollupPortStats.run(bucket, parseInt(port, 10), protocol, count);
    }
    for (const [key, count] of sigCounts) {
      const [bucket, sig, cls] = key.split('|');
      this._rollupSigStats.run(bucket, sig, cls, count);
    }
    for (const [key, counts] of clientCounts) {
      const [bucket, mac] = key.split('|');
      this._rollupClientStats.run(bucket, mac, counts.event, counts.wifi, counts.dhcp, counts.firewall);
    }
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
    const row = await this._queryAsync('SELECT COUNT(*) as count FROM events', [], 'get');
    return row.count;
  }

  async getEventCountToday() {
    const now = new Date();
    const localMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const midnightISO = localMidnight.toISOString();
    const row = await this._queryAsync(
      "SELECT COALESCE(SUM(count), 0) as count FROM event_stats_5m WHERE bucket >= ?", [midnightISO], 'get'
    );
    return row.count;
  }

  async getLastEventTime() {
    const row = await this._queryAsync('SELECT received_at FROM events ORDER BY id DESC LIMIT 1', [], 'get');
    return row ? row.received_at : null;
  }

  async getEventTypeCounts(since) {
    let sql = 'SELECT event_type, SUM(count) as count FROM event_stats_5m';
    const params = [];
    if (since) { sql += ' WHERE bucket >= ?'; params.push(since); }
    sql += ' GROUP BY event_type';
    const rows = await this._queryAsync(sql, params);
    const counts = {};
    for (const row of rows) counts[row.event_type] = row.count;
    return counts;
  }

  // --- Stats / Aggregation ---

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
    const [totalRow, byType, allowedRow, blockedRow, threatsRow] = await Promise.all([
      this._queryAsync('SELECT COALESCE(SUM(count), 0) as c FROM event_stats_5m WHERE bucket >= ?', [since], 'get'),
      this.getEventTypeCounts(since),
      this._queryAsync("SELECT COALESCE(SUM(count), 0) as c FROM event_stats_5m WHERE event_type='firewall' AND action='allow' AND bucket >= ?", [since], 'get'),
      this._queryAsync("SELECT COALESCE(SUM(count), 0) as c FROM event_stats_5m WHERE event_type='firewall' AND action='block' AND bucket >= ?", [since], 'get'),
      this._queryAsync("SELECT COALESCE(SUM(count), 0) as c FROM event_stats_5m WHERE event_type='threat' AND bucket >= ?", [since], 'get'),
    ]);
    return {
      total: totalRow.c,
      byType,
      firewall: { allowed: allowedRow.c, blocked: blockedRow.c, threats: threatsRow.c },
    };
  }

  async getTimeline(since, bucketFormat, eventType, bucketSize) {
    // Derive bucket interval from bucketSize
    const bucketMs = { '5m': 300000, '15m': 900000, '1h': 3600000, '1d': 86400000 }[bucketSize || '1h'] || 3600000;

    // Pre-generate zero-filled bucket map aligned to bucket boundaries
    const startTime = new Date(Math.floor(new Date(since).getTime() / bucketMs) * bucketMs);
    const endTime = new Date(Math.floor(Date.now() / bucketMs) * bucketMs);
    const numBuckets = Math.floor((endTime - startTime) / bucketMs) + 1;

    const buckets = new Map();
    for (let i = 0; i < numBuckets; i++) {
      const ts = new Date(startTime.getTime() + i * bucketMs).toISOString();
      buckets.set(ts, eventType === 'firewall'
        ? { ts, allowed: 0, blocked: 0 }
        : { ts, firewall: 0, threat: 0, dhcp: 0, dns_filter: 0, wifi: 0, admin: 0, system: 0, total: 0 });
    }

    // Query rollup table — already bucketed at 5m granularity
    let sql;
    if (eventType === 'firewall') {
      sql = `SELECT bucket as ts,
              SUM(CASE WHEN action='allow' THEN count ELSE 0 END) as allowed,
              SUM(CASE WHEN action='block' THEN count ELSE 0 END) as blocked
             FROM event_stats_5m WHERE event_type='firewall' AND bucket >= ?
             GROUP BY bucket ORDER BY bucket`;
    } else {
      sql = `SELECT bucket as ts,
              SUM(CASE WHEN event_type='firewall' THEN count ELSE 0 END) as firewall,
              SUM(CASE WHEN event_type='threat' THEN count ELSE 0 END) as threat,
              SUM(CASE WHEN event_type='dhcp' THEN count ELSE 0 END) as dhcp,
              SUM(CASE WHEN event_type='dns_filter' THEN count ELSE 0 END) as dns_filter,
              SUM(CASE WHEN event_type='wifi' THEN count ELSE 0 END) as wifi,
              SUM(CASE WHEN event_type='admin' THEN count ELSE 0 END) as admin,
              SUM(CASE WHEN event_type='system' THEN count ELSE 0 END) as system,
              SUM(count) as total
             FROM event_stats_5m WHERE bucket >= ?
             GROUP BY bucket ORDER BY bucket`;
    }

    const rows = await this._queryAsync(sql, [since]);
    // Merge rollup rows into bucket map (floor to target bucket size for 15m/1h/1d)
    for (const row of rows) {
      const aligned = new Date(Math.floor(new Date(row.ts).getTime() / bucketMs) * bucketMs);
      const key = aligned.toISOString();
      if (buckets.has(key)) {
        const bucket = buckets.get(key);
        if (eventType === 'firewall') {
          bucket.allowed += row.allowed;
          bucket.blocked += row.blocked;
        } else {
          bucket.firewall += row.firewall;
          bucket.threat += row.threat;
          bucket.dhcp += row.dhcp;
          bucket.dns_filter += row.dns_filter;
          bucket.wifi += row.wifi;
          bucket.admin += row.admin;
          bucket.system += row.system;
          bucket.total += row.total;
        }
      }
    }

    return Array.from(buckets.values());
  }

  async getTopTalkers(since, direction, limit, excludePrivate) {
    const dir = direction === 'dst' ? 'dst' : 'src';
    const privFilter = excludePrivate ? `AND ${this._privateIpFilter('ip')}` : '';
    const rows = await this._queryAsync(`
      SELECT ip, SUM(event_count) as count
      FROM ip_stats_hourly WHERE direction = ? AND bucket >= ? ${privFilter}
      GROUP BY ip ORDER BY count DESC LIMIT ?
    `, [dir, since, limit]);

    // Enrich with geo/hostname from cache
    return this._enrichIpRows(rows);
  }

  async getTopBlocked(since, direction, limit, excludePrivate) {
    const dir = direction === 'dst' ? 'dst' : 'src';
    const privFilter = excludePrivate ? `AND ${this._privateIpFilter('ip')}` : '';
    const rows = await this._queryAsync(`
      SELECT ip, SUM(blocked_count) as count
      FROM ip_stats_hourly WHERE direction = ? AND bucket >= ? ${privFilter}
      GROUP BY ip HAVING count > 0 ORDER BY count DESC LIMIT ?
    `, [dir, since, limit]);

    // Enrich with geo/hostname/abuseScore from cache
    return this._enrichIpRows(rows, true);
  }

  async _enrichIpRows(rows, includeAbuse = false) {
    if (rows.length === 0) return rows;
    const ips = rows.map(r => r.ip);
    const placeholders = ips.map(() => '?').join(',');
    const cacheRows = await this._queryAsync(
      `SELECT ip, geo_country, abuse_score, hostname FROM ip_enrichment_cache WHERE ip IN (${placeholders})`,
      ips
    );
    const cache = new Map(cacheRows.map(r => [r.ip, r]));
    return rows.map(r => {
      const c = cache.get(r.ip) || {};
      const result = { ip: r.ip, count: r.count, lastSeen: null, country: c.geo_country || null, hostname: c.hostname || null };
      if (includeAbuse) result.abuseScore = c.abuse_score ?? null;
      return result;
    });
  }

  async getTopPorts(since, limit) {
    return this._queryAsync(`
      SELECT port, protocol, SUM(count) as count
      FROM port_stats_hourly WHERE bucket >= ?
      GROUP BY port, protocol ORDER BY count DESC LIMIT ?
    `, [since, limit]);
  }

  async getTopClients(since, limit) {
    const rows = await this._queryAsync(`
      SELECT mac, SUM(event_count) as eventCount,
        SUM(wifi_count) as wifiEvents, SUM(dhcp_count) as dhcpEvents, SUM(firewall_count) as firewallEvents
      FROM client_stats_hourly WHERE bucket >= ?
      GROUP BY mac ORDER BY eventCount DESC LIMIT ?
    `, [since, limit]);

    // Enrich with alias/ip — not available in rollup, check events for most recent
    if (rows.length === 0) return rows;
    return rows.map(r => ({ ...r, alias: null, ip: null }));
  }

  async getTopThreats(since, limit) {
    return this._queryAsync(`
      SELECT signature, classification, SUM(count) as count, NULL as lastSeen
      FROM sig_stats_hourly WHERE bucket >= ?
      GROUP BY signature, classification ORDER BY count DESC LIMIT ?
    `, [since, limit]);
  }

  async getThreatIntel(since, limit) {
    const [ipRows, totalEnriched, withAbuseScore, highThreat, countries, periodStats] = await Promise.all([
      // IP list from rollup (both directions combined) + cache join
      this._queryAsync(`
        SELECT r.ip, SUM(r.event_count) as event_count, SUM(r.blocked_count) as blocked_count,
               SUM(r.threat_count) as threat_count,
               c.geo_country as country, c.geo_city as city, c.geo_lat as lat, c.geo_lon as lon,
               c.abuse_score, c.hostname
        FROM ip_stats_hourly r
        JOIN ip_enrichment_cache c ON r.ip = c.ip AND c.is_private = 0
        WHERE r.bucket >= ? AND (c.geo_country IS NOT NULL OR c.abuse_score IS NOT NULL)
        GROUP BY r.ip ORDER BY event_count DESC, c.abuse_score DESC LIMIT ?
      `, [since, limit]),
      // Summary counts — already fast (cache table only)
      this._queryAsync("SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE is_private = 0", [], 'get'),
      this._queryAsync("SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE abuse_score > 0 AND is_private = 0", [], 'get'),
      this._queryAsync("SELECT COUNT(*) as c FROM ip_enrichment_cache WHERE abuse_score >= 50 AND is_private = 0", [], 'get'),
      this._queryAsync("SELECT COUNT(DISTINCT geo_country) as c FROM ip_enrichment_cache WHERE geo_country IS NOT NULL AND is_private = 0", [], 'get'),
      // Period summary from rollup + cache join
      this._queryAsync(`
        SELECT COUNT(DISTINCT r.ip) as enriched,
               COUNT(DISTINCT CASE WHEN c.abuse_score > 0 THEN r.ip END) as flagged,
               COUNT(DISTINCT CASE WHEN c.abuse_score >= 50 THEN r.ip END) as highThreat,
               COUNT(DISTINCT c.geo_country) as countries
        FROM ip_stats_hourly r
        JOIN ip_enrichment_cache c ON r.ip = c.ip AND c.is_private = 0
        WHERE r.bucket >= ? AND (c.geo_country IS NOT NULL OR c.abuse_score IS NOT NULL)
      `, [since], 'get'),
    ]);

    return {
      summary: {
        totalEnriched: totalEnriched.c,
        withAbuseScore: withAbuseScore.c,
        highThreat: highThreat.c,
        countries: countries.c,
      },
      periodSummary: {
        enriched: periodStats.enriched,
        flagged: periodStats.flagged,
        highThreat: periodStats.highThreat,
        countries: periodStats.countries,
      },
      ips: ipRows.map(r => ({
        ip: r.ip, hostname: r.hostname, country: r.country, city: r.city,
        lat: r.lat, lon: r.lon, abuse_score: r.abuse_score,
        event_count: r.event_count, blocked_count: r.blocked_count,
        threat_count: r.threat_count, lastSeen: null,
      })),
    };
  }

  async getGeoEvents(since, limit) {
    const half = Math.ceil(limit / 2);
    // Over-fetch from rollup (3x) to account for IPs without geo data in cache
    const [srcRollup, dstRollup] = await Promise.all([
      this._queryAsync(`
        SELECT r.ip, SUM(r.event_count) as count, SUM(r.blocked_count) as blocked, SUM(r.threat_count) as threats,
          c.geo_country as country, c.geo_city as city, c.geo_lat as lat, c.geo_lon as lon,
          c.abuse_score as abuseScore
        FROM ip_stats_hourly r
        JOIN ip_enrichment_cache c ON r.ip = c.ip
        WHERE r.direction = 'src' AND r.bucket >= ? AND c.geo_lat IS NOT NULL AND c.geo_lon IS NOT NULL
        GROUP BY r.ip ORDER BY count DESC LIMIT ?
      `, [since, half]),
      this._queryAsync(`
        SELECT r.ip, SUM(r.event_count) as count, SUM(r.blocked_count) as blocked, SUM(r.threat_count) as threats,
          c.geo_country as country, c.geo_city as city, c.geo_lat as lat, c.geo_lon as lon,
          c.abuse_score as abuseScore
        FROM ip_stats_hourly r
        JOIN ip_enrichment_cache c ON r.ip = c.ip
        WHERE r.direction = 'dst' AND r.bucket >= ? AND c.geo_lat IS NOT NULL AND c.geo_lon IS NOT NULL
        GROUP BY r.ip ORDER BY count DESC LIMIT ?
      `, [since, half]),
    ]);

    const srcRows = srcRollup.map(r => ({ ...r, direction: 'src', lastSeen: null }));
    const dstRows = dstRollup.map(r => ({ ...r, direction: 'dst', lastSeen: null }));
    return [...srcRows, ...dstRows];
  }

  async getRecentGeoEvents(limit) {
    return this._queryAsync(`
      SELECT id, event_type, action, received_at,
        src_ip, src_geo_lat, src_geo_lon, src_geo_country, src_geo_city, src_abuse_score,
        dst_ip, dst_geo_lat, dst_geo_lon, dst_geo_country, dst_geo_city, dst_abuse_score,
        message, dst_port, protocol
      FROM events
      WHERE (src_geo_lat IS NOT NULL OR dst_geo_lat IS NOT NULL)
      ORDER BY id DESC LIMIT ?
    `, [limit]);
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
    const cutoff = new Date(Date.now() - days * 86400000).toISOString();
    const result = this.db.prepare(
      "DELETE FROM events WHERE received_at < ?"
    ).run(cutoff);
    // Clean rollup tables too
    this.db.prepare("DELETE FROM event_stats_5m WHERE bucket < ?").run(cutoff);
    this.db.prepare("DELETE FROM ip_stats_hourly WHERE bucket < ?").run(cutoff);
    this.db.prepare("DELETE FROM port_stats_hourly WHERE bucket < ?").run(cutoff);
    this.db.prepare("DELETE FROM sig_stats_hourly WHERE bucket < ?").run(cutoff);
    this.db.prepare("DELETE FROM client_stats_hourly WHERE bucket < ?").run(cutoff);
    return { deleted: result.changes };
  }

  async resetData() {
    this.db.exec('DROP TABLE IF EXISTS events');
    this.db.exec('DROP TABLE IF EXISTS ip_enrichment_cache');
    this.db.exec('DROP TABLE IF EXISTS event_stats_5m');
    this.db.exec('DROP TABLE IF EXISTS ip_stats_hourly');
    this.db.exec('DROP TABLE IF EXISTS port_stats_hourly');
    this.db.exec('DROP TABLE IF EXISTS sig_stats_hourly');
    this.db.exec('DROP TABLE IF EXISTS client_stats_hourly');
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
    const rows = this.db.prepare('SELECT key, value FROM settings').all();
    // Parse values so callers receive structured data (matches getSetting).
    // Returning the raw JSON-encoded string here was the cause of the
    // master-key/auth-token quote-wrapping bug: callers passed the
    // doubly-encoded string into setMasterKey()/encrypt(), producing
    // ciphertext that couldn't decrypt across restart.
    return rows.map((row) => {
      try { return { key: row.key, value: JSON.parse(row.value) }; }
      catch { return { key: row.key, value: row.value }; }
    });
  }

  // --- Direct DB access (for backward compatibility) ---

  getDb() {
    return this.db;
  }
}

module.exports = SqliteBackend;
