const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const config = require('../config');
const logger = require('../utils/logger');

let db;

function getDb() {
  if (db) return db;

  const dbPath = path.resolve(config.db.path);
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(dbPath);

  // Performance pragmas
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('cache_size = -128000');
  db.pragma('busy_timeout = 5000');

  initSchema(db);
  logger.info({ path: dbPath }, 'SQLite database initialized');

  return db;
}

function initSchema(db) {
  db.exec(`
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

function resetDb() {
  if (db) {
    db.exec('DELETE FROM events');
    db.exec('DELETE FROM ip_enrichment_cache');
    db.exec('VACUUM');
    logger.info('Database cleared');
  }
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, closeDb, resetDb };
