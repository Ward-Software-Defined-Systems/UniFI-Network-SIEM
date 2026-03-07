const { getDb } = require('./database');
const config = require('../config');
const logger = require('../utils/logger');

const EVENT_COLUMNS = [
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

let insertStmt = null;
let insertManyTxn = null;

function getInsertStmt() {
  if (insertStmt) return insertStmt;
  const db = getDb();
  const placeholders = EVENT_COLUMNS.map(() => '?').join(', ');
  const sql = `INSERT INTO events (${EVENT_COLUMNS.join(', ')}) VALUES (${placeholders})`;
  insertStmt = db.prepare(sql);
  insertManyTxn = db.transaction((events) => {
    for (const evt of events) {
      const values = EVENT_COLUMNS.map(col => evt[col] ?? null);
      insertStmt.run(values);
    }
  });
  return insertStmt;
}

// Batch insert queue
let queue = [];
let flushTimer = null;
let onInsertCallback = null;

function setOnInsert(cb) {
  onInsertCallback = cb;
}

function queueEvent(event) {
  // Add raw_message if configured
  if (!config.logging.logRawMessages) {
    delete event.raw_message;
  }

  queue.push(event);

  if (queue.length >= config.performance.insertBatchSize) {
    flushQueue();
  } else if (!flushTimer) {
    flushTimer = setTimeout(flushQueue, config.performance.insertBatchIntervalMs);
  }
}

function flushQueue() {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  if (queue.length === 0) return;

  const batch = queue;
  queue = [];

  try {
    getInsertStmt(); // ensure prepared
    insertManyTxn(batch);

    if (onInsertCallback) {
      for (const evt of batch) {
        onInsertCallback(evt);
      }
    }
  } catch (err) {
    logger.error({ err, count: batch.length }, 'Failed to insert event batch');
  }
}

function queryEvents(filters = {}) {
  const db = getDb();
  const conditions = [];
  const params = [];

  if (filters.event_type) {
    const types = filters.event_type.split(',');
    conditions.push(`event_type IN (${types.map(() => '?').join(',')})`);
    params.push(...types);
  }
  if (filters.action) {
    conditions.push('action = ?');
    params.push(filters.action);
  }
  if (filters.direction) {
    conditions.push('direction = ?');
    params.push(filters.direction);
  }
  if (filters.severity) {
    const sevs = filters.severity.split(',').map(Number);
    conditions.push(`severity IN (${sevs.map(() => '?').join(',')})`);
    params.push(...sevs);
  }
  if (filters.src_ip) {
    conditions.push('src_ip = ?');
    params.push(filters.src_ip);
  }
  if (filters.dst_ip) {
    conditions.push('dst_ip = ?');
    params.push(filters.dst_ip);
  }
  if (filters.dst_port) {
    conditions.push('dst_port = ?');
    params.push(parseInt(filters.dst_port, 10));
  }
  if (filters.protocol) {
    conditions.push('protocol = ?');
    params.push(filters.protocol.toUpperCase());
  }
  if (filters.mac) {
    conditions.push('(client_mac = ? OR wifi_client_mac = ? OR dhcp_mac = ? OR mac_src = ? OR mac_dst = ?)');
    params.push(filters.mac, filters.mac, filters.mac, filters.mac, filters.mac);
  }
  if (filters.since) {
    conditions.push('received_at >= ?');
    params.push(filters.since);
  }
  if (filters.until) {
    conditions.push('received_at <= ?');
    params.push(filters.until);
  }
  if (filters.search) {
    conditions.push(`(message LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dns_name LIKE ? OR hostname LIKE ?)`);
    const term = `%${filters.search}%`;
    params.push(term, term, term, term, term);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = Math.min(parseInt(filters.limit || '50', 10), 500);
  const offset = parseInt(filters.offset || '0', 10);

  const sql = `SELECT * FROM events ${where} ORDER BY id DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  return db.prepare(sql).all(...params);
}

function getEventById(id) {
  const db = getDb();
  return db.prepare('SELECT * FROM events WHERE id = ?').get(id);
}

function getEventCount() {
  const db = getDb();
  return db.prepare('SELECT COUNT(*) as count FROM events').get().count;
}

function getEventCountToday() {
  const db = getDb();
  return db.prepare(
    "SELECT COUNT(*) as count FROM events WHERE received_at >= date('now')"
  ).get().count;
}

function getLastEventTime() {
  const db = getDb();
  const row = db.prepare('SELECT received_at FROM events ORDER BY id DESC LIMIT 1').get();
  return row ? row.received_at : null;
}

function getEventTypeCounts(since) {
  const db = getDb();
  let sql = 'SELECT event_type, COUNT(*) as count FROM events';
  const params = [];
  if (since) {
    sql += ' WHERE received_at >= ?';
    params.push(since);
  }
  sql += ' GROUP BY event_type';
  const rows = db.prepare(sql).all(...params);
  const counts = {};
  for (const row of rows) {
    counts[row.event_type] = row.count;
  }
  return counts;
}

module.exports = {
  queueEvent, flushQueue, setOnInsert,
  queryEvents, getEventById,
  getEventCount, getEventCountToday, getLastEventTime, getEventTypeCounts,
};
