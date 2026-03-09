/**
 * Enrichment Worker Thread
 * 
 * Runs UPDATE operations (backfill + inline enrichment) off the main event loop.
 * Opens its own better-sqlite3 connection to the same WAL-mode DB.
 */
const { parentPort, workerData } = require('worker_threads');
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.resolve(workerData.dbPath);
const db = new Database(dbPath);

// Match main thread pragmas
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = -64000'); // 64MB (less than main — worker is write-heavy, not read-heavy)
db.pragma('busy_timeout = 10000'); // Higher timeout — main thread may hold locks during batch inserts

// Prepared statements (lazily created)
let updateSrcStmt = null;
let updateDstStmt = null;

function getUpdateStmts() {
  if (updateSrcStmt) return;

  updateSrcStmt = db.prepare(`
    UPDATE events SET
      src_geo_country = ?, src_geo_city = ?, src_geo_lat = ?, src_geo_lon = ?,
      src_abuse_score = ?, src_hostname = ?
    WHERE rowid IN (
      SELECT rowid FROM events WHERE src_ip = ? AND src_geo_country IS NULL
      ORDER BY rowid DESC LIMIT ?
    )
  `);

  updateDstStmt = db.prepare(`
    UPDATE events SET
      dst_geo_country = ?, dst_geo_city = ?, dst_geo_lat = ?, dst_geo_lon = ?,
      dst_abuse_score = ?, dst_hostname = ?
    WHERE rowid IN (
      SELECT rowid FROM events WHERE dst_ip = ? AND dst_geo_country IS NULL
      ORDER BY rowid DESC LIMIT ?
    )
  `);
}

function updateEventsWithEnrichment(ip, data, batchLimit) {
  getUpdateStmts();
  const limit = batchLimit || 1000;

  const srcResult = updateSrcStmt.run(
    data.geo_country, data.geo_city, data.geo_lat, data.geo_lon,
    data.abuse_score, data.hostname,
    ip, limit,
  );

  const dstResult = updateDstStmt.run(
    data.geo_country, data.geo_city, data.geo_lat, data.geo_lon,
    data.abuse_score, data.hostname,
    ip, limit,
  );

  return { srcChanged: srcResult.changes, dstChanged: dstResult.changes };
}

function runBackfill() {
  const cached = db.prepare(
    'SELECT ip, geo_country, geo_city, geo_lat, geo_lon, abuse_score, hostname FROM ip_enrichment_cache WHERE is_private = 0 AND (geo_country IS NOT NULL OR abuse_score IS NOT NULL)'
  ).all();

  if (cached.length === 0) {
    parentPort.postMessage({ type: 'backfill-done', ips: 0, totalUpdated: 0 });
    return;
  }

  parentPort.postMessage({ type: 'backfill-start', ips: cached.length });

  let offset = 0;
  let totalUpdated = 0;
  const CHUNK_SIZE = 10; // Can be more aggressive since we're off main thread
  const YIELD_MS = 100;  // Yield between chunks to not starve main thread of DB locks

  function processChunk() {
    const chunk = cached.slice(offset, offset + CHUNK_SIZE);
    if (chunk.length === 0) {
      parentPort.postMessage({ type: 'backfill-done', ips: cached.length, totalUpdated });
      return;
    }

    for (const c of chunk) {
      const result = updateEventsWithEnrichment(c.ip, c, 1000);
      totalUpdated += result.srcChanged + result.dstChanged;
    }

    offset += CHUNK_SIZE;

    // Report progress every 50 IPs
    if (offset % 50 === 0) {
      parentPort.postMessage({ type: 'backfill-progress', processed: offset, total: cached.length, totalUpdated });
    }

    setTimeout(processChunk, YIELD_MS);
  }

  processChunk();
}

// Message handler
parentPort.on('message', (msg) => {
  switch (msg.type) {
    case 'update': {
      // Inline enrichment update for a single IP
      const result = updateEventsWithEnrichment(msg.ip, msg.data, msg.batchLimit);
      parentPort.postMessage({ type: 'update-done', ip: msg.ip, ...result });
      break;
    }
    case 'backfill': {
      runBackfill();
      break;
    }
    case 'shutdown': {
      db.close();
      process.exit(0);
      break;
    }
  }
});

parentPort.postMessage({ type: 'ready' });
