/**
 * Stats Worker Thread
 *
 * Executes read-only SQLite queries off the main event loop.
 * Opens its own better-sqlite3 connection to the same WAL-mode DB.
 */
const { parentPort, workerData } = require('worker_threads');
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.resolve(workerData.dbPath);
const db = new Database(dbPath, { readonly: true });

db.pragma('cache_size = -128000');  // 128MB — read-heavy, matches main thread
db.pragma('busy_timeout = 30000');  // 30s — wait for write locks from main thread / enrichment worker

parentPort.on('message', (msg) => {
  if (msg.type === 'shutdown') {
    db.close();
    process.exit(0);
  }

  const { id, sql, params, method } = msg;
  try {
    const stmt = db.prepare(sql);
    const result = method === 'get'
      ? stmt.get(...(params || []))
      : stmt.all(...(params || []));
    parentPort.postMessage({ id, result });
  } catch (err) {
    parentPort.postMessage({ id, error: err.message });
  }
});

parentPort.postMessage({ type: 'ready' });
