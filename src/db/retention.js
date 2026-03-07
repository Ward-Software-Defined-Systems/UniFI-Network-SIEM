const { getDb } = require('./database');
const config = require('../config');
const logger = require('../utils/logger');

function runRetentionCleanup() {
  try {
    const db = getDb();
    const days = config.db.retentionDays;
    const result = db.prepare(
      "DELETE FROM events WHERE received_at < datetime('now', ?)"
    ).run(`-${days} days`);

    if (result.changes > 0) {
      logger.info({ deleted: result.changes, retentionDays: days }, 'Retention cleanup completed');
    }
  } catch (err) {
    logger.error({ err }, 'Retention cleanup failed');
  }
}

function startRetentionSchedule() {
  // Run cleanup every hour
  runRetentionCleanup();
  return setInterval(runRetentionCleanup, 60 * 60 * 1000);
}

module.exports = { runRetentionCleanup, startRetentionSchedule };
