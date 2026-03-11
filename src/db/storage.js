/**
 * Storage Manager
 * 
 * Singleton that manages the active storage backend.
 * All database operations route through here.
 * 
 * Settings always use SQLite (needed to boot and select the backend).
 * Events and enrichment cache use the configured backend.
 */
const { createBackend } = require('./backends');
const SqliteBackend = require('./backends/sqlite');
const config = require('../config');
const logger = require('../utils/logger');

let activeBackend = null;
let sqliteForSettings = null; // Always SQLite for settings

async function initialize() {
  // Always init SQLite for settings (needed to read database_engine choice)
  sqliteForSettings = new SqliteBackend({
    path: config.db.path,
    abuseIpDbCacheHours: config.enrichment.abuseIpDbCacheHours,
  });
  await sqliteForSettings.initialize();

  // Read configured engine from settings
  const engineSetting = await sqliteForSettings.getSetting('database_engine');
  const engineId = engineSetting || 'sqlite';
  const engineConfig = await sqliteForSettings.getSetting('database_engine_config') || {};

  if (engineId === 'sqlite') {
    // SQLite is both the settings backend and the data backend
    activeBackend = sqliteForSettings;
    logger.info({ backend: 'sqlite' }, 'Using SQLite storage backend');
  } else {
    // External backend for data, SQLite for settings
    try {
      activeBackend = createBackend(engineId, {
        ...engineConfig,
        abuseIpDbCacheHours: config.enrichment.abuseIpDbCacheHours,
      });
      await activeBackend.initialize();
      logger.info({ backend: engineId }, 'Using external storage backend');
    } catch (err) {
      logger.error({ err, backend: engineId }, 'Failed to initialize storage backend, falling back to SQLite');
      activeBackend = sqliteForSettings;
    }
  }

  return activeBackend;
}

function getBackend() {
  if (!activeBackend) {
    throw new Error('Storage manager not initialized. Call initialize() first.');
  }
  return activeBackend;
}

function getSettingsBackend() {
  if (!sqliteForSettings) {
    throw new Error('Storage manager not initialized. Call initialize() first.');
  }
  return sqliteForSettings;
}

/** Get the raw SQLite db handle (for backward compatibility during migration) */
function getDb() {
  return sqliteForSettings.getDb();
}

function getBackendName() {
  return activeBackend ? activeBackend.name : 'uninitialized';
}

async function close() {
  if (activeBackend && activeBackend !== sqliteForSettings) {
    await activeBackend.close();
  }
  if (sqliteForSettings) {
    await sqliteForSettings.close();
  }
  activeBackend = null;
  sqliteForSettings = null;
}

module.exports = {
  initialize,
  getBackend,
  getSettingsBackend,
  getDb,
  getBackendName,
  close,
};
