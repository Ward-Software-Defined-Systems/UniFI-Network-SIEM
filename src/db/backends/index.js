/**
 * Storage Backend Registry & Factory
 * 
 * Central module for backend discovery and instantiation.
 * Settings page uses getAvailableBackends() for the UI.
 * Startup uses createBackend() to instantiate the configured engine.
 */
const SqliteBackend = require('./sqlite');
const WardsonDbBackend = require('./wardsondb');
const OpenSearchBackend = require('./opensearch');

const BACKENDS = {
  sqlite: SqliteBackend,
  wardsondb: WardsonDbBackend,
  opensearch: OpenSearchBackend,
};

/**
 * Get metadata for all available backends (for Settings UI).
 */
function getAvailableBackends() {
  return [
    {
      id: 'sqlite',
      name: 'SQLite (Built-in)',
      description: 'Zero-dependency embedded database. Best for single-node deployments and getting started quickly.',
      status: 'stable',
      configFields: [],
      isDefault: true,
    },
    {
      ...WardsonDbBackend.metadata,
      id: 'wardsondb',
    },
    {
      id: 'opensearch',
      ...OpenSearchBackend.metadata,
      id: 'opensearch',
    },
  ];
}

/**
 * Create a backend instance by ID.
 * @param {string} id - Backend identifier (sqlite, wardsondb, opensearch)
 * @param {object} config - Backend-specific configuration
 * @returns {StorageBackend}
 */
function createBackend(id, config = {}) {
  const BackendClass = BACKENDS[id];
  if (!BackendClass) {
    throw new Error(`Unknown storage backend: ${id}. Available: ${Object.keys(BACKENDS).join(', ')}`);
  }
  return new BackendClass(config);
}

module.exports = { getAvailableBackends, createBackend, BACKENDS };
