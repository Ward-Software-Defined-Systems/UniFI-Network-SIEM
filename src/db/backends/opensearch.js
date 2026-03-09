/**
 * OpenSearch Storage Backend (Beta — Coming Soon)
 * 
 * Connects to an OpenSearch cluster for high-scale SIEM deployments.
 * Uses OpenSearch's native JSON document storage, aggregation pipeline,
 * and Index State Management for retention.
 * 
 * Status: Stub implementation. Integration under development.
 */
const StorageBackend = require('./interface');
const logger = require('../../utils/logger');

const NOT_AVAILABLE = 'OpenSearch backend is not yet available. This feature is under active development.';

class OpenSearchBackend extends StorageBackend {
  constructor(config = {}) {
    super('OpenSearch', config);
    this.status = 'coming_soon';
  }

  static get metadata() {
    return {
      name: 'OpenSearch',
      description: 'Enterprise-grade search and analytics engine. Ideal for large-scale deployments with built-in dashboards, security analytics, and SIEM capabilities.',
      status: 'beta_coming_soon',
      configFields: [
        { key: 'host', label: 'Host', type: 'text', placeholder: 'localhost', default: 'localhost' },
        { key: 'port', label: 'Port', type: 'number', placeholder: '9200', default: 9200 },
        { key: 'username', label: 'Username', type: 'text', placeholder: 'admin', default: 'admin' },
        { key: 'password', label: 'Password', type: 'password', placeholder: 'Required', default: '' },
        { key: 'useTls', label: 'Use TLS', type: 'boolean', default: true },
        { key: 'verifyCerts', label: 'Verify Certificates', type: 'boolean', default: false },
        { key: 'indexPrefix', label: 'Index Prefix', type: 'text', placeholder: 'unifi-events', default: 'unifi-events' },
      ],
    };
  }

  async initialize() {
    logger.warn({ backend: 'opensearch' }, NOT_AVAILABLE);
    throw new Error(NOT_AVAILABLE);
  }

  async close() {}
  async healthCheck() { return { ok: false, details: { status: 'coming_soon', message: NOT_AVAILABLE } }; }

  // All operations throw until implemented
  async insertEvents() { throw new Error(NOT_AVAILABLE); }
  async updateEnrichment() { throw new Error(NOT_AVAILABLE); }
  async queryEvents() { throw new Error(NOT_AVAILABLE); }
  async getEventById() { throw new Error(NOT_AVAILABLE); }
  async getEventCount() { throw new Error(NOT_AVAILABLE); }
  async getEventCountToday() { throw new Error(NOT_AVAILABLE); }
  async getLastEventTime() { throw new Error(NOT_AVAILABLE); }
  async getEventTypeCounts() { throw new Error(NOT_AVAILABLE); }
  async getOverviewStats() { throw new Error(NOT_AVAILABLE); }
  async getTimeline() { throw new Error(NOT_AVAILABLE); }
  async getTopTalkers() { throw new Error(NOT_AVAILABLE); }
  async getTopBlocked() { throw new Error(NOT_AVAILABLE); }
  async getTopPorts() { throw new Error(NOT_AVAILABLE); }
  async getTopClients() { throw new Error(NOT_AVAILABLE); }
  async getTopThreats() { throw new Error(NOT_AVAILABLE); }
  async getThreatIntel() { throw new Error(NOT_AVAILABLE); }
  async getGeoEvents() { throw new Error(NOT_AVAILABLE); }
  async getRecentGeoEvents() { throw new Error(NOT_AVAILABLE); }
  async getCachedEnrichment() { throw new Error(NOT_AVAILABLE); }
  async setCachedEnrichment() { throw new Error(NOT_AVAILABLE); }
  async markPrivate() { throw new Error(NOT_AVAILABLE); }
  async getAllCachedEnrichment() { throw new Error(NOT_AVAILABLE); }
  async runRetention() { throw new Error(NOT_AVAILABLE); }
  async resetData() { throw new Error(NOT_AVAILABLE); }
  async getSetting() { throw new Error(NOT_AVAILABLE); }
  async setSetting() { throw new Error(NOT_AVAILABLE); }
  async getAllSettings() { throw new Error(NOT_AVAILABLE); }
}

module.exports = OpenSearchBackend;
