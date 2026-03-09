/**
 * WardSONDB Storage Backend (Beta — Coming Soon)
 * 
 * High-performance JSON document database built in Rust.
 * REST API client connecting to a WardSONDB server instance.
 * 
 * Status: Stub implementation. WardSONDB is under active development.
 * See: https://github.com/Ward-Software-Defined-Systems/WardSONDB
 */
const StorageBackend = require('./interface');
const logger = require('../../utils/logger');

const NOT_AVAILABLE = 'WardSONDB backend is not yet available. This feature is under active development.';

class WardsonDbBackend extends StorageBackend {
  constructor(config = {}) {
    super('WardSONDB', config);
    this.status = 'coming_soon';
  }

  static get metadata() {
    return {
      name: 'WardSONDB',
      description: 'High-performance Rust-based JSON document database. Optimized for SIEM workloads with selective indexing and low memory footprint.',
      status: 'beta_coming_soon',
      configFields: [
        { key: 'host', label: 'Host', type: 'text', placeholder: 'localhost', default: 'localhost' },
        { key: 'port', label: 'Port', type: 'number', placeholder: '7820', default: 7820 },
        { key: 'apiKey', label: 'API Key', type: 'password', placeholder: 'Optional', default: '' },
        { key: 'useTls', label: 'Use TLS', type: 'boolean', default: false },
      ],
    };
  }

  async initialize() {
    logger.warn({ backend: 'wardsondb' }, NOT_AVAILABLE);
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

module.exports = WardsonDbBackend;
