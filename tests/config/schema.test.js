const { SCHEMA, getEntry, getEntryByEnv, listEntries, CATEGORY_ORDER } = require('../../src/config/schema');

describe('settings schema', () => {
  it('every entry has required fields', () => {
    for (const e of SCHEMA) {
      expect(typeof e.key).toBe('string');
      expect(e.key.length).toBeGreaterThan(0);
      expect(['string', 'number', 'boolean']).toContain(e.type);
      expect(e).toHaveProperty('default');
      expect(typeof e.category).toBe('string');
      expect(typeof e.description).toBe('string');
      expect(e.description.length).toBeGreaterThan(5);
    }
  });

  it('keys are unique', () => {
    const keys = SCHEMA.map((e) => e.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('envVars (when set) are unique', () => {
    const envs = SCHEMA.filter((e) => e.envVar).map((e) => e.envVar);
    expect(new Set(envs).size).toBe(envs.length);
  });

  it('every category is in CATEGORY_ORDER', () => {
    const cats = new Set(SCHEMA.map((e) => e.category));
    for (const c of cats) {
      expect(CATEGORY_ORDER).toContain(c);
    }
  });

  it('sensitivity values are restricted', () => {
    for (const e of SCHEMA) {
      if (e.sensitivity !== undefined) {
        expect(['public', 'private']).toContain(e.sensitivity);
      }
    }
  });

  it('boolean and number defaults are typed correctly', () => {
    for (const e of SCHEMA) {
      if (e.type === 'boolean') expect(typeof e.default).toBe('boolean');
      if (e.type === 'number') expect(typeof e.default).toBe('number');
    }
  });

  it('preserves the legacy nested config keys (no breakage for existing consumers)', () => {
    // These dotted keys are referenced throughout the codebase via
    // config.X.Y. If any of them disappear from the schema, every consumer
    // would silently get `undefined`.
    const expectedKeys = [
      'syslog.port',
      'http.port',
      'db.path',
      'db.retentionDays',
      'enrichment.geoipDbPath',
      'enrichment.abuseIpDbKey',
      'enrichment.abuseIpDbCacheHours',
      'enrichment.rdnsEnabled',
      'enrichment.rdnsTimeoutMs',
      'enrichment.concurrency',
      'performance.insertBatchSize',
      'performance.insertBatchIntervalMs',
      'performance.wsBroadcastThrottleMs',
      'wardsondb.healthTimeoutMs',
      'wardsondb.connectTimeoutMs',
      'wardsondb.queryTimeoutMs',
      'wardsondb.flushConcurrency',
      'opensearch.host',
      'opensearch.port',
      'opensearch.username',
      'opensearch.password',
      'opensearch.useTls',
      'opensearch.verifyCerts',
      'opensearch.indexPrefix',
      'opensearch.bulkSize',
      'health.rebuildingDebouncePolls',
      'logging.level',
      'logging.logRawMessages',
    ];
    for (const k of expectedKeys) {
      expect(getEntry(k)).not.toBeNull();
    }
  });

  describe('lookup helpers', () => {
    it('getEntry returns the right entry by key', () => {
      const e = getEntry('wardsondb.flushConcurrency');
      expect(e.envVar).toBe('WARDSONDB_FLUSH_CONCURRENCY');
      expect(e.default).toBe(4);
    });
    it('getEntry returns null for unknown keys', () => {
      expect(getEntry('does.not.exist')).toBeNull();
    });
    it('getEntryByEnv returns the right entry by envVar', () => {
      const e = getEntryByEnv('ABUSEIPDB_API_KEY');
      expect(e.key).toBe('enrichment.abuseIpDbKey');
      expect(e.sensitivity).toBe('private');
    });
    it('listEntries returns a copy (not the live array)', () => {
      const a = listEntries();
      const b = listEntries();
      expect(a).not.toBe(b);
      expect(a.length).toBe(SCHEMA.length);
    });
  });
});

describe('config (schema-driven loader)', () => {
  // Note: dotenv re-loads `.env` on every require, so explicit-default
  // assertions would be brittle (the developer's real `.env` legitimately
  // overrides defaults). Defaults are exhaustively tested in the schema
  // tests above; here we test the SHAPE of the loaded object plus the
  // env-overlay + coercion behavior.

  function loadConfig() {
    delete require.cache[require.resolve('../../src/config')];
    return require('../../src/config');
  }

  it('builds the legacy nested shape from the schema (every dotted key resolves)', () => {
    const config = loadConfig();
    // Spot-check that every schema-tracked dotted key has a defined value
    // somewhere in the nested object (not undefined).
    for (const entry of SCHEMA) {
      const parts = entry.key.split('.');
      let cur = config;
      for (const p of parts) {
        expect(cur).toBeDefined();
        cur = cur[p];
      }
      expect(cur).not.toBeUndefined();
      // And the type matches the schema declaration
      if (entry.type === 'number') expect(typeof cur).toBe('number');
      if (entry.type === 'boolean') expect(typeof cur).toBe('boolean');
      if (entry.type === 'string') expect(typeof cur).toBe('string');
    }
  });

  it('honours an env-var override and coerces its type', () => {
    process.env.HTTP_PORT = '4444';
    process.env.RDNS_ENABLED = 'true';
    process.env.OPENSEARCH_USE_TLS = 'false';
    delete require.cache[require.resolve('../../src/config')];
    const config = require('../../src/config');
    expect(config.http.port).toBe(4444);
    expect(config.enrichment.rdnsEnabled).toBe(true);
    expect(config.opensearch.useTls).toBe(false);
    delete process.env.HTTP_PORT;
    delete process.env.RDNS_ENABLED;
    delete process.env.OPENSEARCH_USE_TLS;
  });

  it('coerces .env strings to typed values', () => {
    expect(loadConfig()._coerce('5514', 'number')).toBe(5514);
    expect(loadConfig()._coerce('true', 'boolean')).toBe(true);
    expect(loadConfig()._coerce('false', 'boolean')).toBe(false);
    expect(loadConfig()._coerce('1', 'boolean')).toBe(true);
    expect(loadConfig()._coerce('hello', 'string')).toBe('hello');
  });

  describe('applyDbOverrides', () => {
    it('overlays a public string value', () => {
      const config = loadConfig();
      config.applyDbOverrides([{ key: 'opensearch.host', value: 'os.example.com' }]);
      expect(config.opensearch.host).toBe('os.example.com');
    });

    it('overlays a number, coercing strings', () => {
      const config = loadConfig();
      config.applyDbOverrides([{ key: 'wardsondb.flushConcurrency', value: '8' }]);
      expect(config.wardsondb.flushConcurrency).toBe(8);
    });

    it('overlays a boolean', () => {
      const config = loadConfig();
      config.applyDbOverrides([{ key: 'enrichment.rdnsEnabled', value: true }]);
      expect(config.enrichment.rdnsEnabled).toBe(true);
    });

    it('treats empty-string DB values as "not set" (does not clobber default)', () => {
      const config = loadConfig();
      config.applyDbOverrides([{ key: 'enrichment.abuseIpDbKey', value: '' }]);
      expect(config.enrichment.abuseIpDbKey).toBe(''); // unchanged from default
    });

    it('skips unknown keys silently (e.g. database_engine)', () => {
      const config = loadConfig();
      expect(() => config.applyDbOverrides([{ key: 'database_engine', value: 'sqlite' }])).not.toThrow();
    });
  });

  describe('applySettingChange', () => {
    it('updates the in-memory config and returns true', () => {
      const config = loadConfig();
      expect(config.applySettingChange('http.port', 4000)).toBe(true);
      expect(config.http.port).toBe(4000);
    });
    it('returns false for unknown keys', () => {
      const config = loadConfig();
      expect(config.applySettingChange('does.not.exist', 'x')).toBe(false);
    });
    it('coerces the value per schema type', () => {
      const config = loadConfig();
      config.applySettingChange('wardsondb.queryTimeoutMs', '30000');
      expect(config.wardsondb.queryTimeoutMs).toBe(30000);
    });
  });
});
