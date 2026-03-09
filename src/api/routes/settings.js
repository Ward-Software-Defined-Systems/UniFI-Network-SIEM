const express = require('express');
const { getDb, resetDb } = require('../../db/database');
const { getAvailableBackends } = require('../../db/backends');
const config = require('../../config');

const router = express.Router();

// Database engine backends metadata (for Settings UI)
router.get('/database-engines', (req, res) => {
  try {
    const backends = getAvailableBackends();
    const db = getDb();
    // Get current engine from settings (default: sqlite)
    const row = db.prepare("SELECT value FROM settings WHERE key = 'database_engine'").get();
    const activeEngine = row ? JSON.parse(row.value) : 'sqlite';

    // Get engine-specific config if stored
    const configRow = db.prepare("SELECT value FROM settings WHERE key = 'database_engine_config'").get();
    const engineConfig = configRow ? JSON.parse(configRow.value) : {};

    res.json({
      activeEngine,
      engineConfig,
      backends,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get database engines' });
  }
});

router.put('/database-engine', (req, res) => {
  try {
    const { engine, config: engineConfig } = req.body;
    const validEngines = ['sqlite', 'wardsondb', 'opensearch'];
    if (!validEngines.includes(engine)) {
      return res.status(400).json({ error: `Invalid engine: ${engine}. Valid: ${validEngines.join(', ')}` });
    }

    const db = getDb();
    const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    upsert.run('database_engine', JSON.stringify(engine));
    if (engineConfig) {
      // Redact passwords before storing — store actual values
      upsert.run('database_engine_config', JSON.stringify(engineConfig));
    }

    res.json({
      ok: true,
      message: engine === 'sqlite'
        ? 'SQLite backend is active.'
        : `${engine} backend configuration saved. Restart the SIEM to apply changes.`,
      requiresRestart: engine !== 'sqlite',
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save database engine setting' });
  }
});

router.get('/', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare('SELECT key, value FROM settings').all();
    const settings = {};
    for (const row of rows) {
      try { settings[row.key] = JSON.parse(row.value); } catch { settings[row.key] = row.value; }
    }
    // Redact sensitive keys — only indicate presence
    if (settings.abuseIpDbKey) {
      settings.abuseIpDbKey = '••••••••' + settings.abuseIpDbKey.slice(-4);
    }
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

router.put('/', (req, res) => {
  try {
    const db = getDb();
    const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    const txn = db.transaction((entries) => {
      for (const [key, value] of entries) {
        upsert.run(key, JSON.stringify(value));
      }
    });
    txn(Object.entries(req.body));

    // Update in-memory config for keys that take effect immediately
    if (req.body.abuseIpDbKey !== undefined) {
      config.enrichment.abuseIpDbKey = req.body.abuseIpDbKey;
    }
    if (req.body.rdnsEnabled !== undefined) {
      config.enrichment.rdnsEnabled = !!req.body.rdnsEnabled;
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

router.post('/reset-db', (req, res) => {
  try {
    resetDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset database' });
  }
});

module.exports = router;
