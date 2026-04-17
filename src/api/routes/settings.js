const express = require('express');
const storage = require('../../db/storage');
const { getAvailableBackends } = require('../../db/backends');
const config = require('../../config');

const router = express.Router();

// Database engine backends metadata (for Settings UI)
router.get('/database-engines', async (req, res) => {
  try {
    const backends = getAvailableBackends();
    const settingsBackend = storage.getSettingsBackend();
    const activeEngine = await settingsBackend.getSetting('database_engine') || 'sqlite';
    const engineConfig = await settingsBackend.getSetting('database_engine_config') || {};

    res.json({
      activeEngine,
      engineConfig,
      backends,
      currentBackend: storage.getBackendName(),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get database engines' });
  }
});

router.put('/database-engine', async (req, res) => {
  try {
    const { engine, config: engineConfig } = req.body;
    const validEngines = ['sqlite', 'wardsondb', 'opensearch'];
    if (!validEngines.includes(engine)) {
      return res.status(400).json({ error: `Invalid engine: ${engine}. Valid: ${validEngines.join(', ')}` });
    }

    const settingsBackend = storage.getSettingsBackend();
    await settingsBackend.setSetting('database_engine', engine);
    if (engineConfig) {
      await settingsBackend.setSetting('database_engine_config', engineConfig);
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

router.get('/', async (req, res) => {
  try {
    const settingsBackend = storage.getSettingsBackend();
    const rows = await settingsBackend.getAllSettings();
    const settings = {};
    for (const row of rows) {
      try { settings[row.key] = JSON.parse(row.value); } catch { settings[row.key] = row.value; }
    }
    if (settings.abuseIpDbKey) {
      settings.abuseIpDbKey = '••••••••' + settings.abuseIpDbKey.slice(-4);
    }
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

router.put('/', async (req, res) => {
  try {
    const settingsBackend = storage.getSettingsBackend();
    const body = { ...req.body };
    if (typeof body.abuseIpDbKey === 'string') {
      body.abuseIpDbKey = body.abuseIpDbKey.trim();
    }

    for (const [key, value] of Object.entries(body)) {
      await settingsBackend.setSetting(key, value);
    }

    if (body.abuseIpDbKey !== undefined) {
      config.enrichment.abuseIpDbKey = body.abuseIpDbKey;
    }
    if (body.rdnsEnabled !== undefined) {
      config.enrichment.rdnsEnabled = !!body.rdnsEnabled;
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// Grace period after DB reset — suppress heavy queries while indexes rebuild
let lastResetAt = null;
const RESET_GRACE_SECONDS = 60;

function getResetGraceStatus() {
  if (!lastResetAt) return null;
  const elapsed = (Date.now() - lastResetAt) / 1000;
  if (elapsed < RESET_GRACE_SECONDS) {
    return { rebuilding: true, secondsLeft: Math.ceil(RESET_GRACE_SECONDS - elapsed) };
  }
  lastResetAt = null; // Grace period over, clear
  return null;
}

router.post('/reset-db', async (req, res) => {
  // Pause syslog ingestion to avoid write contention during reset + index creation
  req.app.locals.pauseSyslog?.();
  try {
    const backend = storage.getBackend();
    await backend.resetData();
    // Wait for indexes to be fully built before resuming ingestion (WardSONDB).
    // SQLite resolves immediately. 5-minute safety ceiling prevents permanent pause.
    await Promise.race([
      backend.indexesReady,
      new Promise(resolve => setTimeout(resolve, 300_000)),
    ]);
    lastResetAt = Date.now();
    res.json({ ok: true, gracePeriod: RESET_GRACE_SECONDS });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset database' });
  } finally {
    req.app.locals.resumeSyslog?.();
  }
});

// Export router + helper for health endpoint
module.exports = router;
module.exports.getResetGraceStatus = getResetGraceStatus;
