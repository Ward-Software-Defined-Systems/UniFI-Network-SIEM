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
    for (const [key, value] of Object.entries(req.body)) {
      await settingsBackend.setSetting(key, value);
    }

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
  try {
    const backend = storage.getBackend();
    await backend.resetData();
    lastResetAt = Date.now();
    res.json({ ok: true, gracePeriod: RESET_GRACE_SECONDS });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset database' });
  }
});

// Export router + helper for health endpoint
module.exports = router;
module.exports.getResetGraceStatus = getResetGraceStatus;
