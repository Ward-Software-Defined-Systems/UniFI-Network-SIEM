const express = require('express');
const storage = require('../../db/storage');
const { getAvailableBackends } = require('../../db/backends');
const config = require('../../config');
const cryptoUtil = require('../../utils/crypto');
const { SCHEMA, listEntries, CATEGORY_ORDER } = require('../../config/schema');
const logger = require('../../utils/logger');

const router = express.Router();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Map a UI-supplied key to the schema entry. Accepts either the schema's
 * dotted key (`enrichment.abuseIpDbKey`) or its legacyKey (`abuseIpDbKey`).
 */
function findSchemaEntry(uiKey) {
  return SCHEMA.find((e) => e.key === uiKey || e.legacyKey === uiKey) || null;
}

/** Encrypt a string for sensitive storage (no-op for non-sensitive entries). */
function encodeForStorage(entry, value) {
  if (entry.sensitivity === 'private' && typeof value === 'string' && value !== '') {
    return cryptoUtil.encrypt(value);
  }
  return value;
}

/** Decode a stored value: decrypt sensitive, fall through plaintext. */
function decodeFromStorage(entry, value) {
  if (entry.sensitivity === 'private' && typeof value === 'string' && cryptoUtil.isEncrypted(value)) {
    try {
      return cryptoUtil.decrypt(value);
    } catch {
      return ''; // master key wrong; surface as empty rather than ciphertext
    }
  }
  return value;
}

/** Update the in-memory config + persist a single setting. */
async function persistSetting(entry, value) {
  const settingsBackend = storage.getSettingsBackend();
  const dbKey = entry.legacyKey || entry.key;

  // Trim string values defensively (matches the existing AbuseIPDB pattern)
  const trimmed = typeof value === 'string' ? value.trim() : value;

  // Live in-memory update so consumers (e.g. abuseipdb.js) see the new value
  config.applySettingChange(entry.key, trimmed);

  // Persist (encrypted if sensitive)
  await settingsBackend.setSetting(dbKey, encodeForStorage(entry, trimmed));
}

// ---------------------------------------------------------------------------
// Database engine routes (unchanged from prior versions)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Legacy flat-keyed settings API (kept working for the current Settings.jsx).
// Reads/writes are now schema-aware: sensitive values are stored encrypted
// at rest and the route decrypts on read before applying the last-4 mask.
// ---------------------------------------------------------------------------

router.get('/', async (req, res) => {
  try {
    const settingsBackend = storage.getSettingsBackend();
    const rows = await settingsBackend.getAllSettings();

    const settings = {};
    for (const row of rows) {
      // Skip schema-tracked rows that have a dotted key — those are surfaced
      // via /v2. The legacy endpoint only exposes the flat-key namespace
      // that the current UI knows about (abuseIpDbKey, rdnsEnabled, etc.)
      // plus untracked operational rows (database_engine, hunt_*).
      const entry = findSchemaEntry(row.key);
      if (entry && entry.key !== row.key) {
        // legacyKey row — decode + mask sensitive
        const decoded = decodeFromStorage(entry, row.value);
        settings[row.key] = entry.sensitivity === 'private' && decoded
          ? cryptoUtil.maskSensitive(decoded)
          : decoded;
      } else if (!entry) {
        // Untracked row — return as-is (database_engine, hunt_*)
        settings[row.key] = row.value;
      }
      // Schema-key rows (e.g., 'security.masterKey') are intentionally
      // omitted from the legacy endpoint.
    }

    res.json(settings);
  } catch (err) {
    logger.error({ err }, 'GET /api/settings failed');
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

router.put('/', async (req, res) => {
  try {
    const body = { ...req.body };

    for (const [uiKey, rawValue] of Object.entries(body)) {
      const entry = findSchemaEntry(uiKey);
      if (entry) {
        await persistSetting(entry, rawValue);
      } else {
        // Untracked legacy key — pass through as before
        const settingsBackend = storage.getSettingsBackend();
        await settingsBackend.setSetting(uiKey, rawValue);
      }
    }

    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, 'PUT /api/settings failed');
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// ---------------------------------------------------------------------------
// Schema-aware /v2 GET — for the upcoming Settings UI rewrite (Phase 2B2).
// Returns the schema + current values, with sensitive entries masked.
// ---------------------------------------------------------------------------

// Settings keys that are not user-mutable through the UI.
// security.masterKey is the encryption key itself — rotating it requires
// re-encrypting every sensitive row, which is a separate workflow.
const UNMUTABLE_KEYS = new Set(['security.masterKey']);

function readCurrentValue(entry) {
  const parts = entry.key.split('.');
  let cur = config;
  for (const p of parts) {
    if (cur == null) return undefined;
    cur = cur[p];
  }
  return cur;
}

function buildSchemaResponse() {
  const entries = listEntries()
    .filter((e) => !e.hidden)
    .map((entry) => {
      const value = readCurrentValue(entry);
      const masked = entry.sensitivity === 'private' && typeof value === 'string' && value
        ? cryptoUtil.maskSensitive(value)
        : value;
      const isSet = entry.sensitivity === 'private'
        ? typeof value === 'string' && value.length > 0
        : value !== entry.default;
      return {
        key: entry.key,
        type: entry.type,
        category: entry.category,
        description: entry.description,
        default: entry.sensitivity === 'private' ? '' : entry.default,
        sensitivity: entry.sensitivity || 'public',
        envVar: entry.envVar || null,
        requiresRestart: !!entry.requiresRestart,
        readOnly: UNMUTABLE_KEYS.has(entry.key),
        value: masked,
        isSet,
      };
    });

  return { categories: CATEGORY_ORDER, entries };
}

router.get('/v2', async (req, res) => {
  try {
    res.json(buildSchemaResponse());
  } catch (err) {
    logger.error({ err }, 'GET /api/settings/v2 failed');
    res.status(500).json({ error: 'Failed to get settings schema' });
  }
});

/**
 * PUT /api/settings/v2 — body: { key, value }
 * Sets a single schema-tracked setting. Sensitive values are encrypted at
 * rest. Returns the refreshed schema so the UI can render the new state.
 */
router.put('/v2', async (req, res) => {
  try {
    const { key, value } = req.body || {};
    if (typeof key !== 'string') {
      return res.status(400).json({ error: 'key (string) is required' });
    }
    if (UNMUTABLE_KEYS.has(key)) {
      return res.status(403).json({ error: `${key} cannot be modified via the API. Master-key rotation is a separate workflow.` });
    }
    const entry = SCHEMA.find((e) => e.key === key);
    if (!entry) {
      return res.status(404).json({ error: `Unknown setting: ${key}` });
    }

    // Type validation
    if (entry.type === 'number' && value !== '' && !Number.isFinite(Number(value))) {
      return res.status(400).json({ error: `value must be a number for ${key}` });
    }

    // Never accept the masked echo as a real secret. GET masks private values
    // with U+2022 bullets (maskSensitive), which a real key/token never
    // contains. Rejecting here prevents the corrupt-secret / auth.apiToken
    // lockout from ANY client, not just the dashboard UI.
    if (entry.sensitivity === 'private' && typeof value === 'string' && value.includes('•')) {
      return res.status(400).json({ error: `Refusing to store a masked value for ${key}. Type the new secret in full.` });
    }

    await persistSetting(entry, value);
    res.json({ ok: true, schema: buildSchemaResponse() });
  } catch (err) {
    logger.error({ err, key: req.body?.key }, 'PUT /api/settings/v2 failed');
    res.status(500).json({ error: 'Failed to save setting' });
  }
});

/**
 * POST /api/settings/v2/reset — body: { key }
 * Resets a setting to its default by deleting the DB row and reloading
 * the value from .env/default. (Avoids HTTP DELETE-with-body for proxy
 * compatibility.)
 */
router.post('/v2/reset', async (req, res) => {
  try {
    const { key } = req.body || {};
    if (typeof key !== 'string') {
      return res.status(400).json({ error: 'key (string) is required' });
    }
    if (UNMUTABLE_KEYS.has(key)) {
      return res.status(403).json({ error: `${key} cannot be reset via the API.` });
    }
    const entry = SCHEMA.find((e) => e.key === key);
    if (!entry) {
      return res.status(404).json({ error: `Unknown setting: ${key}` });
    }

    const settingsBackend = storage.getSettingsBackend();
    const dbKey = entry.legacyKey || entry.key;
    // Best-effort delete: most backends don't expose a delete primitive,
    // so we set to empty string which is treated as "not set" by the
    // overlay logic, falling back to .env/default.
    await settingsBackend.setSetting(dbKey, '');
    config.applySettingChange(entry.key, entry.default);

    res.json({ ok: true, schema: buildSchemaResponse() });
  } catch (err) {
    logger.error({ err, key: req.body?.key }, 'POST /api/settings/v2/reset failed');
    res.status(500).json({ error: 'Failed to reset setting' });
  }
});

/**
 * POST /api/settings/v2/regenerate-token
 * Generates a new auth.apiToken, encrypts it, persists it, and returns
 * the plaintext value ONCE so the operator can copy it. Subsequent GETs
 * will mask the value.
 */
router.post('/v2/regenerate-token', async (req, res) => {
  try {
    const newToken = cryptoUtil.generateApiToken();
    const settingsBackend = storage.getSettingsBackend();
    await settingsBackend.setSetting('auth.apiToken', cryptoUtil.encrypt(newToken));
    config.applySettingChange('auth.apiToken', newToken);
    logger.warn('API token rotated via /api/settings/v2/regenerate-token');
    res.json({ ok: true, token: newToken });
  } catch (err) {
    logger.error({ err }, 'POST /api/settings/v2/regenerate-token failed');
    res.status(500).json({ error: 'Failed to regenerate token' });
  }
});

// ---------------------------------------------------------------------------
// DB reset — unchanged
// ---------------------------------------------------------------------------

let lastResetAt = null;
const RESET_GRACE_SECONDS = 60;

function getResetGraceStatus() {
  if (!lastResetAt) return null;
  const elapsed = (Date.now() - lastResetAt) / 1000;
  if (elapsed < RESET_GRACE_SECONDS) {
    return { rebuilding: true, secondsLeft: Math.ceil(RESET_GRACE_SECONDS - elapsed) };
  }
  lastResetAt = null;
  return null;
}

router.post('/reset-db', async (req, res) => {
  req.app.locals.pauseSyslog?.();
  try {
    const backend = storage.getBackend();
    await backend.resetData();
    await Promise.race([
      backend.indexesReady,
      new Promise((resolve) => setTimeout(resolve, 300_000)),
    ]);
    lastResetAt = Date.now();
    res.json({ ok: true, gracePeriod: RESET_GRACE_SECONDS });
  } catch (err) {
    logger.error({ err }, 'POST /api/settings/reset-db failed');
    res.status(500).json({ error: 'Failed to reset database' });
  } finally {
    req.app.locals.resumeSyslog?.();
  }
});

module.exports = router;
module.exports.getResetGraceStatus = getResetGraceStatus;
