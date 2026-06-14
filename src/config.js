/**
 * Schema-driven config loader.
 *
 * Strategy:
 *   1. Read the schema (`src/config/schema.js`) — single source of truth.
 *   2. Build a defaults-only nested object from each entry's `default` and
 *      dotted `key`.
 *   3. Overlay any matching env vars (after `dotenv.config()`).
 *   4. Export the nested object — keeps the existing `config.X.y` shape so
 *      no current consumer changes.
 *   5. Expose `applyDbOverrides(rows)` (called from `src/index.js` after
 *      storage.initialize()) and `applySettingChange(key, value)` (used by
 *      the settings PUT route) to update both the in-memory object and the
 *      DB.
 *
 * Sensitive values are decrypted on read via `src/utils/crypto.js`. The
 * crypto module is a no-op until `setMasterKey()` is called (which happens
 * during the DB-overlay step).
 */

require('dotenv').config();

const { SCHEMA } = require('./config/schema');
const crypto = require('./utils/crypto');

function setDeep(obj, dottedKey, value) {
  const parts = dottedKey.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i];
    if (cur[k] == null || typeof cur[k] !== 'object') cur[k] = {};
    cur = cur[k];
  }
  cur[parts[parts.length - 1]] = value;
}

function getDeep(obj, dottedKey) {
  const parts = dottedKey.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[p];
  }
  return cur;
}

function coerce(rawValue, type) {
  if (rawValue == null) return rawValue;
  switch (type) {
    case 'number': {
      const n = typeof rawValue === 'number' ? rawValue : parseFloat(rawValue);
      return Number.isFinite(n) ? n : null;
    }
    case 'boolean':
      if (typeof rawValue === 'boolean') return rawValue;
      // Match dotenv conventions used historically by this codebase
      return rawValue === 'true' || rawValue === true || rawValue === '1' || rawValue === 1;
    case 'string':
    default:
      return typeof rawValue === 'string' ? rawValue : String(rawValue);
  }
}

// -----------------------------------------------------------------------------
// Build the initial config object from schema defaults + .env overlay.
// -----------------------------------------------------------------------------
const config = {};

for (const entry of SCHEMA) {
  let value = entry.default;

  if (entry.envVar && process.env[entry.envVar] !== undefined && process.env[entry.envVar] !== '') {
    value = coerce(process.env[entry.envVar], entry.type);
  }

  // For booleans, .env strings 'false' should produce false even if envVar is set
  if (entry.type === 'boolean' && entry.envVar && process.env[entry.envVar] !== undefined) {
    value = coerce(process.env[entry.envVar], 'boolean');
  }

  setDeep(config, entry.key, value);
}

// -----------------------------------------------------------------------------
// DB overlay — called from src/index.js after storage.initialize().
// `rows` is an array of { key, value } from the settings backend, where
// `value` is already JSON-parsed (matches the existing settings backend
// contract). Schema entries with a `legacyKey` resolve against that key in
// the DB, so existing rows like `abuseIpDbKey` keep their storage shape.
//
// Returns a list of `{key, plaintext}` for sensitive entries whose stored
// value was plaintext (no `v1:` prefix). Caller can iterate this list to
// re-write encrypted values, completing the migration. The in-memory
// config is updated either way.
// -----------------------------------------------------------------------------
function applyDbOverrides(rows) {
  const rowMap = new Map((rows || []).map((r) => [r.key, r.value]));
  const plaintextSensitive = [];
  const decryptFailures = [];

  for (const entry of SCHEMA) {
    const dbKey = entry.legacyKey || entry.key;
    if (!rowMap.has(dbKey)) continue;
    let value = rowMap.get(dbKey);

    if (entry.sensitivity === 'private' && typeof value === 'string' && !entry.noEncrypt) {
      if (crypto.isEncrypted(value)) {
        try {
          value = crypto.decrypt(value);
        } catch (err) {
          // Master key missing or wrong. Common cause: the row was encrypted
          // under a different master key (DB restored from backup, master key
          // env-overridden, or rotated without re-encrypt). Skip silently —
          // this is collected up by the caller via decryptFailures so a
          // single startup-time warning can list affected keys.
          decryptFailures.push({ key: entry.key, dbKey });
          continue;
        }
      } else if (value !== '') {
        // Plaintext sensitive value — flag for migration write-back.
        plaintextSensitive.push({ schemaKey: entry.key, dbKey, plaintext: value });
      }
    }
    // noEncrypt entries (e.g. security.masterKey) pass through plaintext.

    if (typeof value === 'string' && entry.type === 'boolean') value = coerce(value, 'boolean');
    if (typeof value === 'string' && entry.type === 'number') value = coerce(value, 'number');

    if (value === null || value === undefined) continue;
    if (entry.type === 'string' && value === '' && entry.default !== '') {
      // Treat empty-string DB values as "not set" so they don't clobber a
      // real .env or default value. Matches the existing AbuseIPDB precedent.
      continue;
    }

    setDeep(config, entry.key, value);
  }

  return { plaintextSensitive, decryptFailures };
}

/** Apply a single setting change (used by the settings PUT route). */
function applySettingChange(key, value) {
  const entry = SCHEMA.find((e) => e.key === key);
  if (!entry) return false;
  const coerced = coerce(value, entry.type);
  setDeep(config, key, coerced);
  return true;
}

/** Get the current value of a schema setting via dotted key. */
function get(key) {
  return getDeep(config, key);
}

module.exports = config;
module.exports.applyDbOverrides = applyDbOverrides;
module.exports.applySettingChange = applySettingChange;
module.exports.get = get;
module.exports._coerce = coerce; // exposed for tests
