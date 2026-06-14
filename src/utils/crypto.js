/**
 * AES-256-GCM helpers for sensitive settings at rest.
 *
 * Format: `v1:<iv-b64>:<authTag-b64>:<ciphertext-b64>`
 *
 * Master key resolution (in order):
 *   1. process.env.SIEM_MASTER_KEY (hex, 64 chars = 32 bytes)
 *   2. The runtime-supplied key from `setMasterKey(buf)` (used after DB load
 *      reveals the auto-generated key from the `security.masterKey` row)
 *   3. null — encrypt/decrypt are no-ops, returning input unchanged. This is
 *      the bootstrap state before storage.initialize() resolves the key.
 *
 * Idempotency: `decrypt()` returns its input unchanged if it doesn't carry the
 * `v1:` prefix, so plaintext rows pre-migration round-trip cleanly.
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;          // GCM-recommended IV size
const KEY_BYTES = 32;         // AES-256
const VERSION_PREFIX = 'v1:';

let runtimeKey = null;        // populated via setMasterKey()

/** Parse a hex/base64 master key into a 32-byte Buffer. */
function parseKey(value) {
  if (!value || typeof value !== 'string') return null;
  // Hex (64 chars) — preferred for env vars
  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    return Buffer.from(value, 'hex');
  }
  // Otherwise, derive deterministically by SHA-256ing the input. This lets
  // operators paste any string of any length and get a stable 32-byte key,
  // at the cost of weaker entropy if they pick something short. Auto-gen
  // always produces 64-hex.
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

/** Resolve the active master key Buffer or null. */
function getMasterKey() {
  if (runtimeKey) return runtimeKey;
  const fromEnv = parseKey(process.env.SIEM_MASTER_KEY);
  if (fromEnv) return fromEnv;
  return null;
}

/** Set the runtime master key (called after storage layer loads it). */
function setMasterKey(value) {
  if (value == null) {
    runtimeKey = null;
    return;
  }
  if (Buffer.isBuffer(value) && value.length === KEY_BYTES) {
    runtimeKey = value;
    return;
  }
  const parsed = parseKey(typeof value === 'string' ? value : value.toString());
  if (!parsed) throw new Error('crypto: setMasterKey requires hex/base64 key or 32-byte Buffer');
  runtimeKey = parsed;
}

function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(VERSION_PREFIX);
}

/** Generate a fresh 32-byte master key, returned as 64 hex chars. */
function generateMasterKey() {
  return crypto.randomBytes(KEY_BYTES).toString('hex');
}

/** Generate a random API token (32 bytes → 64 hex chars). */
function generateApiToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Encrypt a plaintext string. Returns the encoded form.
 * If no master key is available, returns the plaintext unchanged (boot state).
 */
function encrypt(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('crypto.encrypt: plaintext must be a string');
  }
  const key = getMasterKey();
  if (!key) return plaintext;        // pre-bootstrap — no-op
  if (isEncrypted(plaintext)) return plaintext; // already encrypted

  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    VERSION_PREFIX.replace(/:$/, ''),
    iv.toString('base64'),
    tag.toString('base64'),
    ct.toString('base64'),
  ].join(':');
}

/**
 * Decrypt an encoded string. If the input is plaintext (missing the v1:
 * prefix) it is returned unchanged. Throws on tag-verification failure.
 */
function decrypt(value) {
  if (typeof value !== 'string') return value;
  if (!isEncrypted(value)) return value;

  const key = getMasterKey();
  if (!key) {
    throw new Error('crypto.decrypt: no master key available — set SIEM_MASTER_KEY or call setMasterKey() before reading sensitive settings');
  }

  const parts = value.split(':');
  if (parts.length !== 4 || parts[0] !== VERSION_PREFIX.replace(/:$/, '')) {
    throw new Error('crypto.decrypt: malformed ciphertext envelope');
  }
  const iv = Buffer.from(parts[1], 'base64');
  const tag = Buffer.from(parts[2], 'base64');
  const ct = Buffer.from(parts[3], 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** Mask a sensitive value for UI display: last-4 chars visible. */
function maskSensitive(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  if (value.length <= 4) return '••••';
  return '••••••••' + value.slice(-4);
}

module.exports = {
  encrypt,
  decrypt,
  isEncrypted,
  getMasterKey,
  setMasterKey,
  generateMasterKey,
  generateApiToken,
  maskSensitive,
};
