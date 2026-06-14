/**
 * Bearer-token auth middleware for the SIEM API + WebSocket.
 *
 * The expected token lives in `config.auth.apiToken` (set during
 * bootstrapSettings on startup; auto-generated if missing). All comparisons
 * use timingSafeEqual to avoid timing-side-channel leaks.
 *
 * - `requireApiToken` — Express middleware applied to /api/* routers.
 * - `validateWsToken` — used in the WebSocketServer's verifyClient hook.
 */

const crypto = require('crypto');
const config = require('../../config');
const logger = require('../../utils/logger');

function constantTimeCompare(a, b) {
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

let _missingTokenWarned = false;
function warnMissingToken() {
  if (_missingTokenWarned) return;
  _missingTokenWarned = true;
  logger.warn('config.auth.apiToken is empty — every authenticated request will fail with 503 until a token is configured. Use bootstrap (auto-gen on startup), set SIEM_API_TOKEN in .env, or POST /api/settings/v2/regenerate-token to set one.');
}

function requireApiToken(req, res, next) {
  const expected = config.auth.apiToken;
  if (!expected) {
    warnMissingToken();
    return res.status(503).json({ error: 'Server has no auth token configured. Contact the operator.' });
  }
  const header = req.headers.authorization || '';
  const provided = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!provided) {
    return res.status(401).json({ error: 'Missing Authorization: Bearer <token>' });
  }
  if (!constantTimeCompare(expected, provided)) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  next();
}

function validateWsToken(token) {
  const expected = config.auth.apiToken;
  if (!expected || typeof token !== 'string' || token.length === 0) return false;
  return constantTimeCompare(expected, token);
}

module.exports = { requireApiToken, validateWsToken, constantTimeCompare };
