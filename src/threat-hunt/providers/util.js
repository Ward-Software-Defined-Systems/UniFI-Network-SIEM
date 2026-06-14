const logger = require('../../utils/logger');

/**
 * L1: throw an LLM-provider error that's safe to surface to the dashboard.
 * The raw upstream body is logged server-side (at warn level), but the
 * thrown Error carries only the provider name + HTTP status — no body —
 * because the upstream sometimes echoes prompt fragments, internal IDs,
 * rate-limit details, or quota messages that the operator's UI shouldn't
 * leak verbatim.
 */
async function throwSanitizedProviderError(provider, res) {
  let body = '';
  try {
    body = await res.text();
  } catch {}
  logger.warn(
    { provider, status: res.status, body: body.slice(0, 2000) },
    'LLM provider returned non-OK response',
  );
  const err = new Error(`${provider} API error (HTTP ${res.status})`);
  err.providerStatus = res.status;
  throw err;
}

module.exports = { throwSanitizedProviderError };
