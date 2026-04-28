const express = require('express');
const storage = require('../../db/storage');
const config = require('../../config');
const cryptoUtil = require('../../utils/crypto');
const { SCHEMA } = require('../../config/schema');
const logger = require('../../utils/logger');
const { getSinceOptional } = require('../../utils/period');
const { buildInvestigationPrompt } = require('../../threat-hunt/prompt');
const anthropicProvider = require('../../threat-hunt/providers/anthropic');
const openaiProvider = require('../../threat-hunt/providers/openai');
const geminiProvider = require('../../threat-hunt/providers/gemini');

const router = express.Router();

// Period selector — same options as Dashboard / Live Map / Threat Intel.
// When the request body omits `period` entirely the queries revert to main's
// all-time behavior (no time filter). The UI always sends a period so this
// only affects direct API callers.
const getSince = (period) => getSinceOptional(period);

// Map UI-facing keys (provider, anthropicKey, etc.) to schema entries so the
// existing /api/threat-hunt/settings shape keeps working. Each key's row in
// the DB lives under its legacyKey ('hunt_*'); applyDbOverrides decrypts at
// startup and the bootstrap migration auto-encrypts any previously-plaintext
// hunt_* rows on first read.
const HUNT_KEY_MAP = {
  provider: SCHEMA.find((e) => e.key === 'threathunt.provider'),
  anthropicKey: SCHEMA.find((e) => e.key === 'threathunt.anthropicKey'),
  openaiKey: SCHEMA.find((e) => e.key === 'threathunt.openaiKey'),
  geminiKey: SCHEMA.find((e) => e.key === 'threathunt.geminiKey'),
};

function maskKey(value) {
  if (!value) return '';
  return value.length <= 4 ? '••••' : '••••••••' + value.slice(-4);
}

function getActiveKey() {
  switch (config.threathunt.provider) {
    case 'anthropic': return config.threathunt.anthropicKey;
    case 'openai': return config.threathunt.openaiKey;
    case 'gemini': return config.threathunt.geminiKey;
    default: return null;
  }
}

function getProvider() {
  switch (config.threathunt.provider) {
    case 'anthropic': return anthropicProvider;
    case 'openai': return openaiProvider;
    case 'gemini': return geminiProvider;
    default: return null;
  }
}

// GET /api/threat-hunt/settings — masked view backed by config.threathunt.*
router.get('/settings', (req, res) => {
  const t = config.threathunt;
  res.json({
    provider: t.provider,
    anthropicKey: maskKey(t.anthropicKey),
    openaiKey: maskKey(t.openaiKey),
    geminiKey: maskKey(t.geminiKey),
    hasAnthropicKey: !!t.anthropicKey,
    hasOpenaiKey: !!t.openaiKey,
    hasGeminiKey: !!t.geminiKey,
  });
});

// PUT /api/threat-hunt/settings — schema-aware: sensitive values are encrypted
// at rest, in-memory config is updated immediately so live calls see new keys.
router.put('/settings', async (req, res) => {
  try {
    const settingsBackend = storage.getSettingsBackend();
    for (const [uiKey, rawValue] of Object.entries(req.body || {})) {
      const entry = HUNT_KEY_MAP[uiKey];
      if (!entry) continue; // ignore unknown keys
      const trimmed = typeof rawValue === 'string' ? rawValue.trim() : rawValue;
      const dbKey = entry.legacyKey || entry.key;
      const stored = entry.sensitivity === 'private' && typeof trimmed === 'string' && trimmed !== ''
        ? cryptoUtil.encrypt(trimmed)
        : trimmed;
      await settingsBackend.setSetting(dbKey, stored);
      config.applySettingChange(entry.key, trimmed);
    }
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, 'PUT /api/threat-hunt/settings failed');
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// POST /api/threat-hunt/investigate (non-streaming fallback)
router.post('/investigate', async (req, res) => {
  const { target, period } = req.body;
  if (!target) return res.status(400).json({ error: 'Target IP or hostname required' });

  const provider = getProvider();
  const key = getActiveKey();
  if (!provider) return res.status(400).json({ error: `Unknown provider: ${config.threathunt.provider}` });
  if (!key) return res.status(400).json({ error: `No API key configured for ${config.threathunt.provider}` });

  try {
    const since = period ? getSince(period) : null; // null = all-time
    const backend = storage.getBackend();

    const intel = await backend.gatherHuntIntel(target, since);
    const external = await gatherExternalIntel(target);

    const prompt = buildInvestigationPrompt(target, intel, external, period || null);
    const analysis = await provider.invoke(prompt, key);

    res.json({
      target,
      period: period || null,
      provider: config.threathunt.provider,
      intel,
      external,
      analysis,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    logger.warn({ err, target }, 'Threat hunt investigation failed');
    res.status(500).json({ error: err.message || 'Investigation failed' });
  }
});

// POST /api/threat-hunt/investigate-stream (SSE streaming)
router.post('/investigate-stream', async (req, res) => {
  const { target, period } = req.body;
  if (!target) return res.status(400).json({ error: 'Target IP or hostname required' });

  const provider = getProvider();
  const key = getActiveKey();
  if (!provider) return res.status(400).json({ error: `Unknown provider: ${config.threathunt.provider}` });
  if (!key) return res.status(400).json({ error: `No API key configured for ${config.threathunt.provider}` });

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // M13: disable per-request and per-socket timeouts on the SSE stream.
  // Long Threat Hunt streams (128K tokens + adaptive thinking) routinely
  // exceed the global server.timeout (5min default). Without this the
  // SSE socket gets killed mid-analysis by the HTTPS layer.
  req.setTimeout(0);
  res.setTimeout(0);

  // H13: client-disconnect cancellation. If the operator closes the
  // dashboard tab mid-hunt, abort the upstream LLM fetch instead of
  // letting it stream into the void (wasted tokens, wasted bandwidth,
  // memory bloat in the buffered SSE reader).
  const controller = new AbortController();
  let aborted = false;
  req.on('close', () => {
    if (!res.writableEnded) {
      aborted = true;
      controller.abort();
    }
  });

  const sendEvent = (event, data) => {
    if (aborted || res.writableEnded) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const since = period ? getSince(period) : null;
    const backend = storage.getBackend();

    const intel = await backend.gatherHuntIntel(target, since);
    const external = await gatherExternalIntel(target);
    const timestamp = new Date().toISOString();

    // Send metadata immediately so frontend can render intel panels
    sendEvent('metadata', {
      target,
      period: period || null,
      provider: config.threathunt.provider,
      intel,
      external,
      timestamp,
    });

    const prompt = buildInvestigationPrompt(target, intel, external, period || null);
    await provider.stream(prompt, key, sendEvent, controller.signal);

    sendEvent('done', {});
    if (!res.writableEnded) res.end();
  } catch (err) {
    if (aborted || err.name === 'AbortError') {
      // Client disconnected — silently end without trying to write.
      logger.debug({ target }, 'Threat hunt SSE aborted by client disconnect');
      return;
    }
    logger.warn({ err, target }, 'Threat hunt streaming investigation failed');
    sendEvent('error', { error: err.message || 'Investigation failed' });
    if (!res.writableEnded) res.end();
  }
});

async function gatherExternalIntel(target) {
  const results = { rdns: null, whois: null };

  // Reverse DNS
  try {
    const dns = require('dns').promises;
    const hostnames = await dns.reverse(target);
    results.rdns = hostnames.length > 0 ? hostnames[0] : null;
  } catch {}

  // Basic whois via ipinfo.io (free, no key needed)
  try {
    const res = await fetch(`https://ipinfo.io/${encodeURIComponent(target)}/json`);
    if (res.ok) {
      const data = await res.json();
      results.whois = {
        hostname: data.hostname || null,
        org: data.org || null,
        city: data.city || null,
        region: data.region || null,
        country: data.country || null,
        timezone: data.timezone || null,
      };
    }
  } catch {}

  return results;
}

module.exports = router;
