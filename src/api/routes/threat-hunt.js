const express = require('express');
const { getDb } = require('../../db/database');
const storage = require('../../db/storage');
const config = require('../../config');
const cryptoUtil = require('../../utils/crypto');
const { SCHEMA } = require('../../config/schema');
const logger = require('../../utils/logger');
const { PERIOD_MS, getSinceOptional } = require('../../utils/period');

const router = express.Router();

// Period selector — same options as Dashboard / Live Map / Threat Intel.
// When the request body omits `period` entirely the queries revert to main's
// all-time behavior (no time filter). The UI always sends a period so this
// only affects direct API callers.
const getSince = (period) => getSinceOptional(period);

// Concurrency cap for WardSONDB partition fan-out
const HUNT_FANOUT_CONCURRENCY = 8;

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

  const key = getActiveKey();
  if (!key) return res.status(400).json({ error: `No API key configured for ${config.threathunt.provider}` });

  try {
    const since = period ? getSince(period) : null; // null = all-time

    // Gather local intelligence (scoped to the period if provided, else all-time)
    const intel = await gatherLocalIntel(target, since);

    // Gather external intelligence (not time-scoped — rDNS / WHOIS)
    const external = await gatherExternalIntel(target);

    // Build prompt and call AI
    const prompt = buildInvestigationPrompt(target, intel, external, period || null);
    const analysis = await callAI(prompt);

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

  const key = getActiveKey();
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
    const since = period ? getSince(period) : null; // null = all-time
    const intel = await gatherLocalIntel(target, since);
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
    const provider = config.threathunt.provider;

    switch (provider) {
      case 'anthropic':
        await callAnthropicStream(prompt, key, sendEvent, controller.signal);
        break;
      case 'openai':
        await callOpenAIStream(prompt, key, sendEvent, controller.signal);
        break;
      case 'gemini':
        await callGeminiStream(prompt, key, sendEvent, controller.signal);
        break;
      default:
        sendEvent('error', { error: `Unknown provider: ${provider}` });
    }

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

function getActiveKey() {
  switch (config.threathunt.provider) {
    case 'anthropic': return config.threathunt.anthropicKey;
    case 'openai': return config.threathunt.openaiKey;
    case 'gemini': return config.threathunt.geminiKey;
    default: return null;
  }
}

async function gatherLocalIntel(target, since) {
  const backendName = storage.getBackendName();

  if (backendName === 'WardSONDB') {
    return gatherLocalIntelWardsonDB(target, since);
  }

  if (backendName === 'OpenSearch') {
    return gatherLocalIntelOpenSearch(target, since);
  }

  // SQLite path (original)
  return gatherLocalIntelSQLite(target, since);
}

function gatherLocalIntelSQLite(target, since) {
  const db = getDb();

  // `since` may be null (period omitted) — in that case skip the time filter
  // entirely to match main's pre-period-selector behavior.
  const t = since ? 'AND received_at >= ?' : '';
  const tArg = since ? [since] : [];

  // Cache + related-IPs lookups are NOT time-scoped (cache is current-state).
  const cached = db.prepare('SELECT * FROM ip_enrichment_cache WHERE ip = ?').get(target);
  const totalEvents = db.prepare(
    `SELECT COUNT(*) as c FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}`
  ).get(target, target, ...tArg).c;
  const byAction = db.prepare(`
    SELECT action, COUNT(*) as count FROM events
    WHERE (src_ip = ? OR dst_ip = ?) AND action IS NOT NULL ${t}
    GROUP BY action ORDER BY count DESC
  `).all(target, target, ...tArg);
  const byType = db.prepare(`
    SELECT event_type, COUNT(*) as count FROM events
    WHERE (src_ip = ? OR dst_ip = ?) ${t}
    GROUP BY event_type ORDER BY count DESC
  `).all(target, target, ...tArg);
  const topPorts = db.prepare(`
    SELECT dst_port, protocol, COUNT(*) as count FROM events
    WHERE src_ip = ? AND dst_port IS NOT NULL ${t}
    GROUP BY dst_port, protocol ORDER BY count DESC LIMIT 20
  `).all(target, ...tArg);
  const topSrcPorts = db.prepare(`
    SELECT src_port, protocol, COUNT(*) as count FROM events
    WHERE dst_ip = ? AND src_port IS NOT NULL ${t}
    GROUP BY src_port, protocol ORDER BY count DESC LIMIT 10
  `).all(target, ...tArg);
  const timeline = db.prepare(`
    SELECT strftime('%Y-%m-%dT%H:00:00Z', received_at) as hour, COUNT(*) as count
    FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}
    GROUP BY hour ORDER BY hour
  `).all(target, target, ...tArg);
  const firstSeen = db.prepare(
    `SELECT MIN(received_at) as t FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}`
  ).get(target, target, ...tArg).t;
  const lastSeen = db.prepare(
    `SELECT MAX(received_at) as t FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}`
  ).get(target, target, ...tArg).t;
  const subnet = target.split('.').slice(0, 3).join('.');
  const relatedIPs = db.prepare(`
    SELECT ip, abuse_score, geo_country, hostname FROM ip_enrichment_cache
    WHERE ip LIKE ? AND ip != ? AND is_private = 0
    ORDER BY abuse_score DESC LIMIT 10
  `).all(subnet + '.%', target);
  const signatures = db.prepare(`
    SELECT ids_signature, ids_classification, COUNT(*) as count
    FROM events WHERE (src_ip = ? OR dst_ip = ?) AND ids_signature IS NOT NULL ${t}
    GROUP BY ids_signature ORDER BY count DESC LIMIT 10
  `).all(target, target, ...tArg);
  const targetsHit = db.prepare(
    `SELECT COUNT(DISTINCT dst_ip) as c FROM events WHERE src_ip = ? ${t}`
  ).get(target, ...tArg).c;
  const topDestinations = db.prepare(`
    SELECT dst_ip as ip, COUNT(*) as count FROM events
    WHERE src_ip = ? AND dst_ip IS NOT NULL ${t}
    GROUP BY dst_ip ORDER BY count DESC LIMIT 20
  `).all(target, ...tArg);
  const topSources = db.prepare(`
    SELECT src_ip as ip, COUNT(*) as count FROM events
    WHERE dst_ip = ? AND src_ip IS NOT NULL ${t}
    GROUP BY src_ip ORDER BY count DESC LIMIT 20
  `).all(target, ...tArg);

  return { cached, totalEvents, byAction, byType, topPorts, topSrcPorts, timeline, firstSeen, lastSeen, relatedIPs, signatures, targetsHit, topDestinations, topSources };
}

/**
 * Run the same WardSONDB aggregation pipeline against each partition with
 * bounded concurrency, then merge results client-side by _id.
 */
async function fanOutAggregate(backend, partitions, pipeline) {
  if (!partitions.length) return [];
  const merged = new Map();
  let i = 0;
  const workers = Array.from({ length: HUNT_FANOUT_CONCURRENCY }, async () => {
    while (i < partitions.length) {
      const p = partitions[i++];
      try {
        const r = await backend._request('POST', `/${p}/aggregate`, { pipeline }, 3);
        for (const row of (r.data || [])) {
          const key = typeof row._id === 'object' ? JSON.stringify(row._id) : String(row._id);
          const ex = merged.get(key);
          if (ex) ex.count = (ex.count || 0) + (row.count || 0);
          else merged.set(key, { _id: row._id, count: row.count || 0 });
        }
      } catch (err) {
        logger.debug({ err: err.message, partition: p }, 'Threat hunt fan-out aggregation failed');
      }
    }
  });
  await Promise.all(workers);
  return Array.from(merged.values()).sort((a, b) => (b.count || 0) - (a.count || 0));
}

/** Fan out a count_only query and sum the counts across partitions. */
async function fanOutCount(backend, partitions, filter) {
  if (!partitions.length) return 0;
  let total = 0;
  let i = 0;
  const workers = Array.from({ length: HUNT_FANOUT_CONCURRENCY }, async () => {
    while (i < partitions.length) {
      const p = partitions[i++];
      try {
        const r = await backend._request('POST', `/${p}/query`, { filter, count_only: true }, 3);
        total += r.meta?.total_count || r.data?.count || 0;
      } catch (err) {
        logger.debug({ err: err.message, partition: p }, 'Threat hunt fan-out count failed');
      }
    }
  });
  await Promise.all(workers);
  return total;
}

async function gatherLocalIntelWardsonDB(target, since) {
  const backend = storage.getBackend();
  const cacheCol = backend.cacheCollection;
  const post = (path, body) => backend._request('POST', path, body, 3);

  // Resolve the partition set. When `since` is null (no period provided),
  // fan out across every known partition — matches main's all-time behavior.
  const partitions = since
    ? backend._getPartitionsForRange(since, new Date().toISOString())
    : backend._partitionsNewestFirst();

  // When a period is provided, AND a received_at >= since clause into every
  // $match so we don't scan events outside the window (partitions only narrow
  // the day range; within a partition we still need the clause). When `since`
  // is null, leave filters unmodified.
  const timeRange = since ? { received_at: { '$gte': since } } : null;
  const withTime = (f) => timeRange ? { '$and': [f, timeRange] } : f;

  // IP filter applied at $match (cheap pre-filter on indexed src/dst ip fields)
  const ipOr = { '$or': [{ 'network.src_ip': target }, { 'network.dst_ip': target }] };
  const ipFilter = withTime(ipOr);

  // Enrichment cache lookup is not partitioned and not time-scoped
  const cachedResult = await post(`/${cacheCol}/query`, { filter: { ip: target }, limit: 1 }).catch(() => ({ data: [] }));
  const cached = cachedResult.data?.[0] || null;

  if (partitions.length === 0) {
    return {
      cached, totalEvents: 0, byAction: [], byType: [], topPorts: [], topSrcPorts: [],
      timeline: [], firstSeen: null, lastSeen: null, relatedIPs: [],
      signatures: [], targetsHit: 0, topDestinations: [], topSources: [],
    };
  }

  // Run the heavy aggregations in parallel — each one fans out across partitions internally
  const [
    totalEvents,
    byActionRows,
    byTypeRows,
    topPortsRows,
    topSrcPortsRows,
    signaturesRows,
    topDestinationsRows,
    topSourcesRows,
    firstLastResults,
    targetsHitSet,
  ] = await Promise.all([
    fanOutCount(backend, partitions, ipFilter),

    fanOutAggregate(backend, partitions, [
      { '$match': ipFilter },
      { '$group': { '_id': 'network.action', count: { '$count': {} } } },
    ]),

    fanOutAggregate(backend, partitions, [
      { '$match': ipFilter },
      { '$group': { '_id': 'event_type', count: { '$count': {} } } },
    ]),

    fanOutAggregate(backend, partitions, [
      { '$match': withTime({ 'network.src_ip': target, 'network.dst_port': { '$exists': true } }) },
      { '$group': { '_id': { port: 'network.dst_port', protocol: 'network.protocol' }, count: { '$count': {} } } },
    ]),

    fanOutAggregate(backend, partitions, [
      { '$match': withTime({ 'network.dst_ip': target, 'network.src_port': { '$exists': true } }) },
      { '$group': { '_id': { port: 'network.src_port', protocol: 'network.protocol' }, count: { '$count': {} } } },
    ]),

    fanOutAggregate(backend, partitions, [
      { '$match': {
        '$and': [ipOr, { 'ids.signature': { '$exists': true } }, ...(timeRange ? [timeRange] : [])],
      } },
      { '$group': { '_id': { sig: 'ids.signature', cls: 'ids.classification' }, count: { '$count': {} } } },
    ]),

    fanOutAggregate(backend, partitions, [
      { '$match': withTime({ 'network.src_ip': target }) },
      { '$group': { '_id': 'network.dst_ip', count: { '$count': {} } } },
    ]),

    fanOutAggregate(backend, partitions, [
      { '$match': withTime({ 'network.dst_ip': target }) },
      { '$group': { '_id': 'network.src_ip', count: { '$count': {} } } },
    ]),

    // First and last seen — query each partition for one record at each end, then min/max client-side
    (async () => {
      let i = 0;
      const firsts = [];
      const lasts = [];
      const workers = Array.from({ length: HUNT_FANOUT_CONCURRENCY }, async () => {
        while (i < partitions.length) {
          const p = partitions[i++];
          try {
            const [a, b] = await Promise.all([
              post(`/${p}/query`, { filter: ipFilter, sort: [{ received_at: 'asc' }], fields: ['received_at'], limit: 1 }),
              post(`/${p}/query`, { filter: ipFilter, sort: [{ received_at: 'desc' }], fields: ['received_at'], limit: 1 }),
            ]);
            const f = a.data?.[0]?.received_at;
            const l = b.data?.[0]?.received_at;
            if (f) firsts.push(f);
            if (l) lasts.push(l);
          } catch {}
        }
      });
      await Promise.all(workers);
      return [firsts.length ? firsts.sort()[0] : null, lasts.length ? lasts.sort().slice(-1)[0] : null];
    })(),

    // Unique dst IPs targeted — distinct per partition, union into a Set
    (async () => {
      const set = new Set();
      let i = 0;
      const workers = Array.from({ length: HUNT_FANOUT_CONCURRENCY }, async () => {
        while (i < partitions.length) {
          const p = partitions[i++];
          try {
            const r = await post(`/${p}/distinct`, {
              field: 'network.dst_ip',
              filter: withTime({ 'network.src_ip': target }),
              limit: 10000,
            });
            for (const v of (r.data?.values || [])) set.add(v);
          } catch {}
        }
      });
      await Promise.all(workers);
      return set;
    })(),
  ]);

  const trimRank = (rows, lim) => rows.slice(0, lim).map(r => ({ _id: r._id, count: r.count }));

  const byAction = trimRank(byActionRows, 50).map(r => ({ action: r._id, count: r.count }));
  const byType = trimRank(byTypeRows, 50).map(r => ({ event_type: r._id, count: r.count }));
  const topPorts = trimRank(topPortsRows, 20).map(r => ({ dst_port: r._id?.port, protocol: r._id?.protocol, count: r.count }));
  const topSrcPorts = trimRank(topSrcPortsRows, 10).map(r => ({ src_port: r._id?.port, protocol: r._id?.protocol, count: r.count }));
  const signatures = trimRank(signaturesRows, 10).map(r => ({
    ids_signature: r._id?.sig, ids_classification: r._id?.cls, count: r.count,
  }));
  const topDestinations = trimRank(topDestinationsRows, 20).map(r => ({ ip: r._id, count: r.count }));
  const topSources = trimRank(topSourcesRows, 20).map(r => ({ ip: r._id, count: r.count }));

  const [firstSeen, lastSeen] = firstLastResults;
  const targetsHit = targetsHitSet.size;

  // Timeline — paginate per partition, project received_at, bucket client-side by hour.
  // Cap total fetched docs across all partitions at 100K (existing safety cap).
  let timeline = [];
  try {
    const buckets = {};
    let totalFetched = 0;
    const PAGE = 10000;
    const FETCH_CAP = 100000;

    let pi = 0;
    outer: while (pi < partitions.length && totalFetched < FETCH_CAP) {
      const p = partitions[pi++];
      let offset = 0;
      while (true) {
        const remaining = FETCH_CAP - totalFetched;
        if (remaining <= 0) break outer;
        const limit = Math.min(PAGE, remaining);
        let docs;
        try {
          const page = await post(`/${p}/query`, {
            filter: ipFilter,
            fields: ['received_at'],
            limit,
            offset,
          });
          docs = page.data || [];
        } catch {
          break;
        }
        if (docs.length === 0) break;
        for (const doc of docs) {
          if (!doc.received_at) continue;
          const hour = doc.received_at.substring(0, 13) + ':00:00Z';
          buckets[hour] = (buckets[hour] || 0) + 1;
        }
        totalFetched += docs.length;
        offset += docs.length;
        if (docs.length < limit) break;
      }
    }
    timeline = Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, count]) => ({ hour, count }));
  } catch (err) {
    logger.warn({ err }, 'Failed to build timeline for threat hunt');
  }

  // Related IPs from same /24 subnet (cache only — not time-scoped)
  let relatedIPs = [];
  try {
    const subnet = target.split('.').slice(0, 3).join('.');
    const subnetCacheResult = await post(`/${cacheCol}/query`, {
      filter: { ip: { '$regex': `^${subnet.replace(/\./g, '\\.')}\\.` }, is_private: false },
      limit: 100,
    });
    relatedIPs = (subnetCacheResult.data || [])
      .filter(r => r.ip !== target)
      .sort((a, b) => (b.abuse_score || 0) - (a.abuse_score || 0))
      .slice(0, 10)
      .map(r => ({ ip: r.ip, abuse_score: r.abuse_score, geo_country: r.geo_country, hostname: r.hostname }));
  } catch {}

  return { cached, totalEvents, byAction, byType, topPorts, topSrcPorts, timeline, firstSeen, lastSeen, relatedIPs, signatures, targetsHit, topDestinations, topSources };
}

async function gatherLocalIntelOpenSearch(target, since) {
  const backend = storage.getBackend();
  const client = backend.client;
  const eventsIndex = backend.eventsIndex;
  const cacheIndex = backend.cacheIndex;

  // `since` may be null (period omitted) — skip the range filter entirely
  // to match main's pre-period-selector behavior.
  const timeRange = since ? { range: { received_at: { gte: since } } } : null;
  const withTime = (filters) => timeRange ? [...filters, timeRange] : filters;
  const ipShould = { bool: { should: [{ term: { src_ip: target } }, { term: { dst_ip: target } }], minimum_should_match: 1 } };
  const ipFilter = { bool: { filter: withTime([ipShould]) } };

  try {
    const [mainResult, portsResult, srcPortsResult, firstLastResult, sigsResult, targetsResult, topDstResult, topSrcResult, cachedResult] = await Promise.all([
      // Main aggregations: total, by action, by type — single query
      client.search({ index: eventsIndex, body: {
        size: 0,
        track_total_hits: true,
        query: ipFilter,
        aggs: {
          by_action: { terms: { field: 'network_action', size: 20 } },
          by_type: { terms: { field: 'event_type', size: 20 } },
        },
      }}).catch(() => ({ body: { hits: { total: { value: 0 } }, aggregations: {} } })),

      // Top destination ports (target as source)
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { src_ip: target } }, { exists: { field: 'dst_port' } }]) } },
        aggs: { top_ports: { terms: { field: 'dst_port', size: 20 }, aggs: { proto: { terms: { field: 'protocol', size: 1 } } } } },
      }}).catch(() => ({ body: { aggregations: {} } })),

      // Top source ports (target as destination)
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { dst_ip: target } }, { exists: { field: 'src_port' } }]) } },
        aggs: { top_ports: { terms: { field: 'src_port', size: 10 }, aggs: { proto: { terms: { field: 'protocol', size: 1 } } } } },
      }}).catch(() => ({ body: { aggregations: {} } })),

      // First and last seen
      Promise.all([
        client.search({ index: eventsIndex, body: { size: 1, query: ipFilter, sort: [{ received_at: 'asc' }], _source: ['received_at'] } }),
        client.search({ index: eventsIndex, body: { size: 1, query: ipFilter, sort: [{ received_at: 'desc' }], _source: ['received_at'] } }),
      ]).catch(() => [{ body: { hits: { hits: [] } } }, { body: { hits: { hits: [] } } }]),

      // IDS signatures
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([ipShould, { exists: { field: 'ids_signature' } }]) } },
        aggs: { sigs: { terms: { field: 'ids_signature', size: 10 }, aggs: { cls: { terms: { field: 'ids_category', size: 1 } } } } },
      }}).catch(() => ({ body: { aggregations: {} } })),

      // Unique targets hit (cardinality)
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { src_ip: target } }]) } },
        aggs: { unique_dst: { cardinality: { field: 'dst_ip' } } },
      }}).catch(() => ({ body: { aggregations: {} } })),

      // Top destination IPs
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { src_ip: target } }, { exists: { field: 'dst_ip' } }]) } },
        aggs: { top: { terms: { field: 'dst_ip', size: 20 } } },
      }}).catch(() => ({ body: { aggregations: {} } })),

      // Top source IPs
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { dst_ip: target } }, { exists: { field: 'src_ip' } }]) } },
        aggs: { top: { terms: { field: 'src_ip', size: 20 } } },
      }}).catch(() => ({ body: { aggregations: {} } })),

      // Enrichment cache lookup (not time-scoped)
      client.get({ index: cacheIndex, id: target }).catch(() => ({ body: { found: false } })),
    ]);

    // Parse main aggregations
    const totalEvents = mainResult.body?.hits?.total?.value || 0;
    const byAction = (mainResult.body?.aggregations?.by_action?.buckets || []).map(b => ({ action: b.key, count: b.doc_count }));
    const byType = (mainResult.body?.aggregations?.by_type?.buckets || []).map(b => ({ event_type: b.key, count: b.doc_count }));

    // Parse ports
    const topPorts = (portsResult.body?.aggregations?.top_ports?.buckets || []).map(b => ({
      dst_port: b.key, protocol: b.proto?.buckets?.[0]?.key || null, count: b.doc_count,
    }));
    const topSrcPorts = (srcPortsResult.body?.aggregations?.top_ports?.buckets || []).map(b => ({
      src_port: b.key, protocol: b.proto?.buckets?.[0]?.key || null, count: b.doc_count,
    }));

    // Parse first/last
    const [firstResult, lastResult] = firstLastResult;
    const firstSeen = firstResult.body?.hits?.hits?.[0]?._source?.received_at || null;
    const lastSeen = lastResult.body?.hits?.hits?.[0]?._source?.received_at || null;

    // Parse signatures
    const signatures = (sigsResult.body?.aggregations?.sigs?.buckets || []).map(b => ({
      ids_signature: b.key, ids_classification: b.cls?.buckets?.[0]?.key || null, count: b.doc_count,
    }));

    // Targets hit
    const targetsHit = targetsResult.body?.aggregations?.unique_dst?.value || 0;

    // Top destinations/sources
    const topDestinations = (topDstResult.body?.aggregations?.top?.buckets || []).map(b => ({ ip: b.key, count: b.doc_count }));
    const topSources = (topSrcResult.body?.aggregations?.top?.buckets || []).map(b => ({ ip: b.key, count: b.doc_count }));

    // Cached enrichment — map OpenSearch field names to the format the prompt builder expects
    let cached = null;
    if (cachedResult.body?.found) {
      const src = cachedResult.body._source;
      cached = {
        ip: target,
        geo_country: src.country || null,
        geo_city: src.city || null,
        geo_lat: src.latitude ?? null,
        geo_lon: src.longitude ?? null,
        abuse_score: src.abuseConfidenceScore ?? null,
        hostname: src.hostname || null,
      };
    }

    // Timeline — hourly date_histogram (time-scoped)
    let timeline = [];
    try {
      const tlResult = await client.search({ index: eventsIndex, body: {
        size: 0,
        query: ipFilter,
        aggs: { timeline: { date_histogram: { field: 'received_at', fixed_interval: '1h', min_doc_count: 1 } } },
      }});
      timeline = (tlResult.body?.aggregations?.timeline?.buckets || []).map(b => ({
        hour: new Date(b.key).toISOString().substring(0, 13) + ':00:00Z',
        count: b.doc_count,
      }));
    } catch {}

    // Related IPs from same /24 subnet
    let relatedIPs = [];
    try {
      const subnet = target.split('.').slice(0, 3).join('.');
      const relResult = await client.search({ index: cacheIndex, body: {
        size: 100,
        query: { bool: {
          filter: [{ range: { ip: { gte: subnet + '.0', lte: subnet + '.255' } } }],
          must_not: [{ term: { ip: target } }, { term: { is_private: true } }],
        }},
        sort: [{ abuseConfidenceScore: { order: 'desc', missing: '_last' } }],
      }});
      relatedIPs = (relResult.body?.hits?.hits || []).slice(0, 10).map(h => ({
        ip: h._id, abuse_score: h._source?.abuseConfidenceScore ?? null,
        geo_country: h._source?.country || null, hostname: h._source?.hostname || null,
      }));
    } catch {}

    return { cached, totalEvents, byAction, byType, topPorts, topSrcPorts, timeline, firstSeen, lastSeen, relatedIPs, signatures, targetsHit, topDestinations, topSources };
  } catch (err) {
    logger.warn({ err, target }, 'OpenSearch gatherLocalIntel failed');
    return { cached: null, totalEvents: 0, byAction: [], byType: [], topPorts: [], topSrcPorts: [], timeline: [], firstSeen: null, lastSeen: null, relatedIPs: [], signatures: [], targetsHit: 0, topDestinations: [], topSources: [] };
  }
}

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

function buildInvestigationPrompt(target, intel, external, period) {
  const sections = [];

  sections.push(`You are a senior threat intelligence analyst. Investigate the following IP address and provide a comprehensive threat assessment based on the data provided from our SIEM.`);

  sections.push(`\n## Target: ${target}`);
  if (period) sections.push(`## Investigation Window: last ${period}`);

  // Enrichment data
  if (intel.cached) {
    sections.push(`\n### Enrichment Data`);
    sections.push(`- Country: ${intel.cached.geo_country || 'Unknown'}`);
    sections.push(`- City: ${intel.cached.geo_city || 'Unknown'}`);
    sections.push(`- AbuseIPDB Score: ${intel.cached.abuse_score ?? 'Not scored'}/100`);
    sections.push(`- Hostname: ${intel.cached.hostname || 'None'}`);
  }

  // External data
  if (external.whois) {
    sections.push(`\n### Network Info (WHOIS)`);
    sections.push(`- Organization: ${external.whois.org || 'Unknown'}`);
    sections.push(`- Hostname: ${external.whois.hostname || external.rdns || 'None'}`);
    sections.push(`- Location: ${[external.whois.city, external.whois.region, external.whois.country].filter(Boolean).join(', ') || 'Unknown'}`);
  }

  // Activity summary
  sections.push(`\n### Activity Summary`);
  sections.push(`- Total events: ${intel.totalEvents.toLocaleString()}`);
  sections.push(`- First seen: ${intel.firstSeen || 'N/A'}`);
  sections.push(`- Last seen: ${intel.lastSeen || 'N/A'}`);
  sections.push(`- Unique targets hit: ${intel.targetsHit}`);

  if (intel.byAction.length > 0) {
    sections.push(`\n### Actions`);
    for (const a of intel.byAction) {
      sections.push(`- ${a.action}: ${a.count.toLocaleString()}`);
    }
  }

  if (intel.byType.length > 0) {
    sections.push(`\n### Event Types`);
    for (const t of intel.byType) {
      sections.push(`- ${t.event_type}: ${t.count.toLocaleString()}`);
    }
  }

  if (intel.topPorts.length > 0) {
    sections.push(`\n### Top Destination Ports Targeted`);
    for (const p of intel.topPorts) {
      sections.push(`- ${p.protocol}/${p.dst_port}: ${p.count} events`);
    }
  }

  if (intel.signatures.length > 0) {
    sections.push(`\n### IDS/IPS Signatures Triggered`);
    for (const s of intel.signatures) {
      sections.push(`- ${s.ids_signature} (${s.ids_classification}): ${s.count} events`);
    }
  }

  if (intel.relatedIPs.length > 0) {
    sections.push(`\n### Related IPs (Same /24 Subnet)`);
    for (const r of intel.relatedIPs) {
      sections.push(`- ${r.ip} — Abuse: ${r.abuse_score ?? 'N/A'}, Country: ${r.geo_country || '?'}, Host: ${r.hostname || 'N/A'}`);
    }
  }

  if (intel.timeline.length > 0) {
    sections.push(`\n### Activity Timeline (Hourly)`);
    for (const t of intel.timeline) {
      sections.push(`- ${t.hour}: ${t.count} events`);
    }
  }

  sections.push(`\n## Instructions`);
  sections.push(`Based on the above SIEM data, provide a structured threat assessment with the following sections:`);
  sections.push(`1. **Threat Classification** — What type of threat actor/activity is this? (scanner, brute-forcer, botnet, APT, benign, etc.)`);
  sections.push(`2. **Confidence Level** — How confident are you in this classification? (High/Medium/Low) and why.`);
  sections.push(`3. **Actor Profile** — Who is likely behind this? (automated scanner, hosting provider abuse, nation-state, cybercrime group, researcher, etc.)`);
  sections.push(`4. **Intent Analysis** — What are they likely trying to achieve based on the ports and patterns?`);
  sections.push(`5. **Risk Assessment** — What is the risk to our network? (Critical/High/Medium/Low) and why.`);
  sections.push(`6. **Indicators of Compromise (IOCs)** — List any IOCs from the data (IPs, ports, signatures, patterns).`);
  sections.push(`7. **Recommended Actions** — Specific, actionable recommendations for the network defender.`);
  sections.push(`8. **Related Threat Intelligence** — Any known threat groups, campaigns, or CVEs that match this pattern.`);
  sections.push(`\nBe specific and reference the actual data provided. Do not hallucinate or invent data not present in the evidence.`);

  return sections.join('\n');
}

async function callAI(prompt) {
  const provider = config.threathunt.provider;
  const key = getActiveKey();

  switch (provider) {
    case 'anthropic': return callAnthropic(prompt, key);
    case 'openai': return callOpenAI(prompt, key);
    case 'gemini': return callGemini(prompt, key);
    default: throw new Error(`Unknown provider: ${provider}`);
  }
}

async function callAnthropic(prompt, key) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.threathunt.anthropicModel,
      max_tokens: config.threathunt.anthropicMaxTokens,
      thinking: { type: 'adaptive', display: 'summarized' },
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  // With thinking enabled, find the text content block (skip thinking blocks)
  const textBlock = data.content?.find(b => b.type === 'text');
  return textBlock?.text || 'No response from Anthropic';
}

async function callOpenAI(prompt, key) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: config.threathunt.openaiModel,
      max_tokens: config.threathunt.openaiMaxTokens,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`OpenAI API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content || 'No response from OpenAI';
}

async function callGemini(prompt, key) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${config.threathunt.geminiModel}:generateContent?key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: config.threathunt.geminiMaxTokens },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response from Gemini';
}

// --- Streaming provider functions ---

// Helper: parse SSE lines from a ReadableStream
async function* parseSSEStream(body) {
  const decoder = new TextDecoder();
  let buffer = '';
  // M16: lifted out of the for-await loop so an `event:` line whose
  // matching `data:` line lands in the next chunk still pairs correctly.
  let eventType = null;
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line in buffer
    for (const line of lines) {
      if (line.startsWith('event: ')) {
        eventType = line.slice(7).trim();
      } else if (line.startsWith('data: ')) {
        const data = line.slice(6);
        try {
          yield { event: eventType, data: JSON.parse(data) };
        } catch {
          yield { event: eventType, data };
        }
        eventType = null;
      }
    }
  }
}

async function callAnthropicStream(prompt, key, sendEvent, signal) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.threathunt.anthropicModel,
      max_tokens: config.threathunt.anthropicMaxTokens,
      thinking: { type: 'adaptive', display: 'summarized' },
      stream: true,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal,
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${err}`);
  }

  for await (const { data } of parseSSEStream(res.body)) {
    if (!data || typeof data !== 'object') continue;

    if (data.type === 'content_block_start') {
      if (data.content_block?.type === 'thinking') {
        sendEvent('thinking_start', {});
      } else if (data.content_block?.type === 'text') {
        sendEvent('text_start', {});
      }
    } else if (data.type === 'content_block_delta') {
      if (data.delta?.type === 'thinking_delta') {
        sendEvent('thinking', { text: data.delta.thinking });
      } else if (data.delta?.type === 'text_delta') {
        sendEvent('chunk', { text: data.delta.text });
      }
      // skip signature_delta — not needed for single-turn
    }
  }
}

async function callOpenAIStream(prompt, key, sendEvent, signal) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: config.threathunt.openaiModel,
      max_tokens: config.threathunt.openaiMaxTokens,
      stream: true,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal,
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`OpenAI API error ${res.status}: ${err}`);
  }

  for await (const { data } of parseSSEStream(res.body)) {
    if (data === '[DONE]') break;
    if (!data || typeof data !== 'object') continue;
    const text = data.choices?.[0]?.delta?.content;
    if (text) sendEvent('chunk', { text });
  }
}

async function callGeminiStream(prompt, key, sendEvent, signal) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${config.threathunt.geminiModel}:streamGenerateContent?alt=sse&key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: config.threathunt.geminiMaxTokens },
    }),
    signal,
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini API error ${res.status}: ${err}`);
  }

  for await (const { data } of parseSSEStream(res.body)) {
    if (!data || typeof data !== 'object') continue;
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (text) sendEvent('chunk', { text });
  }
}

module.exports = router;
