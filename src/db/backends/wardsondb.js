/**
 * WardSONDB Storage Backend
 *
 * Architecture:
 * - Events stored in daily partition collections: events-YYYY-MM-DD.
 *   New partitions are created on demand when an event for a new day arrives.
 *   Retention drops entire partition collections atomically.
 * - Five pre-aggregated rollup collections mirror SQLite's rollup tables:
 *     rollups-5m, rollups-ip-hourly, rollups-port-hourly,
 *     rollups-sig-hourly, rollups-client-hourly.
 *   Counts are accumulated in memory during insertEvents() and flushed every
 *   5 seconds via a read-then-increment cycle.
 * - Singleton enrichment_cache collection stores per-IP enrichment data.
 * - Settings remain in SQLite (needed to boot and select the backend).
 */
const StorageBackend = require('./interface');
const logger = require('../../utils/logger');
const { isPrivateIp } = require('../../utils/ip-utils');
const { accumulateRollups, mergeRollups, newRollupBuffers, align5m, align1h } = require('../rollups');
// Use undici's own fetch (not Node's globalThis.fetch) so the per-client Agent
// we construct from the same undici package has a matching request-handler
// interface. Mixing Node's bundled undici with a standalone-undici Agent
// surfaces as `InvalidArgumentError: invalid onRequestStart method`.
const { Agent, fetch } = require('undici');

const FLUSH_INTERVAL_MS = 5000;
const PARTITION_PREFIX = 'events-';
const PARTITION_NAME_RE = /^events-\d{4}-\d{2}-\d{2}$/;

class WardsonDbBackend extends StorageBackend {
  constructor(config = {}) {
    super('WardSONDB', config);
    this.baseUrl = `http${config.useTls ? 's' : ''}://${config.host || 'localhost'}:${config.port || 8080}`;
    this.apiKey = config.apiKey || '';
    this.verifyCerts = config.verifyCerts !== false; // default true
    this.cacheCollection = 'enrichment_cache';
    this.rollup5m = 'rollups-5m';
    this.rollupIpHourly = 'rollups-ip-hourly';
    this.rollupPortHourly = 'rollups-port-hourly';
    this.rollupSigHourly = 'rollups-sig-hourly';
    this.rollupClientHourly = 'rollups-client-hourly';
    this.healthTimeoutMs = config.healthTimeoutMs || 5000;
    this.flushConcurrency = Math.max(1, config.flushConcurrency || 4);

    // Per-client undici dispatcher. A WardSONDB server under heavy
    // flush+backfill load takes longer than undici's 10s default connect
    // timeout to accept new connections, causing spurious
    // `Connect Timeout Error`s. Scoping the Agent to this instance keeps the
    // connect-timeout tuning (and TLS trust) from affecting AbuseIPDB,
    // ipinfo.io, or AI provider fetches. Passed to fetch() as
    // `{ dispatcher }` per-call.
    const connectTimeoutMs = config.connectTimeoutMs || 60_000;
    const queryTimeoutMs = config.queryTimeoutMs || 0;
    const agentConnect = { timeout: connectTimeoutMs };
    // Per-client TLS trust instead of the global NODE_TLS_REJECT_UNAUTHORIZED
    // hack — keeps the bypass scoped to WardSONDB calls (matches the OpenSearch
    // backend's per-client `rejectUnauthorized: false` pattern).
    if (config.useTls && !this.verifyCerts) {
      agentConnect.rejectUnauthorized = false;
      logger.warn('TLS certificate verification disabled for WardSONDB connection');
    }
    this._agent = new Agent({
      connect: agentConnect,
      // 0 means "no client-side timeout" — server's --query-timeout governs.
      headersTimeout: queryTimeoutMs || 0,
      bodyTimeout: queryTimeoutMs || 0,
      keepAliveTimeout: 10_000,
      keepAliveMaxTimeout: 600_000,
    });
    logger.info({ connectTimeoutMs, queryTimeoutMs }, 'WardSONDB undici dispatcher configured (per-client)');

    // Partition existence cache — Set<'events-YYYY-MM-DD'>
    this._partitions = new Set();

    // Rollup accumulator buffers, swapped on each flush
    this._rollupBuffers = this._newBuffers();
    this._flushIntervalHandle = null;
    this._flushing = false;
    this._shuttingDown = false;
    this._backfillStarted = false;

    // Cached doc count across event partitions, used for empty-DB short-circuit
    this._cachedDocCount = null;

    // Enrichment cache map (30s TTL), used by stats joins and event overlay
    this._cacheMap = null;
    this._cacheMapTs = 0;
  }

  static get metadata() {
    return {
      name: 'WardSONDB',
      description: 'High-performance Rust-based JSON document database. Optimized for SIEM workloads with selective indexing and low memory footprint.',
      status: 'beta',
      configFields: [
        { key: 'host', label: 'Host', type: 'text', placeholder: 'localhost', default: 'localhost' },
        { key: 'port', label: 'Port', type: 'number', placeholder: '8080', default: 8080 },
        { key: 'apiKey', label: 'API Key', type: 'password', placeholder: 'Optional', default: '' },
        { key: 'useTls', label: 'Use TLS', type: 'boolean', default: false },
        { key: 'verifyCerts', label: 'Verify Certificates', type: 'boolean', default: true },
      ],
    };
  }

  // --- HTTP Client ---
  // Timeouts: query/aggregation duration is governed by WardSONDB's server-side
  // --query-timeout flag (default 30s). To support long-running Threat Hunt queries,
  // launch WardSONDB with --query-timeout 120 or higher.
  // Health checks use _healthRequest() with AbortSignal.timeout(healthTimeoutMs).

  async _request(method, path, body = null, retries = 3) {
    const url = `${this.baseUrl}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
    const opts = { method, headers, dispatcher: this._agent };
    if (body) opts.body = JSON.stringify(body);

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const resp = await fetch(url, opts);
        const json = await resp.json();

        if (!json.ok) {
          const code = json.error?.code || 'UNKNOWN';
          const msg = json.error?.message || 'Unknown error';
          if (resp.status === 404) return { _notFound: true, code, message: msg };
          if (resp.status === 409) return { _conflict: true, code, message: msg };
          // Retry on 5xx
          if (resp.status >= 500 && attempt < retries) {
            await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
            continue;
          }
          throw new Error(`WardSONDB ${code}: ${msg}`);
        }

        return json;
      } catch (err) {
        if (attempt < retries && err.message?.includes('fetch failed')) {
          logger.debug({ err: err.message, attempt, path }, 'WardSONDB request failed, retrying');
          await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
  }

  /** Health/stats check with a short timeout — should fail fast, no retries */
  async _healthRequest(path) {
    const url = `${this.baseUrl}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers,
      dispatcher: this._agent,
      signal: AbortSignal.timeout(this.healthTimeoutMs),
    });
    const json = await resp.json();
    if (!json.ok) throw new Error(`WardSONDB ${json.error?.code}: ${json.error?.message}`);
    return json;
  }

  async _get(path) { return this._request('GET', path); }
  async _post(path, body) { return this._request('POST', path, body); }
  async _put(path, body) { return this._request('PUT', path, body); }
  async _patch(path, body) { return this._request('PATCH', path, body); }
  async _delete(path) { return this._request('DELETE', path); }

  // Bucket alignment kept as instance methods for backward compatibility
  // with internal callers; both delegate to the shared helpers in
  // src/db/rollups.js so SQLite and WardSONDB stay in lockstep.
  _align5m(iso) { return align5m(iso); }
  _align1h(iso) { return align1h(iso); }

  // --- Partition helpers ---

  _partitionName(dateLike) {
    const d = dateLike instanceof Date ? dateLike : new Date(dateLike);
    return `${PARTITION_PREFIX}${d.toISOString().substring(0, 10)}`;
  }

  /** Extract the partition name from a UUIDv7 _id (first 48 bits = ms since epoch) */
  _partitionFromId(id) {
    if (!id || typeof id !== 'string') return null;
    const hex = id.replace(/-/g, '').substring(0, 12);
    const ms = parseInt(hex, 16);
    if (!Number.isFinite(ms) || ms <= 0) return null;
    return this._partitionName(new Date(ms));
  }

  /** Returns existing partitions overlapping [sinceISO, untilISO], oldest-first */
  _getPartitionsForRange(sinceISO, untilISO) {
    const start = sinceISO ? new Date(sinceISO) : new Date(0);
    const end = untilISO ? new Date(untilISO) : new Date();
    const out = [];
    const cur = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
    const last = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate()));
    while (cur <= last) {
      const name = this._partitionName(cur);
      if (this._partitions.has(name)) out.push(name);
      cur.setUTCDate(cur.getUTCDate() + 1);
    }
    return out;
  }

  /** All known partitions, newest-first */
  _partitionsNewestFirst() {
    return [...this._partitions].sort().reverse();
  }

  /** Idempotent partition creation. Empty collections take indexes instantly. */
  async _ensurePartition(name) {
    if (this._partitions.has(name)) return;
    await this._ensureCollection(name);
    this._partitions.add(name);
    // NEW-C10: await index creation rather than fire-and-forget. Empty
    // collections take indexes instantly per WardSONDB API.md, so the
    // wait is milliseconds — but it eliminates the midnight-rollover
    // race where the first inserts of a new day landed against an
    // unindexed partition before indexes were ready.
    try {
      await this._createPartitionIndexes(name);
    } catch (err) {
      logger.warn({ err: err.message, partition: name }, 'WardSONDB partition index creation failed');
    }
  }

  async _createPartitionIndexes(name) {
    for (const idx of this._getRequiredEventIndexes()) {
      try {
        const body = { name: idx.name };
        if (idx.fields) body.fields = idx.fields;
        else body.field = idx.field;
        await this._post(`/${name}/indexes`, body);
      } catch (err) {
        if (err.message?.includes('INDEX_EXISTS')) continue;
        logger.debug({ err: err.message, partition: name, idx: idx.name }, 'Partition index creation warn');
      }
    }
  }

  /**
   * Fan out a query function over the partitions overlapping [since, until],
   * newest-first. Stops early once `limit` results have been collected.
   * Tolerates per-partition failures.
   */
  async _queryAcrossPartitions(queryFn, sinceISO, untilISO, limit) {
    const partitions = sinceISO || untilISO
      ? this._getPartitionsForRange(sinceISO, untilISO).reverse()
      : this._partitionsNewestFirst();
    if (partitions.length === 0) return [];

    const results = [];
    for (const p of partitions) {
      if (results.length >= limit) break;
      const remaining = limit - results.length;
      try {
        const batch = await queryFn(p, remaining);
        if (Array.isArray(batch)) results.push(...batch);
      } catch (err) {
        logger.debug({ err: err.message, partition: p }, 'WardSONDB partition query failed, continuing');
      }
    }
    return results.slice(0, limit);
  }

  // --- Rollup buffers ---

  _newBuffers() {
    return newRollupBuffers();
  }

  /**
   * Accumulate rollup deltas into the persistent in-memory buffer that
   * the 5-second flush worker drains. Pure aggregation lives in
   * src/db/rollups.js — this method is just the buffer-merge wrapper.
   * Private IPs are NOT filtered at write time — they're filtered at
   * query time when callers pass excludePrivate (matches SQLite's
   * HAVING-style semantics).
   */
  _accumulateRollups(events) {
    mergeRollups(this._rollupBuffers, accumulateRollups(events));
  }

  // --- Rollup flush ---

  _docIdForFiveMin(d) { return `${d.bucket}|${d.event_type}|${d.action}`; }
  _docIdForIpHourly(d) { return `${d.bucket}|${d.ip}|${d.direction}`; }
  _docIdForPortHourly(d) { return `${d.bucket}|${d.port}|${d.protocol}`; }
  _docIdForSigHourly(d) { return `${d.bucket}|${d.signature}|${d.classification}`; }
  _docIdForClientHourly(d) { return `${d.bucket}|${d.mac}`; }

  async _upsertRollup(collection, id, doc, mergeFields) {
    const path = `/${collection}/docs/${encodeURIComponent(id)}`;
    const existing = await this._get(path);

    if (existing._notFound) {
      // Insert new doc with the deterministic _id in the body
      const body = { _id: id, ...doc };
      const created = await this._post(`/${collection}/docs`, body);
      if (created._conflict) {
        // Concurrent creation — fall through to PATCH on retry
        const refetched = await this._get(path);
        if (refetched._notFound) throw new Error(`Failed to upsert rollup ${id}: conflict but doc not found`);
        const merged = {};
        for (const f of mergeFields) merged[f] = (refetched.data[f] || 0) + (doc[f] || 0);
        await this._patch(path, merged);
      }
      return;
    }

    const merged = {};
    for (const f of mergeFields) merged[f] = (existing.data[f] || 0) + (doc[f] || 0);
    await this._patch(path, merged);
  }

  _mergeBuffersBack(drain) {
    const live = this._rollupBuffers;
    const mergeMap = (src, dst, fields) => {
      for (const [k, v] of src) {
        const ex = dst.get(k);
        if (ex) {
          for (const f of fields) ex[f] = (ex[f] || 0) + (v[f] || 0);
        } else {
          dst.set(k, v);
        }
      }
    };
    mergeMap(drain.fiveMin, live.fiveMin, ['count']);
    mergeMap(drain.ipHourly, live.ipHourly, ['event_count', 'blocked_count', 'threat_count']);
    mergeMap(drain.portHourly, live.portHourly, ['count']);
    mergeMap(drain.sigHourly, live.sigHourly, ['count']);
    mergeMap(drain.clientHourly, live.clientHourly, ['event_count', 'wifi_count', 'dhcp_count', 'firewall_count']);
  }

  async _flushRollups() {
    if (this._flushing) return;
    this._flushing = true;
    const t0 = Date.now();

    // Atomic swap
    const drain = this._rollupBuffers;
    this._rollupBuffers = this._newBuffers();

    const fiveMinFields = ['count'];
    const ipFields = ['event_count', 'blocked_count', 'threat_count'];
    const portFields = ['count'];
    const sigFields = ['count'];
    const clientFields = ['event_count', 'wifi_count', 'dhcp_count', 'firewall_count'];

    const tasks = [];
    for (const doc of drain.fiveMin.values()) tasks.push({ col: this.rollup5m, id: this._docIdForFiveMin(doc), doc, fields: fiveMinFields });
    for (const doc of drain.ipHourly.values()) tasks.push({ col: this.rollupIpHourly, id: this._docIdForIpHourly(doc), doc, fields: ipFields });
    for (const doc of drain.portHourly.values()) tasks.push({ col: this.rollupPortHourly, id: this._docIdForPortHourly(doc), doc, fields: portFields });
    for (const doc of drain.sigHourly.values()) tasks.push({ col: this.rollupSigHourly, id: this._docIdForSigHourly(doc), doc, fields: sigFields });
    for (const doc of drain.clientHourly.values()) tasks.push({ col: this.rollupClientHourly, id: this._docIdForClientHourly(doc), doc, fields: clientFields });

    if (tasks.length === 0) {
      this._flushing = false;
      return;
    }

    let failed = false;
    try {
      let i = 0;
      const workers = Array.from({ length: this.flushConcurrency }, async () => {
        while (i < tasks.length) {
          const my = tasks[i++];
          try {
            await this._upsertRollup(my.col, my.id, my.doc, my.fields);
          } catch (err) {
            failed = true;
            logger.debug({ err: err.message, id: my.id, col: my.col }, 'Rollup upsert failed');
          }
        }
      });
      await Promise.all(workers);
    } catch (err) {
      failed = true;
      logger.warn({ err: err.message }, 'Rollup flush worker pool failed');
    }

    if (failed) {
      logger.warn({ tasks: tasks.length }, 'Rollup flush had errors, re-merging buffers for retry');
      this._mergeBuffersBack(drain);
    }

    logger.debug({
      '5m': drain.fiveMin.size,
      ip: drain.ipHourly.size,
      port: drain.portHourly.size,
      sig: drain.sigHourly.size,
      client: drain.clientHourly.size,
      ms: Date.now() - t0,
    }, 'Rollup flush');

    this._flushing = false;
  }

  _startFlushInterval() {
    if (this._flushIntervalHandle) clearInterval(this._flushIntervalHandle);
    this._flushIntervalHandle = setInterval(() => {
      if (this._shuttingDown) return;
      this._flushRollups().catch(err =>
        logger.warn({ err: err.message }, 'Rollup flush cycle error'));
    }, FLUSH_INTERVAL_MS);
    this._flushIntervalHandle.unref?.();
  }

  // --- Lifecycle ---

  _getRequiredEventIndexes() {
    return [
      { name: 'idx_event_type', field: 'event_type' },
      { name: 'idx_received_at', field: 'received_at' },
      { name: 'idx_network_action', field: 'network.action' },
      { name: 'idx_src_ip', field: 'network.src_ip' },
      { name: 'idx_dst_ip', field: 'network.dst_ip' },
      { name: 'idx_dst_port', field: 'network.dst_port' },
      { name: 'idx_type_time', fields: ['event_type', 'received_at'] },
      { name: 'idx_action_time', fields: ['network.action', 'received_at'] },
      { name: 'idx_type_action', fields: ['event_type', 'network.action'] },
    ];
  }

  _getRollupIndexSpecs() {
    return [
      { col: this.rollup5m, name: 'idx_bucket', field: 'bucket' },
      { col: this.rollupIpHourly, name: 'idx_bucket', field: 'bucket' },
      { col: this.rollupIpHourly, name: 'idx_ip_bucket', fields: ['ip', 'bucket'] },
      { col: this.rollupPortHourly, name: 'idx_bucket', field: 'bucket' },
      { col: this.rollupSigHourly, name: 'idx_bucket', field: 'bucket' },
      { col: this.rollupClientHourly, name: 'idx_bucket', field: 'bucket' },
    ];
  }

  /**
   * Indexes on the enrichment_cache collection. Required for $in lookups
   * by IP, $exists / $gt / $gte filters, and accurate count_only queries.
   * Without these, WardSONDB falls back to full-collection scans capped at
   * 10,000 documents — causing Threat Intel summary counts to plateau at 10K
   * and $in lookups to miss IPs beyond that cap.
   */
  _getCacheIndexSpecs() {
    return [
      { col: this.cacheCollection, name: 'idx_cache_ip', field: 'ip' },
      { col: this.cacheCollection, name: 'idx_cache_is_private', field: 'is_private' },
      { col: this.cacheCollection, name: 'idx_cache_geo_country', field: 'geo_country' },
      { col: this.cacheCollection, name: 'idx_cache_abuse_score', field: 'abuse_score' },
    ];
  }

  async _ensureCollection(name) {
    try {
      await this._post('/_collections', { name });
      logger.info({ collection: name }, 'Created WardSONDB collection');
    } catch (err) {
      if (err.message.includes('COLLECTION_EXISTS')) return;
      throw err;
    }
  }

  async initialize() {
    // Verify connection
    const info = await this._get('/');
    logger.info({ backend: 'wardsondb', version: info.data.version, url: this.baseUrl }, 'Connected to WardSONDB');

    // Discover existing partitions
    const cols = await this._get('/_collections');
    const list = cols.data || [];
    let legacyDetected = false;
    for (const c of list) {
      const name = typeof c === 'string' ? c : c.name;
      if (!name) continue;
      if (PARTITION_NAME_RE.test(name)) this._partitions.add(name);
      else if (name === 'events') legacyDetected = true;
    }
    if (legacyDetected) {
      logger.warn('Legacy single `events` collection detected. It will be ignored — backend now uses daily partitions. Drop manually with `DELETE /events` when ready.');
    }
    logger.info({ partitions: this._partitions.size }, 'WardSONDB partitions discovered');

    // Ensure today's partition + 9 indexes
    const today = this._partitionName(new Date());
    await this._ensurePartition(today);

    // Ensure cache + 5 rollup collections
    await this._ensureCollection(this.cacheCollection);
    for (const col of [this.rollup5m, this.rollupIpHourly, this.rollupPortHourly, this.rollupSigHourly, this.rollupClientHourly]) {
      await this._ensureCollection(col);
    }
    for (const idx of [...this._getRollupIndexSpecs(), ...this._getCacheIndexSpecs()]) {
      try {
        const body = { name: idx.name };
        if (idx.fields) body.fields = idx.fields;
        else body.field = idx.field;
        await this._post(`/${idx.col}/indexes`, body);
      } catch (err) {
        if (!err.message?.includes('INDEX_EXISTS')) {
          logger.debug({ err: err.message, col: idx.col, idx: idx.name }, 'Rollup/cache index creation warn');
        }
      }
    }

    // Initial cached doc count from /_stats.total_documents (matches main).
    // Includes rollups+cache (small overhead) but is reliable.
    try {
      const stats = await this._get('/_stats');
      const t = stats.data?.total_documents;
      this._cachedDocCount = typeof t === 'number' ? t : null;
    } catch {
      this._cachedDocCount = null;
    }

    // Today's partition is empty (or pre-existing with indexes already), so
    // ingestion can resume immediately after reset/init.
    this.indexesReady = Promise.resolve();

    // Start the flush cycle
    this._startFlushInterval();

    // Schedule deferred rollup backfill (same 30s cadence as enrichment backfill)
    setTimeout(() => {
      this._runStartupBackfill().catch(err =>
        logger.warn({ err: err.message }, 'Rollup backfill failed'));
    }, 30000);

    logger.info({ backend: 'wardsondb', docCount: this._cachedDocCount, healthTimeoutMs: this.healthTimeoutMs }, 'Storage backend initialized');
  }

  /**
   * Sum doc_count across event-* partitions from a /_collections response payload.
   * Returns null when state is unknown (non-array response, or no matching
   * partitions when we haven't observed any yet either). Returns 0 only when
   * we know the DB is truly empty (partitions exist in-memory but all report 0).
   */
  _sumPartitionDocCounts(list) {
    if (!Array.isArray(list)) return null;
    let total = 0;
    let sawAny = false;
    for (const c of list) {
      if (typeof c !== 'object' || !c?.name) continue;
      if (!PARTITION_NAME_RE.test(c.name)) continue;
      const n = typeof c.doc_count === 'number' ? c.doc_count : null;
      if (n != null) {
        total += n;
        sawAny = true;
      }
    }
    if (sawAny) return total;
    // No matching partitions in the response. If we also have none cached,
    // the state is unknown (e.g., race during startup). If we have cached
    // partitions but the response doesn't list them (shouldn't happen but
    // defensive), prefer unknown over a bogus 0.
    if (this._partitions.size === 0) return null;
    return null;
  }

  async close() {
    this._shuttingDown = true;
    if (this._flushIntervalHandle) {
      clearInterval(this._flushIntervalHandle);
      this._flushIntervalHandle = null;
    }
    // Final flush — bypass _flushing guard
    this._flushing = false;
    try {
      await this._flushRollups();
    } catch (err) {
      logger.warn({ err: err.message }, 'Final rollup flush on shutdown failed');
    }
    // Release keep-alive sockets held by the per-client dispatcher.
    try {
      await this._agent?.close();
    } catch {}
  }

  async healthCheck() {
    try {
      const health = await this._healthRequest('/_health');
      const stats = await this._healthRequest('/_stats');

      // Ensure today's partition exists (handles server-restart-on-new-day)
      const today = this._partitionName(new Date());
      if (!this._partitions.has(today)) {
        await this._ensurePartition(today);
      }

      // Use /_stats.total_documents directly — this is what main did and it's
      // a single, reliable, server-reported number. After partitioning it
      // includes rollups+cache (small overhead, ~0.1% of events count for
      // typical deployments) but it does NOT flicker the way per-partition
      // doc_count does during WardSONDB internal stats rebuilds.
      //
      // Defensive: if total_documents reads as 0 but we previously saw a
      // positive value, treat as transient noise and keep cached. Only
      // resetData() can legitimately drop the count to zero (it sets cached
      // to 0 explicitly).
      let docCount = typeof stats.data?.total_documents === 'number'
        ? stats.data.total_documents
        : this._cachedDocCount;
      if (docCount === 0 && typeof this._cachedDocCount === 'number' && this._cachedDocCount > 0) {
        logger.debug({ cachedDocCount: this._cachedDocCount }, 'WardSONDB stats.total_documents=0 but cached > 0, preserving cached value');
        docCount = this._cachedDocCount;
      } else {
        this._cachedDocCount = docCount;
      }

      return {
        ok: health.data.status === 'healthy',
        writePressure: health.data.write_pressure || 'normal',
        details: {
          backend: 'wardsondb',
          url: this.baseUrl,
          collections: stats.data.collection_count,
          totalDocuments: docCount,
          uptime: stats.data.uptime_seconds,
          eventsStorage: {
            docCount,
            indexCount: null,
            oldestDoc: null,
            newestDoc: null,
            partitions: this._partitions.size,
          },
        },
      };
    } catch (err) {
      return { ok: false, details: { backend: 'wardsondb', error: err.message } };
    }
  }

  // --- Document Transformation ---

  /** Transform a flat SIEM event into a nested WardSONDB document */
  _eventToDocument(event) {
    const doc = {
      event_type: event.event_type,
      severity: event.severity ?? null,
      hostname: event.hostname || null,
      source_format: event.source_format || null,
      message: event.message || null,
      timestamp: event.timestamp || null,
      received_at: event.received_at || new Date().toISOString(),
    };

    if (event.raw_message) doc.raw_message = event.raw_message;

    if (event.action || event.src_ip || event.dst_ip || event.protocol) {
      doc.network = {};
      if (event.action) doc.network.action = event.action;
      if (event.direction) doc.network.direction = event.direction;
      if (event.interface_in) doc.network.interface_in = event.interface_in;
      if (event.interface_out) doc.network.interface_out = event.interface_out;
      if (event.protocol) doc.network.protocol = event.protocol;
      if (event.src_ip) doc.network.src_ip = event.src_ip;
      if (event.src_port != null) doc.network.src_port = event.src_port;
      if (event.dst_ip) doc.network.dst_ip = event.dst_ip;
      if (event.dst_port != null) doc.network.dst_port = event.dst_port;
      if (event.packet_length != null) doc.network.packet_length = event.packet_length;
      if (event.ttl != null) doc.network.ttl = event.ttl;
      if (event.tcp_flags) doc.network.tcp_flags = event.tcp_flags;
      if (event.mac_src) doc.network.mac_src = event.mac_src;
      if (event.mac_dst) doc.network.mac_dst = event.mac_dst;
      if (event.rule_prefix) doc.network.rule_prefix = event.rule_prefix;
    }

    if (event.ids_signature_id || event.ids_signature) {
      doc.ids = {};
      if (event.ids_signature_id) doc.ids.signature_id = event.ids_signature_id;
      if (event.ids_signature) doc.ids.signature = event.ids_signature;
      if (event.ids_classification) doc.ids.classification = event.ids_classification;
      if (event.ids_priority != null) doc.ids.priority = event.ids_priority;
      if (event.threat_type) doc.ids.threat_type = event.threat_type;
      if (event.threat_category) doc.ids.threat_category = event.threat_category;
    }

    if (event.dhcp_action || event.dhcp_ip || event.dhcp_mac) {
      doc.dhcp = {};
      if (event.dhcp_action) doc.dhcp.action = event.dhcp_action;
      if (event.dhcp_ip) doc.dhcp.ip = event.dhcp_ip;
      if (event.dhcp_mac) doc.dhcp.mac = event.dhcp_mac;
      if (event.dhcp_hostname) doc.dhcp.hostname = event.dhcp_hostname;
      if (event.dhcp_interface) doc.dhcp.interface = event.dhcp_interface;
    }

    if (event.dns_action || event.dns_name) {
      doc.dns = {};
      if (event.dns_action) doc.dns.action = event.dns_action;
      if (event.dns_name) doc.dns.name = event.dns_name;
      if (event.dns_type) doc.dns.type = event.dns_type;
      if (event.dns_result) doc.dns.result = event.dns_result;
      if (event.dns_client_ip) doc.dns.client_ip = event.dns_client_ip;
      if (event.dns_filter_type) doc.dns.filter_type = event.dns_filter_type;
      if (event.dns_filter_category) doc.dns.filter_category = event.dns_filter_category;
    }

    if (event.wifi_action || event.wifi_client_mac) {
      doc.wifi = {};
      if (event.wifi_action) doc.wifi.action = event.wifi_action;
      if (event.wifi_client_mac) doc.wifi.client_mac = event.wifi_client_mac;
      if (event.wifi_radio) doc.wifi.radio = event.wifi_radio;
      if (event.wifi_ssid) doc.wifi.ssid = event.wifi_ssid;
      if (event.wifi_channel != null) doc.wifi.channel = event.wifi_channel;
      if (event.wifi_rssi != null) doc.wifi.rssi = event.wifi_rssi;
    }

    if (event.cef_event_class_id || event.cef_name) {
      doc.cef = {};
      if (event.cef_event_class_id) doc.cef.event_class_id = event.cef_event_class_id;
      if (event.cef_name) doc.cef.name = event.cef_name;
      if (event.cef_severity != null) doc.cef.severity = event.cef_severity;
      if (event.unifi_category) doc.cef.category = event.unifi_category;
      if (event.unifi_subcategory) doc.cef.subcategory = event.unifi_subcategory;
      if (event.unifi_host) doc.cef.host = event.unifi_host;
    }

    if (event.client_alias || event.client_mac || event.client_ip) {
      doc.client = {};
      if (event.client_alias) doc.client.alias = event.client_alias;
      if (event.client_mac) doc.client.mac = event.client_mac;
      if (event.client_ip) doc.client.ip = event.client_ip;
    }

    return doc;
  }

  /**
   * Transform a WardSONDB document back into the flat SIEM event format.
   * If `cacheMap` is provided, overlay enrichment fields from cache when the
   * stored doc lacks them — keeps Live Stream / Event Detail rendering
   * SQLite-equivalent for events in older partitions.
   */
  _documentToEvent(doc, cacheMap = null) {
    const event = {
      id: doc._id,
      event_type: doc.event_type,
      severity: doc.severity,
      hostname: doc.hostname,
      source_format: doc.source_format,
      message: doc.message,
      timestamp: doc.timestamp,
      received_at: doc.received_at || doc._created_at,
      raw_message: doc.raw_message || null,
    };

    if (doc.network) {
      event.action = doc.network.action || null;
      event.direction = doc.network.direction || null;
      event.interface_in = doc.network.interface_in || null;
      event.interface_out = doc.network.interface_out || null;
      event.protocol = doc.network.protocol || null;
      event.src_ip = doc.network.src_ip || null;
      event.src_port = doc.network.src_port ?? null;
      event.dst_ip = doc.network.dst_ip || null;
      event.dst_port = doc.network.dst_port ?? null;
      event.packet_length = doc.network.packet_length ?? null;
      event.ttl = doc.network.ttl ?? null;
      event.tcp_flags = doc.network.tcp_flags || null;
      event.mac_src = doc.network.mac_src || null;
      event.mac_dst = doc.network.mac_dst || null;
      event.rule_prefix = doc.network.rule_prefix || null;
    }

    if (doc.ids) {
      event.ids_signature_id = doc.ids.signature_id || null;
      event.ids_signature = doc.ids.signature || null;
      event.ids_classification = doc.ids.classification || null;
      event.ids_priority = doc.ids.priority ?? null;
      event.threat_type = doc.ids.threat_type || null;
      event.threat_category = doc.ids.threat_category || null;
    }

    if (doc.dhcp) {
      event.dhcp_action = doc.dhcp.action || null;
      event.dhcp_ip = doc.dhcp.ip || null;
      event.dhcp_mac = doc.dhcp.mac || null;
      event.dhcp_hostname = doc.dhcp.hostname || null;
      event.dhcp_interface = doc.dhcp.interface || null;
    }

    if (doc.dns) {
      event.dns_action = doc.dns.action || null;
      event.dns_name = doc.dns.name || null;
      event.dns_type = doc.dns.type || null;
      event.dns_result = doc.dns.result || null;
      event.dns_client_ip = doc.dns.client_ip || null;
      event.dns_filter_type = doc.dns.filter_type || null;
      event.dns_filter_category = doc.dns.filter_category || null;
    }

    if (doc.wifi) {
      event.wifi_action = doc.wifi.action || null;
      event.wifi_client_mac = doc.wifi.client_mac || null;
      event.wifi_radio = doc.wifi.radio || null;
      event.wifi_ssid = doc.wifi.ssid || null;
      event.wifi_channel = doc.wifi.channel ?? null;
      event.wifi_rssi = doc.wifi.rssi ?? null;
    }

    if (doc.cef) {
      event.cef_event_class_id = doc.cef.event_class_id || null;
      event.cef_name = doc.cef.name || null;
      event.cef_severity = doc.cef.severity ?? null;
      event.unifi_category = doc.cef.category || null;
      event.unifi_subcategory = doc.cef.subcategory || null;
      event.unifi_host = doc.cef.host || null;
    }

    if (doc.client) {
      event.client_alias = doc.client.alias || null;
      event.client_mac = doc.client.mac || null;
      event.client_ip = doc.client.ip || null;
    }

    // Stored enrichment (today's partition only — written by updateEnrichment)
    if (doc.enrichment) {
      if (doc.enrichment.src) {
        event.src_geo_country = doc.enrichment.src.geo_country || null;
        event.src_geo_city = doc.enrichment.src.geo_city || null;
        event.src_geo_lat = doc.enrichment.src.geo_lat ?? null;
        event.src_geo_lon = doc.enrichment.src.geo_lon ?? null;
        event.src_abuse_score = doc.enrichment.src.abuse_score ?? null;
        event.src_hostname = doc.enrichment.src.hostname || null;
      }
      if (doc.enrichment.dst) {
        event.dst_geo_country = doc.enrichment.dst.geo_country || null;
        event.dst_geo_city = doc.enrichment.dst.geo_city || null;
        event.dst_geo_lat = doc.enrichment.dst.geo_lat ?? null;
        event.dst_geo_lon = doc.enrichment.dst.geo_lon ?? null;
        event.dst_abuse_score = doc.enrichment.dst.abuse_score ?? null;
        event.dst_hostname = doc.enrichment.dst.hostname || null;
      }
    }

    // Query-time cache overlay for older partitions (no stored enrichment)
    if (cacheMap) {
      if (event.src_ip && event.src_geo_country == null) {
        const c = cacheMap.get(event.src_ip);
        if (c) {
          event.src_geo_country = c.geo_country || null;
          event.src_geo_city = c.geo_city || null;
          event.src_geo_lat = c.geo_lat ?? null;
          event.src_geo_lon = c.geo_lon ?? null;
          event.src_abuse_score = c.abuse_score ?? null;
          event.src_hostname = c.hostname || null;
        }
      }
      if (event.dst_ip && event.dst_geo_country == null) {
        const c = cacheMap.get(event.dst_ip);
        if (c) {
          event.dst_geo_country = c.geo_country || null;
          event.dst_geo_city = c.geo_city || null;
          event.dst_geo_lat = c.geo_lat ?? null;
          event.dst_geo_lon = c.geo_lon ?? null;
          event.dst_abuse_score = c.abuse_score ?? null;
          event.dst_hostname = c.hostname || null;
        }
      }
    }

    return event;
  }

  // --- Write Operations ---

  async insertEvents(events) {
    if (!events?.length) return { inserted: 0 };

    // Group by UTC date of received_at — almost always one group, except at midnight
    const byDate = new Map();
    for (const evt of events) {
      const ts = evt.received_at || new Date().toISOString();
      const date = String(ts).substring(0, 10);
      let arr = byDate.get(date);
      if (!arr) { arr = []; byDate.set(date, arr); }
      arr.push(evt);
    }

    let totalInserted = 0;
    const CHUNK = 500;

    for (const [date, group] of byDate) {
      const partition = `${PARTITION_PREFIX}${date}`;
      await this._ensurePartition(partition);
      const documents = group.map(e => this._eventToDocument(e));
      for (let i = 0; i < documents.length; i += CHUNK) {
        const chunk = documents.slice(i, i + CHUNK);
        const result = await this._post(`/${partition}/docs/_bulk`, { documents: chunk });
        totalInserted += result.data?.inserted || 0;
        if (result.data?.errors?.length > 0) {
          // NEW-C8: include sample of error messages so operators can root-
          // cause ingest failures (malformed nested types, doc-too-large,
          // etc.) instead of just seeing a count.
          logger.warn({
            partition,
            errors: result.data.errors.length,
            sample: result.data.errors.slice(0, 3),
          }, 'WardSONDB bulk insert had errors');
        }
      }
    }

    // Update cached doc count additively so empty-DB short-circuit clears
    if (totalInserted > 0) {
      this._cachedDocCount = (this._cachedDocCount || 0) + totalInserted;
    }

    // Accumulate rollups for the inserted batch
    this._accumulateRollups(events);

    return { inserted: totalInserted };
  }

  /**
   * Update enrichment fields on today's partition only. Older partitions rely
   * on query-time cache overlay (see _documentToEvent). Uses the API's
   * _update_by_query endpoint for atomic single-call updates.
   */
  async updateEnrichment(ip, direction, data) {
    const today = this._partitionName(new Date());
    if (!this._partitions.has(today)) return { updated: 0 };

    const ipField = direction === 'dst' ? 'network.dst_ip' : 'network.src_ip';
    const setKey = direction === 'dst' ? 'enrichment.dst' : 'enrichment.src';
    const geoCheckKey = `${setKey}.geo_country`;

    const result = await this._post(`/${today}/docs/_update_by_query`, {
      filter: { [ipField]: ip, [geoCheckKey]: { '$exists': false } },
      update: {
        '$set': {
          [`${setKey}.geo_country`]: data.geo_country ?? null,
          [`${setKey}.geo_city`]: data.geo_city ?? null,
          [`${setKey}.geo_lat`]: data.geo_lat ?? null,
          [`${setKey}.geo_lon`]: data.geo_lon ?? null,
          [`${setKey}.abuse_score`]: data.abuse_score ?? null,
          [`${setKey}.hostname`]: data.hostname ?? null,
        },
      },
    });

    return { updated: result.data?.updated || 0 };
  }

  // --- Read Operations ---

  /** Build a WardSONDB filter object from queryEvents-style HTTP filters. */
  _buildFilter(filters) {
    const filter = {};
    const andClauses = [];

    if (filters.event_type) {
      const types = filters.event_type.split(',');
      if (types.length === 1) filter.event_type = types[0];
      else andClauses.push({ event_type: { '$in': types } });
    }
    if (filters.action) andClauses.push({ 'network.action': filters.action });
    if (filters.direction) andClauses.push({ 'network.direction': filters.direction });
    if (filters.severity) {
      const sevs = filters.severity.split(',').map(Number);
      andClauses.push({ severity: { '$in': sevs } });
    }
    if (filters.src_ip) andClauses.push({ 'network.src_ip': filters.src_ip });
    if (filters.dst_ip) andClauses.push({ 'network.dst_ip': filters.dst_ip });
    if (filters.dst_port) andClauses.push({ 'network.dst_port': parseInt(filters.dst_port, 10) });
    if (filters.protocol) andClauses.push({ 'network.protocol': filters.protocol.toUpperCase() });
    if (filters.since) andClauses.push({ received_at: { '$gte': filters.since } });
    if (filters.until) andClauses.push({ received_at: { '$lte': filters.until } });
    if (filters.search) {
      // NEW-C1: escape regex meta-characters so user input behaves like SQLite's
      // substring LIKE pattern instead of a regex (192.168.1.1 should match the
      // literal IP, not "192a168b1c1"). Cap at 1024 chars (API.md regex pattern
      // length limit).
      const escaped = String(filters.search).slice(0, 1024).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      andClauses.push({ message: { '$regex': escaped } });
    }
    if (filters.mac) {
      andClauses.push({
        '$or': [
          { 'client.mac': filters.mac },
          { 'wifi.client_mac': filters.mac },
          { 'dhcp.mac': filters.mac },
          { 'network.mac_src': filters.mac },
          { 'network.mac_dst': filters.mac },
        ],
      });
    }

    if (andClauses.length === 0 && Object.keys(filter).length === 0) return null;
    const allClauses = [...andClauses];
    for (const [k, v] of Object.entries(filter)) allClauses.push({ [k]: v });
    return allClauses.length === 1 ? allClauses[0] : { '$and': allClauses };
  }

  async queryEvents(filters = {}) {
    const limit = Math.min(parseInt(filters.limit || '50', 10), 500);
    let offset = parseInt(filters.offset || '0', 10);
    const queryFilter = this._buildFilter(filters);
    const cacheMap = await this._getCacheMap();

    const queryPartition = async (partition, remaining) => {
      const result = await this._post(`/${partition}/query`, {
        filter: queryFilter,
        sort: [{ 'received_at': 'desc' }],
        limit: remaining,
        offset,
      });
      const docs = result.data || [];
      // Approximate offset across boundaries: decrement what this partition consumed
      if (offset > 0) offset = Math.max(0, offset - docs.length);
      return docs.map(d => this._documentToEvent(d, cacheMap));
    };

    const events = await this._queryAcrossPartitions(queryPartition, filters.since, filters.until, limit);
    return { events };
  }

  async getEventById(id) {
    // M17: validate UUIDv7 shape up front. A malformed id used to scan
    // every partition sequentially — at 30+ daily partitions × 30s
    // server-side query timeout, a single bad id could hang the request
    // for many minutes.
    const UUIDV7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (typeof id !== 'string' || !UUIDV7_RE.test(id)) return null;

    const cacheMap = await this._getCacheMap();
    const partition = this._partitionFromId(id);

    if (partition && this._partitions.has(partition)) {
      const result = await this._get(`/${partition}/docs/${encodeURIComponent(id)}`);
      if (!result._notFound) return this._documentToEvent(result.data, cacheMap);
    }

    // M17: bounded fallback to the 7 most-recent partitions only. A
    // valid UUIDv7 whose partition isn't in this._partitions is a rare
    // race (server restart between _partitions refresh and the GET);
    // unbounded scanning was the worst-case hang path.
    for (const p of this._partitionsNewestFirst().slice(0, 7)) {
      try {
        const r = await this._get(`/${p}/docs/${encodeURIComponent(id)}`);
        if (!r._notFound) return this._documentToEvent(r.data, cacheMap);
      } catch {}
    }
    return null;
  }

  async getEventCount() {
    // Preserve null (unknown state) vs 0 (confirmed empty) so the sidebar
    // renders '—' rather than a false '0' during startup before /_collections
    // resolves.
    return this._cachedDocCount;
  }

  async getEventCountToday() {
    if (this._isCollectionEmpty()) return 0;
    const midnight = new Date();
    midnight.setHours(0, 0, 0, 0);
    const midnightISO = midnight.toISOString();

    const result = await this._post(`/${this.rollup5m}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': midnightISO } } },
        { '$group': { '_id': null, total: { '$sum': 'count' } } },
      ],
    });
    let total = result.data?.[0]?.total || 0;

    // Add unflushed rollup buffer contribution so the counter stays accurate
    // during the up-to-5s gap between ingest and the next flush cycle.
    for (const doc of this._rollupBuffers.fiveMin.values()) {
      if (doc.bucket >= midnightISO) total += doc.count || 0;
    }
    return total;
  }

  async getLastEventTime() {
    if (this._isCollectionEmpty()) return null;
    for (const p of this._partitionsNewestFirst()) {
      try {
        const r = await this._post(`/${p}/query`, {
          sort: [{ 'received_at': 'desc' }],
          fields: ['received_at'],
          limit: 1,
        });
        if (r.data?.length > 0) return r.data[0].received_at || r.data[0]._created_at;
      } catch (err) {
        logger.debug({ err: err.message, partition: p }, 'getLastEventTime partition query failed');
      }
    }
    return null;
  }

  async getEventTypeCounts(since) {
    if (this._isCollectionEmpty()) return {};
    const pipeline = [];
    if (since) pipeline.push({ '$match': { bucket: { '$gte': since } } });
    pipeline.push({ '$group': { '_id': 'event_type', count: { '$sum': 'count' } } });
    pipeline.push({ '$sort': { count: 'desc' } });
    const result = await this._post(`/${this.rollup5m}/aggregate`, { pipeline });
    const counts = {};
    for (const row of (result.data || [])) {
      if (row._id && row.count > 0) counts[row._id] = row.count;
    }
    return counts;
  }

  // --- Stats / Aggregation (rollup-based) ---

  _isCollectionEmpty() {
    return this._cachedDocCount === 0;
  }

  async getOverviewStats(since) {
    if (this._isCollectionEmpty()) {
      return { total: 0, byType: {}, firewall: { allowed: 0, blocked: 0, threats: 0 } };
    }
    const timeMatch = { bucket: { '$gte': since } };
    const sumOnlyGroup = { '_id': null, total: { '$sum': 'count' } };
    const agg = (filter) => this._post(`/${this.rollup5m}/aggregate`, {
      pipeline: [{ '$match': filter }, { '$group': sumOnlyGroup }],
    });

    const [totalRes, byTypeRes, allowedRes, blockedRes, threatRes] = await Promise.all([
      agg(timeMatch),
      this._post(`/${this.rollup5m}/aggregate`, {
        pipeline: [
          { '$match': timeMatch },
          { '$group': { '_id': 'event_type', count: { '$sum': 'count' } } },
        ],
      }),
      agg({ ...timeMatch, event_type: 'firewall', action: 'allow' }),
      agg({ ...timeMatch, event_type: 'firewall', action: 'block' }),
      agg({ ...timeMatch, event_type: 'threat' }),
    ]);

    const byType = {};
    for (const row of (byTypeRes.data || [])) {
      if (row._id) byType[row._id] = row.count || 0;
    }

    return {
      total: totalRes.data?.[0]?.total || 0,
      byType,
      firewall: {
        allowed: allowedRes.data?.[0]?.total || 0,
        blocked: blockedRes.data?.[0]?.total || 0,
        threats: threatRes.data?.[0]?.total || 0,
      },
    };
  }

  /**
   * Timeline aggregation — single $group on rollups-5m, then re-bucket
   * client-side into the requested bucketSize (5m/15m/1h/1d) with zero-fill.
   * Mirrors sqlite.js:705-768.
   */
  async getTimeline(since, _bucketFormat, eventType, bucketSize) {
    if (this._isCollectionEmpty()) return [];

    const bucketMs = {
      '5m': 5 * 60000,
      '15m': 15 * 60000,
      '1h': 3600000,
      '1d': 86400000,
    }[bucketSize || '1h'] || 3600000;

    const start = new Date(Math.floor(new Date(since).getTime() / bucketMs) * bucketMs);
    const end = new Date(Math.floor(Date.now() / bucketMs) * bucketMs);
    const numBuckets = Math.floor((end - start) / bucketMs) + 1;

    const buckets = new Map();
    for (let i = 0; i < numBuckets; i++) {
      const ts = new Date(start.getTime() + i * bucketMs).toISOString();
      buckets.set(ts, eventType === 'firewall'
        ? { ts, allowed: 0, blocked: 0 }
        : { ts, firewall: 0, threat: 0, dhcp: 0, dns_filter: 0, wifi: 0, admin: 0, system: 0, total: 0 });
    }

    const result = await this._post(`/${this.rollup5m}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': start.toISOString() } } },
        { '$group': {
          '_id': { b: 'bucket', t: 'event_type', a: 'action' },
          count: { '$sum': 'count' },
        }},
      ],
    });

    for (const row of (result.data || [])) {
      const b = row._id?.b;
      const tp = row._id?.t;
      const ac = row._id?.a;
      if (!b) continue;
      const aligned = new Date(Math.floor(new Date(b).getTime() / bucketMs) * bucketMs).toISOString();
      const bucket = buckets.get(aligned);
      if (!bucket) continue;
      const cnt = row.count || 0;
      if (eventType === 'firewall') {
        if (tp !== 'firewall') continue;
        if (ac === 'allow') bucket.allowed += cnt;
        else if (ac === 'block') bucket.blocked += cnt;
      } else {
        if (tp && tp in bucket) bucket[tp] += cnt;
        bucket.total += cnt;
      }
    }

    return Array.from(buckets.values());
  }

  async _getCacheMap() {
    if (this._cacheMapTs && Date.now() - this._cacheMapTs < 30000) return this._cacheMap;
    const CAP = 100000;
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: { is_private: false },
      limit: CAP,
    });
    const data = result.data || [];
    if (data.length >= CAP) {
      logger.warn({ loaded: data.length, cap: CAP },
        'WardSONDB _getCacheMap hit cap — some enrichment data may be missing from event/stats joins');
    }
    this._cacheMap = new Map(data.map(d => [d.ip, d]));
    this._cacheMapTs = Date.now();
    return this._cacheMap;
  }

  async getTopTalkers(since, direction, limit, excludePrivate) {
    if (this._isCollectionEmpty()) return [];
    const dir = direction === 'dst' ? 'dst' : 'src';
    const fetchLimit = excludePrivate ? limit * 5 : limit;

    const result = await this._post(`/${this.rollupIpHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since }, direction: dir } },
        { '$group': { '_id': 'ip', count: { '$sum': 'event_count' } } },
        { '$sort': { count: 'desc' } },
        { '$limit': fetchLimit },
      ],
    });

    const cacheMap = await this._getCacheMap();
    let rows = (result.data || []).map(r => {
      const c = cacheMap.get(r._id) || {};
      return {
        ip: r._id,
        count: r.count || 0,
        lastSeen: null,
        country: c.geo_country || null,
        hostname: c.hostname || null,
      };
    });
    if (excludePrivate) rows = rows.filter(r => !isPrivateIp(r.ip));
    return rows.slice(0, limit);
  }

  async getTopBlocked(since, direction, limit, excludePrivate) {
    if (this._isCollectionEmpty()) return [];
    const dir = direction === 'dst' ? 'dst' : 'src';
    const fetchLimit = excludePrivate ? limit * 5 : limit;

    const result = await this._post(`/${this.rollupIpHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since }, direction: dir } },
        { '$group': { '_id': 'ip', count: { '$sum': 'blocked_count' } } },
        { '$match': { count: { '$gt': 0 } } },
        { '$sort': { count: 'desc' } },
        { '$limit': fetchLimit },
      ],
    });

    const cacheMap = await this._getCacheMap();
    let rows = (result.data || []).map(r => {
      const c = cacheMap.get(r._id) || {};
      return {
        ip: r._id,
        count: r.count || 0,
        lastSeen: null,
        country: c.geo_country || null,
        abuseScore: c.abuse_score ?? null,
        hostname: c.hostname || null,
      };
    });
    if (excludePrivate) rows = rows.filter(r => !isPrivateIp(r.ip));
    return rows.slice(0, limit);
  }

  async getTopPorts(since, limit) {
    if (this._isCollectionEmpty()) return [];
    const result = await this._post(`/${this.rollupPortHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since } } },
        { '$group': { '_id': { port: 'port', protocol: 'protocol' }, count: { '$sum': 'count' } } },
        { '$sort': { count: 'desc' } },
        { '$limit': limit },
      ],
    });
    return (result.data || []).map(r => ({
      port: r._id?.port,
      protocol: r._id?.protocol || null,
      count: r.count || 0,
    }));
  }

  async getTopClients(since, limit) {
    if (this._isCollectionEmpty()) return [];
    const result = await this._post(`/${this.rollupClientHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since } } },
        { '$group': {
          '_id': 'mac',
          eventCount: { '$sum': 'event_count' },
          wifiEvents: { '$sum': 'wifi_count' },
          dhcpEvents: { '$sum': 'dhcp_count' },
          firewallEvents: { '$sum': 'firewall_count' },
        }},
        { '$sort': { eventCount: 'desc' } },
        { '$limit': limit },
      ],
    });
    return (result.data || []).map(r => ({
      mac: r._id,
      alias: null,
      ip: null,
      eventCount: r.eventCount || 0,
      wifiEvents: r.wifiEvents || 0,
      dhcpEvents: r.dhcpEvents || 0,
      firewallEvents: r.firewallEvents || 0,
    }));
  }

  async getTopThreats(since, limit) {
    if (this._isCollectionEmpty()) return [];
    const result = await this._post(`/${this.rollupSigHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since } } },
        { '$group': {
          '_id': { signature: 'signature', classification: 'classification' },
          count: { '$sum': 'count' },
        }},
        { '$sort': { count: 'desc' } },
        { '$limit': limit },
      ],
    });
    return (result.data || []).map(r => ({
      signature: r._id?.signature || null,
      classification: r._id?.classification || null,
      count: r.count || 0,
      lastSeen: null,
    }));
  }

  async getThreatIntel(since, limit) {
    if (this._isCollectionEmpty()) {
      return {
        summary: { totalEnriched: 0, withAbuseScore: 0, highThreat: 0, countries: 0 },
        periodSummary: { enriched: 0, flagged: 0, highThreat: 0, countries: 0 },
        ips: [],
      };
    }

    const t0 = Date.now();

    // --- Global summary ---
    // Use $group+$count aggregation instead of count_only so accuracy isn't
    // bounded by any scan cap. Each pipeline fully aggregates the filtered set.
    const enrichedCount = async (filter) => {
      const r = await this._post(`/${this.cacheCollection}/aggregate`, {
        pipeline: [
          { '$match': filter },
          { '$group': { '_id': null, count: { '$count': {} } } },
        ],
      });
      return r.data?.[0]?.count || 0;
    };

    const [totalEnriched, withAbuseScore, highThreat, countriesRes] = await Promise.all([
      // Enriched = has geo_country OR abuse_score set (non-null). WardSONDB
      // documents always have these fields (set to null on miss), so test for
      // non-null truthiness via separate $or queries against concrete values.
      enrichedCount({
        is_private: false,
        '$or': [
          // NEW-C6: $ne is not in WardSONDB's index-supported operators
          // list (API.md:1317), so $ne: null silently falls back to a
          // 10K-clamped full scan. $gte: '' / $gte: 0 hit the existing
          // idx_cache_geo_country / idx_cache_abuse_score indexes.
          { geo_country: { '$gte': '' } },
          { abuse_score: { '$gte': 0 } },
        ],
      }),
      enrichedCount({ is_private: false, abuse_score: { '$gt': 0 } }),
      enrichedCount({ is_private: false, abuse_score: { '$gte': 50 } }),
      this._post(`/${this.cacheCollection}/distinct`, {
        field: 'geo_country',
        filter: { is_private: false, geo_country: { '$gte': '' } },  // NEW-C6
        limit: 1000,
      }).catch(() => ({ data: { count: 0 } })),
    ]);
    const summary = {
      totalEnriched,
      withAbuseScore,
      highThreat,
      countries: countriesRes.data?.count || 0,
    };

    // --- Top IPs ---
    // Match SQLite semantics: sort by event_count desc (with abuse_score desc
    // as client-side tiebreaker after enrichment join). No threat_count filter
    // — Threat Intel shows active enriched IPs, not just IDS-alert IPs.
    const OVERFETCH = Math.min(Math.max(limit * 10, 500), 10000);
    const topAgg = await this._post(`/${this.rollupIpHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since } } },
        { '$group': {
          '_id': 'ip',
          event_count: { '$sum': 'event_count' },
          blocked_count: { '$sum': 'blocked_count' },
          threat_count: { '$sum': 'threat_count' },
        }},
        { '$sort': { event_count: 'desc' } },
        { '$limit': OVERFETCH },
      ],
    });

    const aggRows = topAgg.data || [];
    const aggIps = aggRows.map(r => r._id).filter(Boolean);

    // Targeted cache fetch keyed by ip (requires idx_cache_ip for reliability
    // beyond the 10K query cap).
    let cacheMap = new Map();
    if (aggIps.length > 0) {
      const cacheRes = await this._post(`/${this.cacheCollection}/query`, {
        filter: { ip: { '$in': aggIps }, is_private: false },
        limit: Math.min(aggIps.length, 10000),
      });
      cacheMap = new Map((cacheRes.data || []).map(d => [d.ip, d]));
    }

    // SQLite parity: only show IPs that are enriched with geo or abuse data.
    const enrichedRows = aggRows.filter(r => {
      const c = cacheMap.get(r._id);
      return c && (c.geo_country != null || c.abuse_score != null);
    });

    // Apply abuse_score tiebreaker client-side (SQLite: ORDER BY event_count DESC, abuse_score DESC)
    enrichedRows.sort((a, b) => {
      const ea = a.event_count || 0, eb = b.event_count || 0;
      if (ea !== eb) return eb - ea;
      const sa = cacheMap.get(a._id)?.abuse_score ?? -1;
      const sb = cacheMap.get(b._id)?.abuse_score ?? -1;
      return sb - sa;
    });

    const ips = enrichedRows
      .slice(0, limit)
      .map(r => {
        const c = cacheMap.get(r._id) || {};
        return {
          ip: r._id,
          country: c.geo_country || null,
          city: c.geo_city || null,
          lat: c.geo_lat ?? null,
          lon: c.geo_lon ?? null,
          abuse_score: c.abuse_score ?? null,
          hostname: c.hostname || null,
          event_count: r.event_count || 0,
          blocked_count: r.blocked_count || 0,
          threat_count: r.threat_count || 0,
          lastSeen: null,
        };
      });

    // --- Period summary ---
    const periodIpsRes = await this._post(`/${this.rollupIpHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since } } },
        { '$group': { '_id': 'ip' } },
        { '$limit': 10000 },
      ],
    });
    const periodIps = (periodIpsRes.data || []).map(r => r._id).filter(Boolean);

    let periodSummary = { enriched: 0, flagged: 0, highThreat: 0, countries: 0 };
    if (periodIps.length > 0) {
      const CHUNK = 500;
      const countriesSet = new Set();
      let enriched = 0, flagged = 0, highThreatCount = 0;
      for (let i = 0; i < periodIps.length; i += CHUNK) {
        const chunk = periodIps.slice(i, i + CHUNK);
        const res = await this._post(`/${this.cacheCollection}/query`, {
          filter: { ip: { '$in': chunk }, is_private: false },
          limit: chunk.length,
        });
        for (const d of (res.data || [])) {
          if (d.geo_country != null || d.abuse_score != null) enriched++;
          if (d.abuse_score > 0) flagged++;
          if (d.abuse_score >= 50) highThreatCount++;
          if (d.geo_country) countriesSet.add(d.geo_country);
        }
      }
      periodSummary = { enriched, flagged, highThreat: highThreatCount, countries: countriesSet.size };
    }

    // H11: diagnostic log demoted to debug. Was info to help debug
    // empty-result cases; permanent info-level logging at the
    // dashboard's 5-30s poll cadence floods logs in steady state.
    logger.debug({
      since, limit,
      aggRows: aggRows.length,
      cacheHits: cacheMap.size,
      enrichedRows: enrichedRows.length,
      finalIps: ips.length,
      periodIps: periodIps.length,
      ms: Date.now() - t0,
    }, 'WardSONDB getThreatIntel diagnostic');

    return { summary, periodSummary, ips };
  }

  async getGeoEvents(since, limit) {
    if (this._isCollectionEmpty()) return [];

    // Over-fetch per direction so the geo filter (applied client-side after
    // the cache join) doesn't starve the final result when many top IPs are
    // private/multicast/unenriched. Mirror getThreatIntel's scaling.
    const OVERFETCH = Math.min(Math.max(limit * 10, 500), 10000);

    const aggDir = (dir) => this._post(`/${this.rollupIpHourly}/aggregate`, {
      pipeline: [
        { '$match': { bucket: { '$gte': since }, direction: dir } },
        { '$group': {
          '_id': 'ip',
          count: { '$sum': 'event_count' },
          blocked: { '$sum': 'blocked_count' },
          threats: { '$sum': 'threat_count' },
        }},
        { '$sort': { count: 'desc' } },
        { '$limit': OVERFETCH },
      ],
    });

    const [srcRes, dstRes] = await Promise.all([aggDir('src'), aggDir('dst')]);
    const srcRows = srcRes.data || [];
    const dstRows = dstRes.data || [];

    // Targeted cache fetch keyed by the specific rollup IPs (requires
    // idx_cache_ip). Avoids the 10K cap that a bulk {is_private:false} query
    // imposes — our deployments routinely have >10K cached IPs.
    const ipSet = new Set();
    for (const r of srcRows) if (r._id) ipSet.add(r._id);
    for (const r of dstRows) if (r._id) ipSet.add(r._id);
    const ips = [...ipSet];

    let cacheMap = new Map();
    if (ips.length > 0) {
      const CHUNK = 500;
      for (let i = 0; i < ips.length; i += CHUNK) {
        const chunk = ips.slice(i, i + CHUNK);
        const cacheRes = await this._post(`/${this.cacheCollection}/query`, {
          filter: { ip: { '$in': chunk }, is_private: false, geo_lat: { '$gte': -90 } },  // NEW-C6
          limit: chunk.length,
        });
        for (const d of (cacheRes.data || [])) cacheMap.set(d.ip, d);
      }
    }

    const buildRows = (rows, direction) =>
      rows.filter(r => cacheMap.has(r._id)).map(r => {
        const c = cacheMap.get(r._id);
        return {
          ip: r._id,
          country: c.geo_country || null,
          city: c.geo_city || null,
          lat: c.geo_lat,
          lon: c.geo_lon,
          abuseScore: c.abuse_score ?? null,
          count: r.count || 0,
          blocked: r.blocked || 0,
          threats: r.threats || 0,
          lastSeen: null,
          direction,
        };
      });

    const all = [...buildRows(srcRows, 'src'), ...buildRows(dstRows, 'dst')];
    all.sort((a, b) => b.count - a.count);
    const final = all.slice(0, limit);

    logger.debug({  // H11
      since, limit,
      srcAgg: srcRows.length,
      dstAgg: dstRows.length,
      uniqueIps: ips.length,
      cacheHits: cacheMap.size,
      returned: final.length,
    }, 'WardSONDB getGeoEvents diagnostic');

    return final;
  }

  async getRecentGeoEvents(limit) {
    if (this._isCollectionEmpty()) return [];

    // First pass: collect recent event docs across partitions newest-first.
    // NEW-P5: drop the $exists filter (every event has at least one of
    // src/dst, JS-side filter handles the rare both-null case) so the
    // descending received_at sort can use IndexSorted on idx_received_at.
    // M3: include events with src OR dst — the previous filter required
    // src_ip and silently dropped dst-only events.
    const partitions = this._partitionsNewestFirst();
    const candidates = [];
    for (const partition of partitions) {
      if (candidates.length >= limit * 3) break;
      const remaining = limit * 3 - candidates.length;
      try {
        const r = await this._post(`/${partition}/query`, {
          sort: [{ 'received_at': 'desc' }],
          limit: Math.min(remaining, 500),
        });
        for (const doc of (r.data || [])) {
          if (doc.network?.src_ip || doc.network?.dst_ip) candidates.push(doc);
        }
      } catch (err) {
        logger.debug({ err: err.message, partition }, 'getRecentGeoEvents partition query failed');
      }
    }

    // Second pass: targeted cache lookup for the IPs we actually saw.
    const ipSet = new Set();
    for (const doc of candidates) {
      if (doc.network?.src_ip) ipSet.add(doc.network.src_ip);
      if (doc.network?.dst_ip) ipSet.add(doc.network.dst_ip);
    }
    const ips = [...ipSet];
    const cacheMap = new Map();
    if (ips.length > 0) {
      const CHUNK = 500;
      for (let i = 0; i < ips.length; i += CHUNK) {
        const chunk = ips.slice(i, i + CHUNK);
        const cacheRes = await this._post(`/${this.cacheCollection}/query`, {
          filter: { ip: { '$in': chunk }, is_private: false, geo_lat: { '$gte': -90 } },  // NEW-C6
          limit: chunk.length,
        });
        for (const d of (cacheRes.data || [])) cacheMap.set(d.ip, d);
      }
    }

    // Third pass: emit events with at least one enriched IP. NEW-C12 —
    // pass cacheMap to _documentToEvent so it does the full geo + hostname
    // overlay (the previous manual overlay below missed the hostname field).
    const events = [];
    for (const doc of candidates) {
      if (events.length >= limit) break;
      const srcIp = doc.network?.src_ip;
      const dstIp = doc.network?.dst_ip;
      const sGeo = srcIp ? cacheMap.get(srcIp) : null;
      const dGeo = dstIp ? cacheMap.get(dstIp) : null;
      if (!sGeo && !dGeo) continue;
      events.push(this._documentToEvent(doc, cacheMap));
    }
    return events;
  }

  // --- Enrichment Cache ---
  // Note: the plural getAllCachedEnrichments() (no callers anywhere in
  // the repo) was removed as part of L6 in Phase 7. Use the singular
  // getAllCachedEnrichment() below.

  async getCachedEnrichment(ip) {
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: { ip },
      limit: 1,
    });
    if (!result.data || result.data.length === 0) return null;
    const doc = result.data[0];

    const updatedAt = new Date(doc.updated_at || doc._updated_at).getTime();
    const maxAge = (this.config.abuseIpDbCacheHours || 24) * 60 * 60 * 1000;
    if (Date.now() - updatedAt > maxAge) return null;

    return {
      ip: doc.ip,
      geo_country: doc.geo_country || null,
      geo_city: doc.geo_city || null,
      geo_lat: doc.geo_lat ?? null,
      geo_lon: doc.geo_lon ?? null,
      abuse_score: doc.abuse_score ?? null,
      hostname: doc.hostname || null,
      is_private: doc.is_private ? 1 : 0,
      updated_at: doc.updated_at || doc._updated_at,
    };
  }

  async setCachedEnrichment(ip, data) {
    const existing = await this._post(`/${this.cacheCollection}/query`, {
      filter: { ip },
      fields: ['_id'],
      limit: 1,
    });

    const cacheDoc = {
      ip,
      geo_country: data.geo_country || null,
      geo_city: data.geo_city || null,
      geo_lat: data.geo_lat ?? null,
      geo_lon: data.geo_lon ?? null,
      abuse_score: data.abuse_score ?? null,
      hostname: data.hostname || null,
      is_private: data.is_private ? true : false,
      updated_at: new Date().toISOString(),
    };

    if (existing.data && existing.data.length > 0) {
      await this._put(`/${this.cacheCollection}/docs/${existing.data[0]._id}`, cacheDoc);
    } else {
      await this._post(`/${this.cacheCollection}/docs`, cacheDoc);
    }
  }

  async markPrivate(ip) {
    // NEW-C7: PATCH only `is_private: true` on the existing cache row,
    // or INSERT a minimal doc if absent. Avoids the destructive PUT path
    // (via setCachedEnrichment) that would null out previously-stored
    // geo_country / abuse_score / hostname for an IP later flagged private.
    try {
      const existing = await this._post(`/${this.cacheCollection}/query`, {
        filter: { ip },
        fields: ['_id'],
        limit: 1,
      });
      const doc = existing.data?.[0];
      const now = new Date().toISOString();
      if (doc?._id) {
        await this._patch(`/${this.cacheCollection}/docs/${encodeURIComponent(doc._id)}`, {
          is_private: true,
          updated_at: now,
        });
      } else {
        await this._post(`/${this.cacheCollection}/docs`, {
          ip, is_private: true, updated_at: now,
        });
      }
    } catch (err) {
      logger.debug({ err: err.message, ip }, 'WardSONDB markPrivate failed');
    }
  }

  async getAllCachedEnrichment() {
    const result = await this._post(`/${this.cacheCollection}/query`, {
      filter: {
        '$and': [
          { is_private: false },
          { '$or': [
            { geo_country: { '$exists': true } },
            { abuse_score: { '$exists': true } },
          ]},
        ],
      },
      limit: 10000,
    });
    return (result.data || []).map(d => ({
      ip: d.ip,
      geo_country: d.geo_country,
      geo_city: d.geo_city,
      geo_lat: d.geo_lat,
      geo_lon: d.geo_lon,
      abuse_score: d.abuse_score,
      hostname: d.hostname,
    }));
  }

  // --- Maintenance ---

  async runRetention(days) {
    const cutoffMs = Date.now() - days * 86400000;
    const cutoffDate = new Date(cutoffMs);
    const cutoffISO = cutoffDate.toISOString();
    const cutoffDay = cutoffISO.substring(0, 10);

    // Drop event partitions older than cutoffDay
    const toDrop = [...this._partitions].filter(name => {
      const day = name.substring(PARTITION_PREFIX.length);
      return day < cutoffDay;
    });

    let dropped = 0;
    for (const p of toDrop) {
      try {
        await this._delete(`/${p}`);
        this._partitions.delete(p);
        dropped++;
      } catch (err) {
        logger.warn({ err: err.message, partition: p }, 'Failed to drop partition during retention');
      }
    }

    // Clean rollup entries older than cutoff (small collections, cheap)
    const rollupCols = [this.rollup5m, this.rollupIpHourly, this.rollupPortHourly, this.rollupSigHourly, this.rollupClientHourly];
    for (const col of rollupCols) {
      try {
        await this._post(`/${col}/docs/_delete_by_query`, {
          filter: { bucket: { '$lt': cutoffISO } },
        });
      } catch (err) {
        logger.debug({ err: err.message, col }, 'Rollup retention cleanup failed');
      }
    }

    if (dropped > 0) {
      logger.info({ dropped, cutoffDay, rollupsCleaned: rollupCols.length }, 'WardSONDB retention cleanup');
    }
    return { deleted: dropped };
  }

  async resetData() {
    // Stop flush so no concurrent writes
    if (this._flushIntervalHandle) {
      clearInterval(this._flushIntervalHandle);
      this._flushIntervalHandle = null;
    }

    // Discover all event partitions (union with in-memory cache)
    const existing = new Set(this._partitions);
    try {
      const cols = await this._get('/_collections');
      for (const c of (cols.data || [])) {
        const name = typeof c === 'string' ? c : c?.name;
        if (name && PARTITION_NAME_RE.test(name)) existing.add(name);
      }
    } catch {}

    // Drop all event partitions
    for (const p of existing) {
      try { await this._delete(`/${p}`); } catch {}
    }
    // Drop rollup collections
    for (const c of [this.rollup5m, this.rollupIpHourly, this.rollupPortHourly, this.rollupSigHourly, this.rollupClientHourly]) {
      try { await this._delete(`/${c}`); } catch {}
    }
    // Drop enrichment cache
    try { await this._delete(`/${this.cacheCollection}`); } catch {}

    // Reset in-memory state
    this._partitions.clear();
    this._rollupBuffers = this._newBuffers();
    this._cacheMap = null;
    this._cacheMapTs = 0;
    this._cachedDocCount = 0;

    // Recreate today's partition + indexes
    const today = this._partitionName(new Date());
    await this._ensurePartition(today);

    // Recreate rollup collections + indexes
    for (const col of [this.rollup5m, this.rollupIpHourly, this.rollupPortHourly, this.rollupSigHourly, this.rollupClientHourly]) {
      await this._ensureCollection(col);
    }
    // Recreate enrichment cache BEFORE its indexes
    await this._ensureCollection(this.cacheCollection);

    for (const idx of [...this._getRollupIndexSpecs(), ...this._getCacheIndexSpecs()]) {
      try {
        const body = { name: idx.name };
        if (idx.fields) body.fields = idx.fields;
        else body.field = idx.field;
        await this._post(`/${idx.col}/indexes`, body);
      } catch (err) {
        if (!err.message?.includes('INDEX_EXISTS')) {
          logger.debug({ err: err.message, col: idx.col, idx: idx.name }, 'Rollup/cache index creation warn during reset');
        }
      }
    }

    // Today's partition is empty — indexes are instant — ingestion can resume
    this.indexesReady = Promise.resolve();

    // Restart flush
    this._startFlushInterval();
  }

  // --- Backfill ---

  /**
   * One-time rollup backfill on startup if rollup collections are empty but
   * event partitions hold data (e.g., upgrading from a pre-rollup version, or
   * recovering from a wipe of the rollup collections only).
   * Idempotency: read-then-increment double-counts on re-run, so we hard-skip
   * if rollups already contain anything.
   */
  async _runStartupBackfill() {
    if (this._backfillStarted || this._shuttingDown) return;
    this._backfillStarted = true;

    // Probe rollups for existing data
    let rollupCount = 0;
    try {
      const probe = await this._post(`/${this.rollup5m}/query`, { count_only: true, limit: 1 });
      // NEW-C9: prefer data.count (canonical) over meta.total_count
      // (diagnostic). Use ?? not || so a legitimate 0 isn't replaced.
      rollupCount = probe.data?.count ?? probe.meta?.total_count ?? 0;
    } catch {}

    if (rollupCount > 0) {
      logger.info({ rollupCount }, 'Skipping rollup backfill — rollups already populated');
      return;
    }
    if (this._partitions.size === 0) {
      logger.info('Skipping rollup backfill — no event partitions');
      return;
    }

    logger.info({ partitions: this._partitions.size }, 'Starting rollup backfill');
    const startedAt = Date.now();
    const CHUNK = 1000;

    for (const partition of [...this._partitions].sort()) {
      let offset = 0;
      let chunkIdx = 0;
      while (!this._shuttingDown) {
        const t0 = Date.now();
        let docs;
        try {
          const r = await this._post(`/${partition}/query`, {
            sort: [{ 'received_at': 'asc' }],
            limit: CHUNK,
            offset,
          });
          docs = r.data || [];
        } catch (err) {
          logger.warn({ err: err.message, partition, offset }, 'Backfill chunk fetch failed');
          break;
        }
        if (docs.length === 0) break;

        const events = docs.map(d => this._documentToEvent(d));
        this._accumulateRollups(events);
        await this._flushRollups();

        offset += docs.length;
        chunkIdx++;
        logger.info({ partition, chunk: chunkIdx, docs: docs.length, ms: Date.now() - t0 }, 'Rollup backfill chunk');
        if (docs.length < CHUNK) break;
      }
    }
    logger.info({ totalMs: Date.now() - startedAt }, 'Rollup backfill complete');
  }

  // --- Settings ---
  // Settings stay in SQLite (needed to select the backend on boot).

  async getSetting() { throw new Error('Settings are managed by SQLite'); }
  async setSetting() { throw new Error('Settings are managed by SQLite'); }
  async getAllSettings() { throw new Error('Settings are managed by SQLite'); }
}

module.exports = WardsonDbBackend;
