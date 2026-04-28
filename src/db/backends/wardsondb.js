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
 *   5 seconds. Phase 10 (M10) replaced the read-then-increment pattern with
 *   append-only deltas via `/{col}/docs/_bulk`: each flush writes a fresh
 *   batch of {bucket, ..., count, delta:true} documents with deterministic
 *   `_id = ${bucket}|${k1}|${k2}|${flushId}`. Queries already use
 *   `$group + $sum` so they sum correctly across delta docs without code
 *   changes. The append-only model removes the lost-update race that
 *   PATCH had under concurrent flushes (M11).
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
    // M10: append-only delta `_id` suffix counter. Combined with Date.now()
    // it stays unique across same-millisecond flushes (rare but possible
    // under heavy load) and tags each flush idempotently — duplicate _id
    // returns 409 per-doc on a retry, so the same buffer can be re-flushed
    // without double-counting.
    this._flushCounter = 0;
    // NEW-P3: rollup compaction state.
    this._compacting = false;
    this._compactionIntervalHandle = null;

    // Cached doc count across event partitions, used for empty-DB short-circuit
    this._cachedDocCount = null;
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

  // --- Rollup flush (append-only deltas, M10) ---

  /**
   * Build the deterministic `_id` for a delta document.
   *
   * Shape: `${bucket}|${naturalKeys}|${flushId}`. The flushId suffix
   * makes each flush's deltas unique while letting a retry of the SAME
   * flush land on duplicate `_id`s (409 per-doc → silently skipped).
   * The natural-key prefix is what compaction filters on.
   */
  _baseKeyFiveMin(d) { return `${d.bucket}|${d.event_type}|${d.action}`; }
  _baseKeyIpHourly(d) { return `${d.bucket}|${d.ip}|${d.direction}`; }
  _baseKeyPortHourly(d) { return `${d.bucket}|${d.port}|${d.protocol}`; }
  _baseKeySigHourly(d) { return `${d.bucket}|${d.signature}|${d.classification}`; }
  _baseKeyClientHourly(d) { return `${d.bucket}|${d.mac}`; }

  /**
   * Per-collection bulk insert. Returns true on success, false on
   * transactional failure. WardSONDB's `_bulk` is atomic per call — if
   * the transaction fails, none of the docs are committed (per
   * API.md:512), so a re-merge of the drain buffer on failure is safe
   * and won't double-count.
   */
  async _bulkInsertDeltas(collection, docs) {
    if (docs.length === 0) return true;
    try {
      const result = await this._post(`/${collection}/docs/_bulk`, { documents: docs });
      const inserted = result.data?.inserted ?? 0;
      const errors = result.data?.errors || [];
      if (errors.length > 0) {
        // Per-doc errors. Duplicate _id is the expected mode on a retry
        // of the same flush — log at debug so a real failure (e.g.,
        // schema validation) still gets surfaced via the inserted-vs-
        // submitted gap below.
        logger.debug(
          { col: collection, errorCount: errors.length, sample: errors.slice(0, 3) },
          'Rollup bulk delta had per-doc errors',
        );
      }
      // Successful retry: inserted may be 0 if every doc was a duplicate.
      // Successful first attempt: inserted should equal docs.length.
      // Anything in between with non-duplicate errors is a problem worth
      // logging, but we still consider the call successful — partial
      // success means the duplicates already landed previously.
      const expected = docs.length;
      if (inserted < expected && errors.length === 0) {
        logger.warn({ col: collection, inserted, submitted: expected }, 'Rollup bulk under-inserted with no errors reported');
      }
      return true;
    } catch (err) {
      logger.warn(
        { err: err.message, col: collection, docs: docs.length },
        'Rollup bulk delta insert failed',
      );
      return false;
    }
  }

  /**
   * Re-merge a partial drain back into the live buffer. Called when
   * one or more per-collection bulk inserts failed — only the failed
   * Maps are re-merged, so collections that succeeded don't get
   * double-counted on the next flush.
   */
  _mergeBuffersBack(drain, failedMaps) {
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
    if (failedMaps.has('fiveMin')) mergeMap(drain.fiveMin, live.fiveMin, ['count']);
    if (failedMaps.has('ipHourly')) mergeMap(drain.ipHourly, live.ipHourly, ['event_count', 'blocked_count', 'threat_count']);
    if (failedMaps.has('portHourly')) mergeMap(drain.portHourly, live.portHourly, ['count']);
    if (failedMaps.has('sigHourly')) mergeMap(drain.sigHourly, live.sigHourly, ['count']);
    if (failedMaps.has('clientHourly')) mergeMap(drain.clientHourly, live.clientHourly, ['event_count', 'wifi_count', 'dhcp_count', 'firewall_count']);
  }

  async _flushRollups() {
    if (this._flushing) return;
    this._flushing = true;
    const t0 = Date.now();

    try {
      // Atomic swap so accumulation continues into a fresh buffer while
      // the prior buffer drains.
      const drain = this._rollupBuffers;
      this._rollupBuffers = this._newBuffers();

      // Stable per-flush identifier. Combined with the natural-key prefix
      // it produces a deterministic `_id` for each delta — meaning a
      // retry of the same flush hits 409 per-doc and skips, never
      // double-counts.
      const flushId = `${Date.now()}-${this._flushCounter++}`;

      // Build per-collection delta arrays. Each delta carries `delta:true`
      // so compaction (Phase 10B / NEW-P3) can target them with
      // `_delete_by_query` without touching canonical docs.
      const buildDeltas = (map, baseKeyFn) => {
        const out = [];
        for (const d of map.values()) {
          out.push({ _id: `${baseKeyFn(d)}|${flushId}`, ...d, delta: true });
        }
        return out;
      };

      const tasks = [
        { key: 'fiveMin', col: this.rollup5m, docs: buildDeltas(drain.fiveMin, (d) => this._baseKeyFiveMin(d)) },
        { key: 'ipHourly', col: this.rollupIpHourly, docs: buildDeltas(drain.ipHourly, (d) => this._baseKeyIpHourly(d)) },
        { key: 'portHourly', col: this.rollupPortHourly, docs: buildDeltas(drain.portHourly, (d) => this._baseKeyPortHourly(d)) },
        { key: 'sigHourly', col: this.rollupSigHourly, docs: buildDeltas(drain.sigHourly, (d) => this._baseKeySigHourly(d)) },
        { key: 'clientHourly', col: this.rollupClientHourly, docs: buildDeltas(drain.clientHourly, (d) => this._baseKeyClientHourly(d)) },
      ];

      const totalDocs = tasks.reduce((n, t) => n + t.docs.length, 0);
      if (totalDocs === 0) return;

      // Bulk insert per collection in parallel (each call is its own
      // atomic transaction at the WardSONDB layer). flushConcurrency
      // caps the parallelism; with 5 collections and a default of 4 the
      // worker pool absorbs all five with at most one slot of queueing.
      const failedMaps = new Set();
      let i = 0;
      const workers = Array.from({ length: Math.min(this.flushConcurrency, tasks.length) }, async () => {
        while (i < tasks.length) {
          const my = tasks[i++];
          const ok = await this._bulkInsertDeltas(my.col, my.docs);
          if (!ok) failedMaps.add(my.key);
        }
      });
      await Promise.all(workers);

      if (failedMaps.size > 0) {
        logger.warn({ failed: [...failedMaps] }, 'Rollup flush partial failure — re-merging affected buffers for retry');
        this._mergeBuffersBack(drain, failedMaps);
      }

      logger.debug({
        '5m': drain.fiveMin.size,
        ip: drain.ipHourly.size,
        port: drain.portHourly.size,
        sig: drain.sigHourly.size,
        client: drain.clientHourly.size,
        ms: Date.now() - t0,
        flushId,
        failed: failedMaps.size,
      }, 'Rollup flush');
    } finally {
      this._flushing = false;
    }
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

  // --- Rollup compaction (NEW-P3) ---

  /**
   * Per-collection compaction definitions. Each entry says how to
   * group the deltas by their natural key, the count fields to sum,
   * and how to assemble the canonical doc + its `_id` from a $group row.
   *
   * Canonical docs share the same shape as deltas — including `delta:
   * false` so queries can keep using `$group + $sum` without filter
   * changes while compaction targets `delta: true` for deletion.
   */
  _compactionSpecs() {
    return [
      {
        col: this.rollup5m,
        keyFields: { event_type: 'event_type', action: 'action' },
        sumFields: ['count'],
        canonicalIdFor: (row) => `${row.bucket}|${row.event_type}|${row.action}|c`,
      },
      {
        col: this.rollupIpHourly,
        keyFields: { ip: 'ip', direction: 'direction' },
        sumFields: ['event_count', 'blocked_count', 'threat_count'],
        canonicalIdFor: (row) => `${row.bucket}|${row.ip}|${row.direction}|c`,
      },
      {
        col: this.rollupPortHourly,
        keyFields: { port: 'port', protocol: 'protocol' },
        sumFields: ['count'],
        canonicalIdFor: (row) => `${row.bucket}|${row.port}|${row.protocol}|c`,
      },
      {
        col: this.rollupSigHourly,
        keyFields: { signature: 'signature', classification: 'classification' },
        sumFields: ['count'],
        canonicalIdFor: (row) => `${row.bucket}|${row.signature}|${row.classification}|c`,
      },
      {
        col: this.rollupClientHourly,
        keyFields: { mac: 'mac' },
        sumFields: ['event_count', 'wifi_count', 'dhcp_count', 'firewall_count'],
        canonicalIdFor: (row) => `${row.bucket}|${row.mac}|c`,
      },
    ];
  }

  /**
   * Compact buckets that closed at least `minAgeHours` ago. The window
   * is intentionally generous so we never collide with an in-flight
   * flush for the same bucket.
   *
   * Order is: aggregate → upsert canonical → delete deltas. A crash
   * between the upsert and the delete leaves the canonical correct AND
   * the deltas present — queries see the same total counted twice for
   * a brief window. The next compaction run is idempotent because
   * canonical docs ALSO carry their `bucket` field, and we sum
   * everything in the bucket (delta + existing canonical) before doing
   * a full PUT replacement of the canonical.
   */
  async _compactRollups(minAgeHours = 1) {
    if (this._compacting) return;
    this._compacting = true;
    const t0 = Date.now();
    let totalCanonicalsWritten = 0;
    let totalDeltasDeleted = 0;
    try {
      const cutoff = new Date(Date.now() - minAgeHours * 60 * 60 * 1000).toISOString();
      for (const spec of this._compactionSpecs()) {
        const counts = await this._compactCollection(spec, cutoff);
        totalCanonicalsWritten += counts.canonicals;
        totalDeltasDeleted += counts.deltas;
      }
      logger.info({
        canonicals: totalCanonicalsWritten,
        deltasDeleted: totalDeltasDeleted,
        ms: Date.now() - t0,
        cutoff,
      }, 'Rollup compaction complete');
    } catch (err) {
      logger.warn({ err: err.message }, 'Rollup compaction failed');
    } finally {
      this._compacting = false;
    }
  }

  async _compactCollection(spec, cutoff) {
    const { col, keyFields, sumFields, canonicalIdFor } = spec;

    // Distinct old buckets that still contain deltas. If only canonical
    // docs are present, there's nothing to compact for that bucket.
    let buckets;
    try {
      const r = await this._post(`/${col}/distinct`, {
        field: 'bucket',
        filter: { bucket: { '$lt': cutoff }, delta: true },
        limit: 5000,
      });
      buckets = r.data?.values || [];
    } catch (err) {
      logger.warn({ err: err.message, col }, 'Compaction distinct lookup failed');
      return { canonicals: 0, deltas: 0 };
    }
    if (buckets.length === 0) return { canonicals: 0, deltas: 0 };

    let canonicals = 0;
    let deltas = 0;

    for (const bucket of buckets) {
      try {
        // Aggregate ALL docs in the bucket (delta + any existing canonical)
        // grouped by natural key. Including canonical in the sum is what
        // makes re-runs idempotent: the canonical's count is folded into
        // the new canonical, then deltas are deleted, then on the next
        // run there are no deltas so canonicals are unchanged.
        const groupSpec = { _id: keyFields };
        for (const f of sumFields) groupSpec[f] = { '$sum': f };
        const agg = await this._post(`/${col}/aggregate`, {
          pipeline: [
            { '$match': { bucket } },
            { '$group': groupSpec },
          ],
        });
        const rows = agg.data || [];
        if (rows.length === 0) continue;

        // Build canonical docs and PUT them (replace if exists, insert if not).
        // Per WardSONDB API.md: PUT replaces, returns 404 if missing. We
        // try POST first with a deterministic _id; on 409 we fall back to
        // PUT for the in-place replacement.
        for (const row of rows) {
          const doc = { bucket, ...row._id, delta: false };
          for (const f of sumFields) doc[f] = row[f] || 0;
          const id = canonicalIdFor(doc);
          const path = `/${col}/docs/${encodeURIComponent(id)}`;

          // PUT replaces atomically when the doc exists; on 404 we POST
          // to create. Either way the canonical reflects the freshly
          // aggregated total.
          const replaced = await this._put(path, doc);
          if (replaced._notFound) {
            const created = await this._post(`/${col}/docs`, { _id: id, ...doc });
            if (created._conflict) {
              // Race: another compactor created it concurrently. Retry the PUT.
              await this._put(path, doc).catch(() => {});
            }
          }
          canonicals++;
        }

        // Delete deltas for this bucket. Canonical docs carry `delta: false`
        // so they're left intact.
        const del = await this._post(`/${col}/docs/_delete_by_query`, {
          filter: { bucket, delta: true },
        });
        deltas += del.data?.deleted || 0;
      } catch (err) {
        logger.warn({ err: err.message, col, bucket }, 'Per-bucket compaction failed');
      }
    }

    return { canonicals, deltas };
  }

  _startCompactionInterval() {
    if (this._compactionIntervalHandle) clearInterval(this._compactionIntervalHandle);
    // Run compaction every 30 minutes. The cutoff window (default 1h)
    // ensures we never touch buckets that could still receive flush
    // writes from a delayed event arrival.
    this._compactionIntervalHandle = setInterval(() => {
      if (this._shuttingDown) return;
      this._compactRollups().catch((err) =>
        logger.warn({ err: err.message }, 'Rollup compaction cycle error'));
    }, 30 * 60 * 1000);
    this._compactionIntervalHandle.unref?.();
  }

  // --- Lifecycle ---

  _getRequiredEventIndexes() {
    // NEW-C4: idx_event_type (single-field) was removed because both
    // idx_type_time (event_type, received_at) and idx_type_action
    // (event_type, network.action) serve as event_type prefixes for
    // single-key lookups, AND the bitmap accelerator covers
    // event_type entirely (low cardinality, ~10 values). Existing
    // partitions still carry the old index — it's harmless and ages
    // out as partitions are dropped via retention.
    return [
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

  /**
   * NEW-P4: install or update a TTL policy on each rollup collection.
   * Idempotent — PUT replaces any existing policy. Errors are logged
   * but non-fatal (fall back to app-side _delete_by_query in
   * runRetention()).
   */
  async _setRollupTTLs() {
    const days = this.config.retentionDays;
    if (!days || days <= 0) {
      logger.debug('No retention configured; skipping rollup TTL setup');
      return;
    }
    const cols = [
      this.rollup5m,
      this.rollupIpHourly,
      this.rollupPortHourly,
      this.rollupSigHourly,
      this.rollupClientHourly,
    ];
    for (const col of cols) {
      try {
        await this._put(`/${col}/ttl`, {
          retention_days: days,
          // Bucket timestamps are produced by align5m()/align1h() in
          // src/db/rollups.js. They're ISO 8601 strings tied to the
          // time window the doc covers — stable across delta + canonical
          // forms — which is what we want for retention.
          field: 'bucket',
        });
        logger.info({ col, days }, 'Rollup TTL policy active');
      } catch (err) {
        logger.warn({ err: err.message, col }, 'Failed to set rollup TTL — will fall back to runRetention _delete_by_query');
      }
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

    // NEW-P4: server-side TTL on each rollup collection. WardSONDB runs
    // a TTL cleanup task on a 60s cadence (--ttl-interval default), so
    // expired buckets get purged without an app-side _delete_by_query
    // roundtrip on every retention cycle. The field is `bucket` (the
    // 5m/1h-aligned ISO timestamp from src/db/rollups.js), not
    // _created_at — because after compaction, canonical docs get a
    // fresh _created_at while their bucket timestamp stays anchored to
    // the actual time window they cover.
    await this._setRollupTTLs();

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
    // NEW-P3: hourly compaction folds older delta docs into a single
    // canonical doc per (bucket, key) and prunes the deltas. Without
    // this the rollup collections grow linearly with flushes.
    this._startCompactionInterval();

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
    if (this._compactionIntervalHandle) {
      clearInterval(this._compactionIntervalHandle);
      this._compactionIntervalHandle = null;
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

  /**
   * Decode a base64-encoded keyset cursor → { received_at, id } | null.
   * Malformed cursors silently fall back to a fresh first page rather
   * than 400-erroring the whole query.
   */
  _decodeCursor(raw) {
    if (!raw || typeof raw !== 'string') return null;
    try {
      const json = Buffer.from(raw, 'base64').toString('utf8');
      const obj = JSON.parse(json);
      if (typeof obj?.received_at === 'string' && typeof obj?.id === 'string') {
        return { received_at: obj.received_at, id: obj.id };
      }
    } catch {}
    return null;
  }

  _encodeCursor(receivedAt, id) {
    return Buffer.from(JSON.stringify({ received_at: receivedAt, id }), 'utf8').toString('base64');
  }

  async queryEvents(filters = {}) {
    const limit = Math.min(parseInt(filters.limit || '50', 10), 500);
    const cursor = this._decodeCursor(filters.cursor);
    const queryFilter = this._buildFilter(filters);

    // M4: keyset pagination. With a `(received_at, _id)` cursor we can
    // skip directly to the next page without paying the offset-scan
    // cost (which grows with the number of events ahead of you in the
    // partition). _id here is UUIDv7 — its time-prefix means sorting by
    // _id within a same-millisecond received_at bucket is also
    // monotonic, so the keyset stays well-defined.
    //
    // Fall-back: if no cursor is provided, the old `offset` parameter
    // still works for backwards compatibility with callers that haven't
    // adopted cursors yet (e.g., direct API consumers).
    let offset = cursor ? 0 : parseInt(filters.offset || '0', 10);
    let cursorFilter = queryFilter;
    if (cursor) {
      const cursorClause = {
        '$or': [
          { received_at: { '$lt': cursor.received_at } },
          {
            '$and': [
              { received_at: cursor.received_at },
              { _id: { '$lt': cursor.id } },
            ],
          },
        ],
      };
      cursorFilter = queryFilter
        ? { '$and': [queryFilter, cursorClause] }
        : cursorClause;
    }

    // Fetch limit + 1 so we can detect hasMore without a second query.
    const fetchLimit = limit + 1;

    // M9: collect raw docs first, then look up cache for the IPs we
    // actually saw. Avoids the previous bulk-load that pulled up to
    // 100K cache rows for a query returning at most 500 events.
    const queryPartition = async (partition, remaining) => {
      const result = await this._post(`/${partition}/query`, {
        filter: cursorFilter,
        sort: [{ received_at: 'desc' }, { _id: 'desc' }],
        limit: remaining,
        offset,
      });
      const docs = result.data || [];
      if (offset > 0) offset = Math.max(0, offset - docs.length);
      return docs;
    };

    // When a cursor is set, scope partitions to those overlapping
    // [start, cursor.received_at] — we never need to look at partitions
    // newer than the cursor.
    const untilForFanOut = cursor ? cursor.received_at : filters.until;
    const rawDocs = await this._queryAcrossPartitions(queryPartition, filters.since, untilForFanOut, fetchLimit);

    const hasMore = rawDocs.length > limit;
    const docs = hasMore ? rawDocs.slice(0, limit) : rawDocs;
    const last = docs[docs.length - 1];
    const nextCursor = hasMore && last
      ? this._encodeCursor(last.received_at, last._id)
      : null;

    const ipSet = new Set();
    for (const doc of docs) {
      if (doc.network?.src_ip) ipSet.add(doc.network.src_ip);
      if (doc.network?.dst_ip) ipSet.add(doc.network.dst_ip);
    }
    const cacheMap = await this._lookupCacheForIps(ipSet);

    const events = docs.map((d) => this._documentToEvent(d, cacheMap));
    return { events, hasMore, nextCursor };
  }

  async getEventById(id) {
    // M17: validate UUIDv7 shape up front. A malformed id used to scan
    // every partition sequentially — at 30+ daily partitions × 30s
    // server-side query timeout, a single bad id could hang the request
    // for many minutes.
    const UUIDV7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (typeof id !== 'string' || !UUIDV7_RE.test(id)) return null;

    const partition = this._partitionFromId(id);
    let doc = null;

    if (partition && this._partitions.has(partition)) {
      const result = await this._get(`/${partition}/docs/${encodeURIComponent(id)}`);
      if (!result._notFound) doc = result.data;
    }

    if (!doc) {
      // M17: bounded fallback to the 7 most-recent partitions only. A
      // valid UUIDv7 whose partition isn't in this._partitions is a rare
      // race (server restart between _partitions refresh and the GET);
      // unbounded scanning was the worst-case hang path.
      for (const p of this._partitionsNewestFirst().slice(0, 7)) {
        try {
          const r = await this._get(`/${p}/docs/${encodeURIComponent(id)}`);
          if (!r._notFound) { doc = r.data; break; }
        } catch {}
      }
    }
    if (!doc) return null;

    // M9: targeted cache lookup for just this doc's IPs (≤2).
    const ips = [];
    if (doc.network?.src_ip) ips.push(doc.network.src_ip);
    if (doc.network?.dst_ip) ips.push(doc.network.dst_ip);
    const cacheMap = await this._lookupCacheForIps(ips);

    return this._documentToEvent(doc, cacheMap);
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

  /**
   * M9: targeted cache lookup for a specific set of IPs. Replaces the
   * previous bulk _getCacheMap which loaded up to 100K rows on every 30s
   * expiration (a no-op above the API's 10K hard limit, and wasteful
   * even below it). Chunks the $in filter at 500 IPs to fit within
   * server-side query payload caps. Empty input returns an empty Map
   * immediately — no network round-trip.
   */
  async _lookupCacheForIps(ips) {
    const map = new Map();
    if (!ips) return map;
    const unique = ips instanceof Set ? [...ips] : [...new Set(ips)];
    if (unique.length === 0) return map;
    const CHUNK = 500;
    for (let i = 0; i < unique.length; i += CHUNK) {
      const chunk = unique.slice(i, i + CHUNK);
      try {
        const res = await this._post(`/${this.cacheCollection}/query`, {
          filter: { ip: { '$in': chunk } },
          limit: chunk.length,
        });
        for (const d of (res.data || [])) map.set(d.ip, d);
      } catch (err) {
        logger.debug({ err: err.message, chunk: chunk.length }, '_lookupCacheForIps chunk failed');
      }
    }
    return map;
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

    // M9: targeted lookup for just the top-N rollup IPs.
    const aggRows = result.data || [];
    const ipSet = new Set(aggRows.map(r => r._id).filter(Boolean));
    const cacheMap = await this._lookupCacheForIps(ipSet);
    let rows = aggRows.map(r => {
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

    // M9: targeted lookup for just the top-N rollup IPs.
    const aggRows = result.data || [];
    const ipSet = new Set(aggRows.map(r => r._id).filter(Boolean));
    const cacheMap = await this._lookupCacheForIps(ipSet);
    let rows = aggRows.map(r => {
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
    // NEW-P2: /distinct over the indexed `ip` field is index-only when no
    // filter touches a non-indexed column; even with the bucket filter
    // it's cheaper than $group{_id:ip} on a busy rollup collection.
    // M14: surface truncation so the UI can warn that the period summary
    // undercounts. The 10K cap is the WardSONDB API hard limit per
    // API.md:1657 — we can't get more even by raising it.
    const PERIOD_IPS_CAP = 10000;
    const periodIpsRes = await this._post(`/${this.rollupIpHourly}/distinct`, {
      field: 'ip',
      filter: { bucket: { '$gte': since } },
      limit: PERIOD_IPS_CAP,
    }).catch(() => ({ data: { values: [], truncated: false } }));
    const periodIps = (periodIpsRes.data?.values || []).filter(Boolean);
    const periodIpsTruncated = periodIpsRes.data?.truncated === true
      || periodIps.length >= PERIOD_IPS_CAP;
    if (periodIpsTruncated) {
      logger.warn({
        cap: PERIOD_IPS_CAP, periodIps: periodIps.length, since,
      }, 'WardSONDB getThreatIntel periodIps truncated — period summary may undercount');
    }

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
      periodSummary = {
        enriched, flagged, highThreat: highThreatCount, countries: countriesSet.size,
        // M14: propagate truncation flag so the UI can render a banner
        // when the period summary undercounts (busy 30d windows with
        // >10K unique IPs).
        truncated: periodIpsTruncated,
      };
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

  // --- Threat Hunt ---

  async gatherHuntIntel(target, since) {
    const { gatherHuntIntel } = require('../../threat-hunt/intel/wardsondb');
    return gatherHuntIntel(this, target, since);
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
    // M5: read-then-write merge. Pull the full existing row (not just
    // `_id`) so we can preserve fields not present in the new `data`.
    // Matches OpenSearch's behavior and keeps SQLite/WardSONDB/
    // OpenSearch caches in lockstep — no more "marking an IP private
    // wipes its geo_country" footgun.
    const existing = await this._post(`/${this.cacheCollection}/query`, {
      filter: { ip },
      limit: 1,
    });
    const prev = existing.data?.[0] || {};

    const cacheDoc = {
      ip,
      geo_country: data.geo_country ?? prev.geo_country ?? null,
      geo_city: data.geo_city ?? prev.geo_city ?? null,
      geo_lat: data.geo_lat ?? prev.geo_lat ?? null,
      geo_lon: data.geo_lon ?? prev.geo_lon ?? null,
      abuse_score: data.abuse_score ?? prev.abuse_score ?? null,
      hostname: data.hostname ?? prev.hostname ?? null,
      is_private: (data.is_private ?? prev.is_private) ? true : false,
      updated_at: new Date().toISOString(),
    };

    if (prev._id) {
      await this._put(`/${this.cacheCollection}/docs/${encodeURIComponent(prev._id)}`, cacheDoc);
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

    // NEW-P4: rollups are pruned by WardSONDB's server-side TTL policy
    // (set in _setRollupTTLs() during initialize()). This _delete_by_query
    // sweep stays as a safety net — it's a no-op once TTL has caught
    // up, and indexed/cheap when it does match anything.
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
