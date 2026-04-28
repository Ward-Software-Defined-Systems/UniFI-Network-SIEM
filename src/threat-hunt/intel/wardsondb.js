/**
 * Threat Hunt intel gathering against the WardSONDB backend.
 *
 * Fan-out aggregation across daily partitions with bounded concurrency,
 * merged client-side. Heavy reads run in parallel via Promise.all so
 * the wall-clock cost is the slowest single aggregation, not their sum.
 */
const logger = require('../../utils/logger');

const HUNT_FANOUT_CONCURRENCY = 8;

async function fanOutAggregate(backend, partitions, pipeline) {
  if (!partitions.length) return [];
  const merged = new Map();
  let i = 0;
  const post = (path, body) => backend._request('POST', path, body, 3);
  const workers = Array.from({ length: HUNT_FANOUT_CONCURRENCY }, async () => {
    while (i < partitions.length) {
      const p = partitions[i++];
      try {
        const result = await post(`/${p}/aggregate`, { pipeline });
        for (const row of (result.data || [])) {
          const key = JSON.stringify(row._id);
          const existing = merged.get(key);
          if (existing) existing.count += row.count || 0;
          else merged.set(key, { _id: row._id, count: row.count || 0 });
        }
      } catch {}
    }
  });
  await Promise.all(workers);
  return Array.from(merged.values()).sort((a, b) => b.count - a.count);
}

async function fanOutCount(backend, partitions, filter) {
  if (!partitions.length) return 0;
  let total = 0;
  let i = 0;
  const post = (path, body) => backend._request('POST', path, body, 3);
  const workers = Array.from({ length: HUNT_FANOUT_CONCURRENCY }, async () => {
    while (i < partitions.length) {
      const p = partitions[i++];
      try {
        const result = await post(`/${p}/query`, { filter, count_only: true });
        total += result.data?.count ?? result.meta?.total_count ?? 0;
      } catch {}
    }
  });
  await Promise.all(workers);
  return total;
}

async function gatherHuntIntel(backend, target, since) {
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

  const trimRank = (rows, lim) => rows.slice(0, lim).map((r) => ({ _id: r._id, count: r.count }));

  const byAction = trimRank(byActionRows, 50).map((r) => ({ action: r._id, count: r.count }));
  const byType = trimRank(byTypeRows, 50).map((r) => ({ event_type: r._id, count: r.count }));
  const topPorts = trimRank(topPortsRows, 20).map((r) => ({ dst_port: r._id?.port, protocol: r._id?.protocol, count: r.count }));
  const topSrcPorts = trimRank(topSrcPortsRows, 10).map((r) => ({ src_port: r._id?.port, protocol: r._id?.protocol, count: r.count }));
  const signatures = trimRank(signaturesRows, 10).map((r) => ({
    ids_signature: r._id?.sig, ids_classification: r._id?.cls, count: r.count,
  }));
  const topDestinations = trimRank(topDestinationsRows, 20).map((r) => ({ ip: r._id, count: r.count }));
  const topSources = trimRank(topSourcesRows, 20).map((r) => ({ ip: r._id, count: r.count }));

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
      .filter((r) => r.ip !== target)
      .sort((a, b) => (b.abuse_score || 0) - (a.abuse_score || 0))
      .slice(0, 10)
      .map((r) => ({ ip: r.ip, abuse_score: r.abuse_score, geo_country: r.geo_country, hostname: r.hostname }));
  } catch {}

  return { cached, totalEvents, byAction, byType, topPorts, topSrcPorts, timeline, firstSeen, lastSeen, relatedIPs, signatures, targetsHit, topDestinations, topSources };
}

module.exports = { gatherHuntIntel };
