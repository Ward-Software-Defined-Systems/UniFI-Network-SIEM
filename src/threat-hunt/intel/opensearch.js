/**
 * Threat Hunt intel gathering against the OpenSearch backend.
 *
 * Native aggregations (terms / cardinality / date_histogram) replace
 * the partition fan-out used for WardSONDB.
 */
const logger = require('../../utils/logger');

async function gatherHuntIntel(backend, target, since) {
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
      } }).catch(() => ({ body: { hits: { total: { value: 0 } }, aggregations: {} } })),

      // Top destination ports (target as source)
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { src_ip: target } }, { exists: { field: 'dst_port' } }]) } },
        aggs: { top_ports: { terms: { field: 'dst_port', size: 20 }, aggs: { proto: { terms: { field: 'protocol', size: 1 } } } } },
      } }).catch(() => ({ body: { aggregations: {} } })),

      // Top source ports (target as destination)
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { dst_ip: target } }, { exists: { field: 'src_port' } }]) } },
        aggs: { top_ports: { terms: { field: 'src_port', size: 10 }, aggs: { proto: { terms: { field: 'protocol', size: 1 } } } } },
      } }).catch(() => ({ body: { aggregations: {} } })),

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
      } }).catch(() => ({ body: { aggregations: {} } })),

      // Unique targets hit (cardinality)
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { src_ip: target } }]) } },
        aggs: { unique_dst: { cardinality: { field: 'dst_ip' } } },
      } }).catch(() => ({ body: { aggregations: {} } })),

      // Top destination IPs
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { src_ip: target } }, { exists: { field: 'dst_ip' } }]) } },
        aggs: { top: { terms: { field: 'dst_ip', size: 20 } } },
      } }).catch(() => ({ body: { aggregations: {} } })),

      // Top source IPs
      client.search({ index: eventsIndex, body: {
        size: 0,
        query: { bool: { filter: withTime([{ term: { dst_ip: target } }, { exists: { field: 'src_ip' } }]) } },
        aggs: { top: { terms: { field: 'src_ip', size: 20 } } },
      } }).catch(() => ({ body: { aggregations: {} } })),

      // Enrichment cache lookup (not time-scoped)
      client.get({ index: cacheIndex, id: target }).catch(() => ({ body: { found: false } })),
    ]);

    // Parse main aggregations
    const totalEvents = mainResult.body?.hits?.total?.value || 0;
    const byAction = (mainResult.body?.aggregations?.by_action?.buckets || []).map((b) => ({ action: b.key, count: b.doc_count }));
    const byType = (mainResult.body?.aggregations?.by_type?.buckets || []).map((b) => ({ event_type: b.key, count: b.doc_count }));

    // Parse ports
    const topPorts = (portsResult.body?.aggregations?.top_ports?.buckets || []).map((b) => ({
      dst_port: b.key, protocol: b.proto?.buckets?.[0]?.key || null, count: b.doc_count,
    }));
    const topSrcPorts = (srcPortsResult.body?.aggregations?.top_ports?.buckets || []).map((b) => ({
      src_port: b.key, protocol: b.proto?.buckets?.[0]?.key || null, count: b.doc_count,
    }));

    // Parse first/last
    const [firstResult, lastResult] = firstLastResult;
    const firstSeen = firstResult.body?.hits?.hits?.[0]?._source?.received_at || null;
    const lastSeen = lastResult.body?.hits?.hits?.[0]?._source?.received_at || null;

    // Parse signatures
    const signatures = (sigsResult.body?.aggregations?.sigs?.buckets || []).map((b) => ({
      ids_signature: b.key, ids_classification: b.cls?.buckets?.[0]?.key || null, count: b.doc_count,
    }));

    // Targets hit
    const targetsHit = targetsResult.body?.aggregations?.unique_dst?.value || 0;

    // Top destinations/sources
    const topDestinations = (topDstResult.body?.aggregations?.top?.buckets || []).map((b) => ({ ip: b.key, count: b.doc_count }));
    const topSources = (topSrcResult.body?.aggregations?.top?.buckets || []).map((b) => ({ ip: b.key, count: b.doc_count }));

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
      } });
      timeline = (tlResult.body?.aggregations?.timeline?.buckets || []).map((b) => ({
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
        } },
        sort: [{ abuseConfidenceScore: { order: 'desc', missing: '_last' } }],
      } });
      relatedIPs = (relResult.body?.hits?.hits || []).slice(0, 10).map((h) => ({
        ip: h._id, abuse_score: h._source?.abuseConfidenceScore ?? null,
        geo_country: h._source?.country || null, hostname: h._source?.hostname || null,
      }));
    } catch {}

    return { cached, totalEvents, byAction, byType, topPorts, topSrcPorts, timeline, firstSeen, lastSeen, relatedIPs, signatures, targetsHit, topDestinations, topSources };
  } catch (err) {
    logger.warn({ err, target }, 'OpenSearch gatherHuntIntel failed');
    return { cached: null, totalEvents: 0, byAction: [], byType: [], topPorts: [], topSrcPorts: [], timeline: [], firstSeen: null, lastSeen: null, relatedIPs: [], signatures: [], targetsHit: 0, topDestinations: [], topSources: [] };
  }
}

module.exports = { gatherHuntIntel };
