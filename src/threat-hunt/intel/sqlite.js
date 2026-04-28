/**
 * Threat Hunt intel gathering against the SQLite backend.
 *
 * Operates directly on the better-sqlite3 handle — these queries are
 * milliseconds even on multi-million-row tables thanks to the
 * idx_events_src_ip / idx_events_dst_ip indexes, so they don't need
 * the stats worker offload.
 */
function gatherHuntIntel(backend, target, since) {
  const db = backend.getDb();

  // `since` may be null (period omitted) — in that case skip the time
  // filter entirely to match main's pre-period-selector behavior.
  const t = since ? 'AND received_at >= ?' : '';
  const tArg = since ? [since] : [];

  // Cache + related-IPs lookups are NOT time-scoped (cache is current-state).
  const cached = db.prepare('SELECT * FROM ip_enrichment_cache WHERE ip = ?').get(target);
  const totalEvents = db.prepare(
    `SELECT COUNT(*) as c FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}`,
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
    `SELECT MIN(received_at) as t FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}`,
  ).get(target, target, ...tArg).t;
  const lastSeen = db.prepare(
    `SELECT MAX(received_at) as t FROM events WHERE (src_ip = ? OR dst_ip = ?) ${t}`,
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
    `SELECT COUNT(DISTINCT dst_ip) as c FROM events WHERE src_ip = ? ${t}`,
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

module.exports = { gatherHuntIntel };
