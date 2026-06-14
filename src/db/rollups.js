/**
 * Pure-function rollup math, shared by every backend that maintains
 * pre-aggregated stats tables/collections.
 *
 * `accumulateRollups(events)` returns five Maps keyed by composite strings
 * (bucket | dimension fields). Backends iterate the values and persist via
 * their own primitive (UPSERT for SQLite, in-memory buffer + flush for
 * WardSONDB delta-rollups in Phase 10, or a no-op for OpenSearch where
 * native Rollup jobs handle this server-side).
 *
 * Bucket sizes:
 *   - 5-minute  → event_stats_5m / rollups-5m
 *   - 1-hour    → ip_stats_hourly / rollups-ip-hourly, port_stats_hourly,
 *                 sig_stats_hourly, client_stats_hourly
 *
 * Field names in the returned Maps match the SQL columns and WardSONDB
 * doc fields exactly (event_count, blocked_count, etc.) — no per-backend
 * renaming.
 */

const FIVE_MIN_MS = 5 * 60 * 1000;
const ONE_HOUR_MS = 60 * 60 * 1000;

function align5m(iso) {
  const ms = (iso ? new Date(iso) : new Date()).getTime();
  return new Date(Math.floor(ms / FIVE_MIN_MS) * FIVE_MIN_MS).toISOString();
}

function align1h(iso) {
  const ms = (iso ? new Date(iso) : new Date()).getTime();
  return new Date(Math.floor(ms / ONE_HOUR_MS) * ONE_HOUR_MS).toISOString();
}

/**
 * Returns a fresh set of empty rollup buffers — convenient for callers
 * that maintain a persistent buffer (WardSONDB).
 */
function newRollupBuffers() {
  return {
    fiveMin: new Map(),
    ipHourly: new Map(),
    portHourly: new Map(),
    sigHourly: new Map(),
    clientHourly: new Map(),
  };
}

/**
 * Accumulate counts for a batch of events and return five Maps.
 *
 * Keys:
 *   fiveMin       `${bucket5m}|${event_type}|${action}`
 *   ipHourly      `${bucket1h}|${ip}|${direction}`        // src or dst
 *   portHourly    `${bucket1h}|${dst_port}|${protocol}`
 *   sigHourly     `${bucket1h}|${ids_signature}|${ids_classification}`  // threat events only
 *   clientHourly  `${bucket1h}|${mac}`
 */
function accumulateRollups(events) {
  const out = newRollupBuffers();
  const now = Date.now();

  for (const evt of events) {
    const ms = evt.received_at ? new Date(evt.received_at).getTime() : now;
    if (!Number.isFinite(ms)) continue;

    const b5 = new Date(Math.floor(ms / FIVE_MIN_MS) * FIVE_MIN_MS).toISOString();
    const b1 = new Date(Math.floor(ms / ONE_HOUR_MS) * ONE_HOUR_MS).toISOString();

    const type = evt.event_type || 'unknown';
    const action = evt.action || '';
    const isBlocked = action === 'block' ? 1 : 0;
    const isThreat = type === 'threat' ? 1 : 0;

    // 5-minute event stats
    {
      const key = `${b5}|${type}|${action}`;
      const ex = out.fiveMin.get(key);
      if (ex) ex.count++;
      else out.fiveMin.set(key, { bucket: b5, event_type: type, action, count: 1 });
    }

    // Hourly IP stats — both directions, all IPs (private filtering happens
    // at query time so this remains a pure aggregation).
    if (evt.src_ip) addIp(out.ipHourly, b1, evt.src_ip, 'src', isBlocked, isThreat);
    if (evt.dst_ip) addIp(out.ipHourly, b1, evt.dst_ip, 'dst', isBlocked, isThreat);

    // Hourly port stats — every event with a destination port
    if (evt.dst_port != null) {
      const protocol = evt.protocol || '';
      const key = `${b1}|${evt.dst_port}|${protocol}`;
      const ex = out.portHourly.get(key);
      if (ex) ex.count++;
      else out.portHourly.set(key, { bucket: b1, port: evt.dst_port, protocol, count: 1 });
    }

    // Hourly signature stats — threat events only, with explicit
    // '(no signature)' fallback so threats without an IDS signature still
    // appear in Top Threats.
    if (type === 'threat') {
      const sig = evt.ids_signature || '(no signature)';
      const cls = evt.ids_classification || '';
      const key = `${b1}|${sig}|${cls}`;
      const ex = out.sigHourly.get(key);
      if (ex) ex.count++;
      else out.sigHourly.set(key, { bucket: b1, signature: sig, classification: cls, count: 1 });
    }

    // Hourly client stats — first-non-null MAC across the three sources.
    // Counts are pre-pivoted by event type so Top Clients can render
    // wifi/dhcp/firewall breakdowns without grouping at query time.
    const mac = evt.client_mac || evt.wifi_client_mac || evt.dhcp_mac;
    if (mac) {
      const key = `${b1}|${mac}`;
      const ex = out.clientHourly.get(key);
      if (ex) {
        ex.event_count++;
        if (type === 'wifi') ex.wifi_count++;
        else if (type === 'dhcp') ex.dhcp_count++;
        else if (type === 'firewall') ex.firewall_count++;
      } else {
        out.clientHourly.set(key, {
          bucket: b1, mac,
          event_count: 1,
          wifi_count: type === 'wifi' ? 1 : 0,
          dhcp_count: type === 'dhcp' ? 1 : 0,
          firewall_count: type === 'firewall' ? 1 : 0,
        });
      }
    }
  }

  return out;
}

function addIp(map, bucket, ip, direction, isBlocked, isThreat) {
  const key = `${bucket}|${ip}|${direction}`;
  const ex = map.get(key);
  if (ex) {
    ex.event_count++;
    ex.blocked_count += isBlocked;
    ex.threat_count += isThreat;
    return;
  }
  map.set(key, {
    bucket, ip, direction,
    event_count: 1, blocked_count: isBlocked, threat_count: isThreat,
  });
}

/**
 * Merge `source` rollups into `target`. Used by WardSONDB to fold each
 * batch's accumulated rollups into the persistent in-memory buffer that
 * flushes every 5 seconds.
 */
function mergeRollups(target, source) {
  for (const [key, r] of source.fiveMin) {
    const ex = target.fiveMin.get(key);
    if (ex) ex.count += r.count;
    else target.fiveMin.set(key, r);
  }
  for (const [key, r] of source.ipHourly) {
    const ex = target.ipHourly.get(key);
    if (ex) {
      ex.event_count += r.event_count;
      ex.blocked_count += r.blocked_count;
      ex.threat_count += r.threat_count;
    } else {
      target.ipHourly.set(key, r);
    }
  }
  for (const [key, r] of source.portHourly) {
    const ex = target.portHourly.get(key);
    if (ex) ex.count += r.count;
    else target.portHourly.set(key, r);
  }
  for (const [key, r] of source.sigHourly) {
    const ex = target.sigHourly.get(key);
    if (ex) ex.count += r.count;
    else target.sigHourly.set(key, r);
  }
  for (const [key, r] of source.clientHourly) {
    const ex = target.clientHourly.get(key);
    if (ex) {
      ex.event_count += r.event_count;
      ex.wifi_count += r.wifi_count;
      ex.dhcp_count += r.dhcp_count;
      ex.firewall_count += r.firewall_count;
    } else {
      target.clientHourly.set(key, r);
    }
  }
  return target;
}

module.exports = { align5m, align1h, accumulateRollups, mergeRollups, newRollupBuffers };
