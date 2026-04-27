/**
 * Single source of truth for private-IP classification.
 *
 * `isPrivateIp(ip)` returns true when the IP is one of:
 *   - RFC1918:        10/8, 172.16/12, 192.168/16
 *   - CGNAT:          100.64/10            (NOT 100.128–100.199)
 *   - loopback:       127/8 / ::1
 *   - link-local:     169.254/16 / fe80::/10
 *   - ULA:            fc00::/7
 *   - multicast:      224/4
 *   - zero/broadcast: 0.0.0.0, 255.255.255.255, ::
 *   - IPv4-mapped IPv6 (::ffff:x.y.z.w) — delegates to IPv4 check
 *   - any unparseable / non-string input  — defensive default
 *
 * Returns false for:
 *   - public IPv4
 *   - global IPv6 (e.g. 2001:db8::1)
 *   - IPv4-mapped IPv6 of a public IPv4
 *
 * The SQL form of the same predicate lives in
 * `src/db/utils/private-ip-sql.js` and the frontend mirror is at
 * `frontend/src/lib/ip-utils.js`. All three must stay in sync.
 */

function ipv4ToLong(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = parseInt(p, 10);
    if (v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function isPrivateIpv4(ip) {
  const long = ipv4ToLong(ip);
  if (long === null) return null; // not IPv4
  // All comparisons use >>> 0 so the high-bit ranges (172.x, 224.x, 255.x)
  // compare correctly under JS's signed 32-bit bitwise semantics.
  if (((long & 0xFF000000) >>> 0) === (0x0A000000 >>> 0)) return true; // 10/8
  if (((long & 0xFFF00000) >>> 0) === (0xAC100000 >>> 0)) return true; // 172.16/12
  if (((long & 0xFFFF0000) >>> 0) === (0xC0A80000 >>> 0)) return true; // 192.168/16
  if (((long & 0xFFC00000) >>> 0) === (0x64400000 >>> 0)) return true; // 100.64/10 — CGNAT
  if (((long & 0xFF000000) >>> 0) === (0x7F000000 >>> 0)) return true; // 127/8
  if (((long & 0xFFFF0000) >>> 0) === (0xA9FE0000 >>> 0)) return true; // 169.254/16
  if (((long & 0xF0000000) >>> 0) === (0xE0000000 >>> 0)) return true; // 224/4 multicast
  if (long === (0xFFFFFFFF >>> 0)) return true;                        // broadcast
  if (long === 0) return true;                                         // 0.0.0.0
  return false;
}

function isPrivateIpv6(ip) {
  if (typeof ip !== 'string' || !ip.includes(':')) return null;
  const lower = ip.toLowerCase();
  // Drop the optional zone identifier (fe80::1%eth0).
  const noZone = lower.split('%')[0];
  // Reject anything outside the IPv6 character set (rejects garbage like
  // "x:y:z" while still accepting valid "::ffff:1.2.3.4" embedded form).
  if (!/^[0-9a-f:.]+$/.test(noZone)) return null;

  // IPv4-mapped IPv6 — delegate to the IPv4 check on the embedded address.
  if (noZone.startsWith('::ffff:')) {
    const rest = noZone.slice(7);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(rest)) {
      const v4 = isPrivateIpv4(rest);
      if (v4 !== null) return v4;
    }
  }

  if (noZone === '::' || noZone === '::1') return true;        // unspecified, loopback
  if (/^fe[89ab]/.test(noZone)) return true;                    // fe80::/10 link-local
  if (/^f[cd]/.test(noZone)) return true;                       // fc00::/7 ULA
  return false; // global unicast or other
}

function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true; // defensive: skip enrichment

  const v4 = isPrivateIpv4(ip);
  if (v4 !== null) return v4;

  const v6 = isPrivateIpv6(ip);
  if (v6 !== null) return v6;

  // Unrecognized format — defensive default: treat as private so we don't
  // waste enrichment quota / API calls on garbage.
  return true;
}

const WAN_INTERFACES = new Set([
  'eth0', 'eth8', 'eth9', 'pppoe0', 'pppoe1',
  'wg0', 'wg1', 'wgsts1000',
]);

function detectDirection(interfaceIn, interfaceOut, srcIp, dstIp) {
  const srcPrivate = isPrivateIp(srcIp);
  const dstPrivate = isPrivateIp(dstIp);

  if (!interfaceOut) return 'local';
  if (WAN_INTERFACES.has(interfaceIn) && dstPrivate) return 'inbound';
  if (srcPrivate && WAN_INTERFACES.has(interfaceOut)) return 'outbound';
  if (srcPrivate && dstPrivate) return 'inter-vlan';
  return 'outbound';
}

module.exports = { isPrivateIp, isPrivateIpv4, isPrivateIpv6, detectDirection };
