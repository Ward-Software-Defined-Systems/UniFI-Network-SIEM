/**
 * Generates the SQLite SQL fragment that mirrors `isPrivateIp` from
 * `src/utils/ip-utils.js`. Used by SqliteBackend's stats methods when
 * `excludePrivate=true`. Kept programmatic so the CGNAT range (100.64/10)
 * and multicast range (224/4) are explicit per-octet patterns rather than
 * the previously buggy LIKE wildcards (`'100.1__.%'` accidentally
 * captured 100.128–100.199 which are public).
 *
 * Returns a string of `${col} NOT LIKE '...'` clauses joined by `\n      AND `.
 * Caller wraps in `WHERE ... AND (<this fragment>)` etc.
 */

function buildPrivateIpFilter(col) {
  const lines = [
    `${col} NOT LIKE '10.%'`,
    `${col} NOT LIKE '192.168.%'`,
  ];
  // 172.16/12 → 172.16 through 172.31
  for (let i = 16; i <= 31; i++) lines.push(`${col} NOT LIKE '172.${i}.%'`);
  // CGNAT 100.64/10 → 100.64 through 100.127 (NOT 100.128–100.199 — H4 fix)
  for (let i = 64; i <= 127; i++) lines.push(`${col} NOT LIKE '100.${i}.%'`);
  // Loopback 127/8
  lines.push(`${col} NOT LIKE '127.%'`);
  // Link-local 169.254/16
  lines.push(`${col} NOT LIKE '169.254.%'`);
  // Multicast 224/4 → 224 through 239
  for (let i = 224; i <= 239; i++) lines.push(`${col} NOT LIKE '${i}.%'`);
  // Zero and broadcast
  lines.push(`${col} != '0.0.0.0'`);
  lines.push(`${col} != '255.255.255.255'`);
  // Coarse IPv6 exclusion. UniFi gateways currently emit IPv4 only; if any
  // IPv6 strings ever land in src/dst columns (colons in the IP), we
  // exclude them all rather than try to parse IPv6 in SQL. The downstream
  // JS-side filter on the rare IPv6 row is a future enhancement.
  lines.push(`${col} NOT LIKE '%:%'`);
  return lines.join('\n      AND ');
}

module.exports = { buildPrivateIpFilter };
