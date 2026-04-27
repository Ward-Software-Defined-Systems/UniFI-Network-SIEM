/**
 * Tiny IPv4 CIDR utilities for the syslog source allowlist.
 *
 * IPv4 only. UniFi gateways send syslog over IPv4 in practice; if/when
 * IPv6 sources show up, extend or swap for the `ip-cidr` package.
 */

const logger = require('./logger');

function ipv4ToInt(ip) {
  if (typeof ip !== 'string') return null;
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

/**
 * Compile a comma-separated CSV of IPs/CIDRs into a list of {baseInt, mask}.
 * Returns null when the input is empty (caller treats null as "allow all").
 * Logs a warning for individual malformed entries but does not throw.
 */
function compileCidrs(csv) {
  if (!csv || typeof csv !== 'string' || csv.trim() === '') return null;
  const compiled = [];
  for (const raw of csv.split(',')) {
    const part = raw.trim();
    if (!part) continue;
    const [base, bitsStr] = part.split('/');
    const baseInt = ipv4ToInt(base);
    if (baseInt === null) {
      logger.warn({ entry: part }, 'Skipping invalid syslog-allowlist entry (not an IPv4 address)');
      continue;
    }
    const bits = bitsStr === undefined ? 32 : parseInt(bitsStr, 10);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
      logger.warn({ entry: part }, 'Skipping invalid syslog-allowlist entry (CIDR bits out of range)');
      continue;
    }
    const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
    compiled.push({ baseInt: (baseInt & mask) >>> 0, mask });
  }
  return compiled.length === 0 ? null : compiled;
}

function ipMatchesAny(ip, compiled) {
  if (!compiled) return true; // null = allow all
  const ipInt = ipv4ToInt(ip);
  if (ipInt === null) return false;
  for (const { baseInt, mask } of compiled) {
    if (((ipInt & mask) >>> 0) === baseInt) return true;
  }
  return false;
}

module.exports = { ipv4ToInt, compileCidrs, ipMatchesAny };
