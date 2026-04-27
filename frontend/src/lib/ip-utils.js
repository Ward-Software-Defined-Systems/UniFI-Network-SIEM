// Frontend mirror of `src/utils/ip-utils.js` — keep in sync.
// Kept as a parallel ESM file rather than a build-time symlink so the
// frontend can ship without any backend transpilation step.

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
  if (long === null) return null;
  if (((long & 0xFF000000) >>> 0) === (0x0A000000 >>> 0)) return true;
  if (((long & 0xFFF00000) >>> 0) === (0xAC100000 >>> 0)) return true;
  if (((long & 0xFFFF0000) >>> 0) === (0xC0A80000 >>> 0)) return true;
  if (((long & 0xFFC00000) >>> 0) === (0x64400000 >>> 0)) return true;
  if (((long & 0xFF000000) >>> 0) === (0x7F000000 >>> 0)) return true;
  if (((long & 0xFFFF0000) >>> 0) === (0xA9FE0000 >>> 0)) return true;
  if (((long & 0xF0000000) >>> 0) === (0xE0000000 >>> 0)) return true;
  if (long === (0xFFFFFFFF >>> 0)) return true;
  if (long === 0) return true;
  return false;
}

function isPrivateIpv6(ip) {
  if (typeof ip !== 'string' || !ip.includes(':')) return null;
  const lower = ip.toLowerCase();
  const noZone = lower.split('%')[0];
  if (!/^[0-9a-f:.]+$/.test(noZone)) return null;
  if (noZone.startsWith('::ffff:')) {
    const rest = noZone.slice(7);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(rest)) {
      const v4 = isPrivateIpv4(rest);
      if (v4 !== null) return v4;
    }
  }
  if (noZone === '::' || noZone === '::1') return true;
  if (/^fe[89ab]/.test(noZone)) return true;
  if (/^f[cd]/.test(noZone)) return true;
  return false;
}

export function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const v4 = isPrivateIpv4(ip);
  if (v4 !== null) return v4;
  const v6 = isPrivateIpv6(ip);
  if (v6 !== null) return v6;
  return true;
}
