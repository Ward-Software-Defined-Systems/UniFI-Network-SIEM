function ipToLong(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return 0;
  return ((parseInt(parts[0]) << 24) | (parseInt(parts[1]) << 16) |
          (parseInt(parts[2]) << 8) | parseInt(parts[3])) >>> 0;
}

function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const long = ipToLong(ip);
  // All comparisons use >>> 0 to ensure unsigned 32-bit arithmetic
  // (JS bitwise ops return signed int32; high-bit IPs like 172.x would mismatch)
  // 10.0.0.0/8
  if (((long & 0xFF000000) >>> 0) === (0x0A000000 >>> 0)) return true;
  // 172.16.0.0/12
  if (((long & 0xFFF00000) >>> 0) === (0xAC100000 >>> 0)) return true;
  // 192.168.0.0/16
  if (((long & 0xFFFF0000) >>> 0) === (0xC0A80000 >>> 0)) return true;
  // 100.64.0.0/10 (CGNAT)
  if (((long & 0xFFC00000) >>> 0) === (0x64400000 >>> 0)) return true;
  // 127.0.0.0/8
  if (((long & 0xFF000000) >>> 0) === (0x7F000000 >>> 0)) return true;
  // 169.254.0.0/16
  if (((long & 0xFFFF0000) >>> 0) === (0xA9FE0000 >>> 0)) return true;
  // 224.0.0.0/4 (multicast)
  if (((long & 0xF0000000) >>> 0) === (0xE0000000 >>> 0)) return true;
  // 255.255.255.255
  if (long === (0xFFFFFFFF >>> 0)) return true;
  // 0.0.0.0
  if (long === 0) return true;
  return false;
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

module.exports = { isPrivateIp, detectDirection };
