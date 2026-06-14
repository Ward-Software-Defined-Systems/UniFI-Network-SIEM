const { isPrivateIp, detectDirection } = require('../../src/utils/ip-utils');

describe('isPrivateIp', () => {
  describe('RFC1918', () => {
    it.each([
      '10.0.0.1', '10.255.255.254',
      '172.16.0.1', '172.16.255.254', '172.31.255.254',
      '192.168.0.1', '192.168.255.254',
    ])('classifies %s as private', (ip) => {
      expect(isPrivateIp(ip)).toBe(true);
    });

    it.each([
      '11.0.0.1',
      '172.15.255.254', '172.32.0.1',
      '192.169.0.1', '192.167.0.1',
    ])('classifies %s as public (just outside RFC1918)', (ip) => {
      expect(isPrivateIp(ip)).toBe(false);
    });
  });

  describe('CGNAT (100.64.0.0/10)', () => {
    it('classifies addresses inside the /10 as private', () => {
      expect(isPrivateIp('100.64.0.1')).toBe(true);
      expect(isPrivateIp('100.100.0.1')).toBe(true);
      // Boundary: 100.127.255.255 is the LAST address in the /10
      expect(isPrivateIp('100.127.255.255')).toBe(true);
    });

    it('classifies 100.128.x.x and beyond as PUBLIC (outside the /10)', () => {
      // H4 — the SQLite SQL filter currently mis-classifies 100.128–100.199 as
      // private due to a too-broad LIKE pattern. The JS isPrivateIp is correct,
      // and this test locks in that behavior so the SQLite fix can mirror it.
      expect(isPrivateIp('100.128.0.1')).toBe(false);
      expect(isPrivateIp('100.150.0.1')).toBe(false);
      expect(isPrivateIp('100.199.0.1')).toBe(false);
      expect(isPrivateIp('100.200.0.1')).toBe(false);
    });
  });

  describe('Special-purpose ranges', () => {
    it('loopback 127/8 is private', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true);
      expect(isPrivateIp('127.255.255.254')).toBe(true);
    });

    it('link-local 169.254/16 is private', () => {
      expect(isPrivateIp('169.254.1.1')).toBe(true);
    });

    it('multicast 224/4 is private (filtered from external lookups)', () => {
      expect(isPrivateIp('224.0.0.1')).toBe(true);
      expect(isPrivateIp('239.255.255.255')).toBe(true);
    });

    it('all-zeros and broadcast are private', () => {
      expect(isPrivateIp('0.0.0.0')).toBe(true);
      expect(isPrivateIp('255.255.255.255')).toBe(true);
    });
  });

  describe('Public IPs', () => {
    it.each(['8.8.8.8', '1.1.1.1', '99.83.252.10', '34.117.59.81'])(
      '%s is public',
      (ip) => expect(isPrivateIp(ip)).toBe(false),
    );
  });

  describe('Invalid input', () => {
    it('null/undefined/non-string returns true (defensive default)', () => {
      expect(isPrivateIp(null)).toBe(true);
      expect(isPrivateIp(undefined)).toBe(true);
      expect(isPrivateIp(42)).toBe(true);
    });
  });

  describe('IPv6 (Phase 4 / H5)', () => {
    it('IPv6 loopback ::1 is private', () => {
      expect(isPrivateIp('::1')).toBe(true);
    });

    it('IPv6 unspecified :: is private', () => {
      expect(isPrivateIp('::')).toBe(true);
    });

    it('IPv6 link-local fe80::/10 is private', () => {
      expect(isPrivateIp('fe80::1')).toBe(true);
      expect(isPrivateIp('febf::ffff')).toBe(true);
    });

    it('IPv6 ULA fc00::/7 is private', () => {
      expect(isPrivateIp('fc00::1')).toBe(true);
      expect(isPrivateIp('fd12:3456::1')).toBe(true);
    });

    it('global IPv6 (2001:db8::1) is PUBLIC', () => {
      expect(isPrivateIp('2001:db8::1')).toBe(false);
    });

    it('IPv4-mapped IPv6 of a public IPv4 is PUBLIC', () => {
      expect(isPrivateIp('::ffff:8.8.8.8')).toBe(false);
    });

    it('IPv4-mapped IPv6 of a private IPv4 is private (delegates to IPv4 logic)', () => {
      expect(isPrivateIp('::ffff:10.0.0.1')).toBe(true);
      expect(isPrivateIp('::ffff:127.0.0.1')).toBe(true);
    });

    it('zone identifiers are stripped (fe80::1%eth0 still private)', () => {
      expect(isPrivateIp('fe80::1%eth0')).toBe(true);
    });

    it('garbage with colons but non-hex chars falls back to defensive default (private)', () => {
      expect(isPrivateIp('not:an:address')).toBe(true);
    });
  });
});

describe('detectDirection', () => {
  it('inbound: src public, dst private, in on WAN', () => {
    expect(detectDirection('eth8', 'br4', '8.8.8.8', '172.16.4.1')).toBe('inbound');
  });

  it('outbound: src private, out on WAN', () => {
    expect(detectDirection('br4', 'eth8', '172.16.4.1', '8.8.8.8')).toBe('outbound');
  });

  it('inter-vlan: src and dst both private, no WAN interface in path', () => {
    expect(detectDirection('br4', 'br10', '172.16.4.1', '172.16.10.1')).toBe('inter-vlan');
  });

  it('local: no out interface', () => {
    expect(detectDirection('br4', '', '172.16.4.1', '172.16.4.2')).toBe('local');
  });
});
