const { ipv4ToInt, compileCidrs, ipMatchesAny } = require('../../src/utils/cidr');

describe('cidr', () => {
  describe('ipv4ToInt', () => {
    it('parses dotted-quad correctly', () => {
      expect(ipv4ToInt('0.0.0.0')).toBe(0);
      expect(ipv4ToInt('255.255.255.255')).toBe(0xFFFFFFFF);
      expect(ipv4ToInt('10.0.0.1')).toBe(0x0A000001);
      expect(ipv4ToInt('192.168.1.100')).toBe(0xC0A80164);
    });
    it('returns null on invalid input', () => {
      expect(ipv4ToInt(null)).toBeNull();
      expect(ipv4ToInt('')).toBeNull();
      expect(ipv4ToInt('1.2.3')).toBeNull();
      expect(ipv4ToInt('1.2.3.4.5')).toBeNull();
      expect(ipv4ToInt('256.0.0.1')).toBeNull();
      expect(ipv4ToInt('1.2.3.x')).toBeNull();
      expect(ipv4ToInt('::1')).toBeNull();
    });
  });

  describe('compileCidrs', () => {
    it('returns null for empty/missing input (allow-all)', () => {
      expect(compileCidrs('')).toBeNull();
      expect(compileCidrs('   ')).toBeNull();
      expect(compileCidrs(null)).toBeNull();
      expect(compileCidrs(undefined)).toBeNull();
    });
    it('compiles a single bare IP as /32', () => {
      const c = compileCidrs('10.0.0.1');
      expect(c.length).toBe(1);
      expect(c[0].mask).toBe(0xFFFFFFFF);
      expect(c[0].baseInt).toBe(0x0A000001);
    });
    it('compiles a CIDR', () => {
      const c = compileCidrs('192.168.1.0/24');
      expect(c.length).toBe(1);
      expect(c[0].mask).toBe(0xFFFFFF00);
      expect(c[0].baseInt).toBe(0xC0A80100);
    });
    it('compiles multiple comma-separated entries (with whitespace tolerance)', () => {
      const c = compileCidrs(' 10.0.0.0/8 , 172.16.4.1 , 192.168.0.0/16 ');
      expect(c.length).toBe(3);
    });
    it('skips invalid entries with a warning, keeps valid ones', () => {
      const c = compileCidrs('10.0.0.0/8,not-an-ip,256.1.1.1,192.168.1.1');
      expect(c.length).toBe(2);
    });
    it('skips entries with bad CIDR bits', () => {
      const c = compileCidrs('10.0.0.0/33');
      expect(c).toBeNull();
    });
    it('returns null when every entry is invalid', () => {
      expect(compileCidrs('garbage,more-garbage')).toBeNull();
    });
    it('handles /0 (match all) as a valid CIDR', () => {
      const c = compileCidrs('0.0.0.0/0');
      expect(c.length).toBe(1);
      expect(c[0].mask).toBe(0);
      expect(c[0].baseInt).toBe(0);
    });
  });

  describe('ipMatchesAny', () => {
    it('returns true for null compiled list (allow-all)', () => {
      expect(ipMatchesAny('1.2.3.4', null)).toBe(true);
    });
    it('matches a single /32 entry', () => {
      const c = compileCidrs('10.0.0.1');
      expect(ipMatchesAny('10.0.0.1', c)).toBe(true);
      expect(ipMatchesAny('10.0.0.2', c)).toBe(false);
    });
    it('matches inside a /24', () => {
      const c = compileCidrs('192.168.1.0/24');
      expect(ipMatchesAny('192.168.1.1', c)).toBe(true);
      expect(ipMatchesAny('192.168.1.255', c)).toBe(true);
      expect(ipMatchesAny('192.168.2.1', c)).toBe(false);
    });
    it('matches inside a /8', () => {
      const c = compileCidrs('10.0.0.0/8');
      expect(ipMatchesAny('10.0.0.1', c)).toBe(true);
      expect(ipMatchesAny('10.255.255.254', c)).toBe(true);
      expect(ipMatchesAny('11.0.0.1', c)).toBe(false);
    });
    it('matches against the first matching entry across multiple', () => {
      const c = compileCidrs('10.0.0.0/8,172.16.0.0/12,192.168.0.0/16');
      expect(ipMatchesAny('10.5.5.5', c)).toBe(true);
      expect(ipMatchesAny('172.20.1.1', c)).toBe(true);
      expect(ipMatchesAny('192.168.99.99', c)).toBe(true);
      expect(ipMatchesAny('8.8.8.8', c)).toBe(false);
    });
    it('returns false on invalid IP input', () => {
      const c = compileCidrs('10.0.0.0/8');
      expect(ipMatchesAny('not-an-ip', c)).toBe(false);
      expect(ipMatchesAny(null, c)).toBe(false);
    });
    it('/0 matches any IPv4 address', () => {
      const c = compileCidrs('0.0.0.0/0');
      expect(ipMatchesAny('1.2.3.4', c)).toBe(true);
      expect(ipMatchesAny('255.255.255.255', c)).toBe(true);
    });
  });
});
