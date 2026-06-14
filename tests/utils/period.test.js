const { PERIOD_MS, getSinceOptional, getSinceOrDefault } = require('../../src/utils/period');

describe('period util', () => {
  describe('PERIOD_MS', () => {
    it('exposes the canonical period set', () => {
      expect(Object.keys(PERIOD_MS).sort()).toEqual(['1h', '24h', '30d', '6h', '7d']);
      expect(PERIOD_MS['1h']).toBe(3600000);
      expect(PERIOD_MS['30d']).toBe(2592000000);
    });
  });

  describe('getSinceOptional', () => {
    it('returns null for unknown periods', () => {
      expect(getSinceOptional('2h')).toBeNull();
      expect(getSinceOptional('')).toBeNull();
      expect(getSinceOptional(undefined)).toBeNull();
    });

    it('returns an ISO string roughly the right offset in the past', () => {
      const before = Date.now();
      const since = getSinceOptional('1h');
      const after = Date.now();
      expect(since).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      const t = new Date(since).getTime();
      // Allow ~10ms slack on either side
      expect(t).toBeGreaterThanOrEqual(before - 3600000 - 10);
      expect(t).toBeLessThanOrEqual(after - 3600000 + 10);
    });

    it('handles 30d', () => {
      const since = getSinceOptional('30d');
      const t = new Date(since).getTime();
      expect(Date.now() - t).toBeGreaterThan(2_500_000_000);
      expect(Date.now() - t).toBeLessThan(2_700_000_000);
    });
  });

  describe('getSinceOrDefault', () => {
    it('falls back to 24h for unknown periods', () => {
      const since = getSinceOrDefault('99x');
      const t = new Date(since).getTime();
      expect(Date.now() - t).toBeGreaterThan(86_000_000);
      expect(Date.now() - t).toBeLessThan(86_500_000);
    });

    it('honours a custom default period', () => {
      const since = getSinceOrDefault(undefined, '1h');
      const t = new Date(since).getTime();
      expect(Date.now() - t).toBeGreaterThan(3_590_000);
      expect(Date.now() - t).toBeLessThan(3_610_000);
    });

    it('returns null only when both period and default are unknown', () => {
      expect(getSinceOrDefault('bogus', 'also-bogus')).toBeNull();
    });
  });
});
