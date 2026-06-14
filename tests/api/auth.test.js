const { constantTimeCompare } = require('../../src/api/middleware/auth');
const config = require('../../src/config');
const cryptoUtil = require('../../src/utils/crypto');

describe('auth middleware', () => {
  describe('constantTimeCompare', () => {
    it('returns true for identical strings', () => {
      expect(constantTimeCompare('abc123', 'abc123')).toBe(true);
    });
    it('returns false for different strings of equal length', () => {
      expect(constantTimeCompare('abc123', 'xyz789')).toBe(false);
    });
    it('returns false for different lengths (no length leak via comparison)', () => {
      expect(constantTimeCompare('short', 'longer-string')).toBe(false);
    });
    it('handles empty strings', () => {
      expect(constantTimeCompare('', '')).toBe(true);
      expect(constantTimeCompare('a', '')).toBe(false);
    });
  });

  describe('requireApiToken middleware', () => {
    // Re-require for a fresh module each time so the warned-flag is reset.
    function loadAuth() {
      delete require.cache[require.resolve('../../src/api/middleware/auth')];
      return require('../../src/api/middleware/auth');
    }
    function makeReqRes(headers = {}) {
      const req = { headers };
      const sentBody = { code: null, body: null };
      const res = {
        status(code) { sentBody.code = code; return this; },
        json(obj) { sentBody.body = obj; return this; },
      };
      return { req, res, sent: sentBody };
    }

    afterEach(() => {
      config.auth.apiToken = '';
    });

    it('503 when no token is configured', () => {
      config.auth.apiToken = '';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes();
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(sent.code).toBe(503);
      expect(nextCalled).toBe(false);
    });

    it('401 when no Authorization header', () => {
      config.auth.apiToken = 'thetoken123';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes();
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(sent.code).toBe(401);
      expect(sent.body.error).toMatch(/Missing/);
      expect(nextCalled).toBe(false);
    });

    it('401 when Authorization is not Bearer', () => {
      config.auth.apiToken = 'thetoken123';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes({ authorization: 'Basic foo' });
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(sent.code).toBe(401);
      expect(nextCalled).toBe(false);
    });

    it('401 when token mismatches', () => {
      config.auth.apiToken = 'thetoken123';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes({ authorization: 'Bearer wrong' });
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(sent.code).toBe(401);
      expect(sent.body.error).toMatch(/Invalid/);
      expect(nextCalled).toBe(false);
    });

    it('401 when token is right length but wrong bytes', () => {
      config.auth.apiToken = 'aaaaaa';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes({ authorization: 'Bearer bbbbbb' });
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(sent.code).toBe(401);
      expect(nextCalled).toBe(false);
    });

    it('passes when token matches exactly', () => {
      config.auth.apiToken = 'thetoken123';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes({ authorization: 'Bearer thetoken123' });
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(sent.code).toBeNull();
    });

    it('tolerates extra whitespace in Bearer header', () => {
      config.auth.apiToken = 'thetoken123';
      const { requireApiToken } = loadAuth();
      const { req, res, sent } = makeReqRes({ authorization: 'Bearer thetoken123  ' });
      let nextCalled = false;
      requireApiToken(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });
  });

  describe('validateWsToken', () => {
    function loadAuth() {
      delete require.cache[require.resolve('../../src/api/middleware/auth')];
      return require('../../src/api/middleware/auth');
    }
    afterEach(() => { config.auth.apiToken = ''; });

    it('false when no expected token configured', () => {
      const { validateWsToken } = loadAuth();
      expect(validateWsToken('anytoken')).toBe(false);
    });
    it('false on empty/null token input', () => {
      config.auth.apiToken = 'configured';
      const { validateWsToken } = loadAuth();
      expect(validateWsToken('')).toBe(false);
      expect(validateWsToken(null)).toBe(false);
      expect(validateWsToken(undefined)).toBe(false);
    });
    it('true on exact match', () => {
      config.auth.apiToken = 'thetoken';
      const { validateWsToken } = loadAuth();
      expect(validateWsToken('thetoken')).toBe(true);
    });
    it('false on mismatch', () => {
      config.auth.apiToken = 'thetoken';
      const { validateWsToken } = loadAuth();
      expect(validateWsToken('other')).toBe(false);
    });
  });
});
