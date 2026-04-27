const crypto = require('../../src/utils/crypto');

const TEST_KEY = '0'.repeat(64); // 64 hex chars → 32 zero bytes

describe('crypto helpers', () => {
  beforeEach(() => {
    crypto.setMasterKey(null);
    delete process.env.SIEM_MASTER_KEY;
  });

  describe('without a master key', () => {
    it('encrypt() returns plaintext unchanged (boot state)', () => {
      expect(crypto.encrypt('hello')).toBe('hello');
    });

    it('decrypt() returns plaintext unchanged when input is not v1: prefixed', () => {
      expect(crypto.decrypt('plaintext value')).toBe('plaintext value');
    });

    it('decrypt() throws when input IS encrypted but no key is available', () => {
      // Set a key, encrypt, clear key, then attempt decrypt.
      crypto.setMasterKey(TEST_KEY);
      const ct = crypto.encrypt('secret');
      crypto.setMasterKey(null);
      expect(() => crypto.decrypt(ct)).toThrow(/no master key/);
    });
  });

  describe('with a master key', () => {
    beforeEach(() => crypto.setMasterKey(TEST_KEY));

    it('round-trips a UTF-8 string', () => {
      const ct = crypto.encrypt('hello world ✓');
      expect(ct).toMatch(/^v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
      expect(crypto.decrypt(ct)).toBe('hello world ✓');
    });

    it('round-trips an empty string', () => {
      const ct = crypto.encrypt('');
      expect(crypto.decrypt(ct)).toBe('');
    });

    it('produces different ciphertexts for the same plaintext (random IV)', () => {
      const a = crypto.encrypt('same plaintext');
      const b = crypto.encrypt('same plaintext');
      expect(a).not.toBe(b);
      expect(crypto.decrypt(a)).toBe(crypto.decrypt(b));
    });

    it('decrypt() is idempotent on plaintext', () => {
      expect(crypto.decrypt('not encrypted')).toBe('not encrypted');
    });

    it('encrypt() is idempotent on already-encrypted input', () => {
      const ct = crypto.encrypt('x');
      expect(crypto.encrypt(ct)).toBe(ct);
    });

    it('throws on a corrupted auth tag', () => {
      const ct = crypto.encrypt('payload');
      const parts = ct.split(':');
      parts[2] = Buffer.from('badtag').toString('base64');
      const corrupted = parts.join(':');
      expect(() => crypto.decrypt(corrupted)).toThrow();
    });

    it('rotates: new key cannot decrypt old ciphertext', () => {
      const ct = crypto.encrypt('locked');
      crypto.setMasterKey('1'.repeat(64));
      expect(() => crypto.decrypt(ct)).toThrow();
    });
  });

  describe('key resolution', () => {
    it('falls back to SIEM_MASTER_KEY env var when no runtime key is set', () => {
      crypto.setMasterKey(null);
      process.env.SIEM_MASTER_KEY = TEST_KEY;
      const ct = crypto.encrypt('via env');
      expect(crypto.decrypt(ct)).toBe('via env');
    });

    it('runtime key (setMasterKey) wins over env var', () => {
      process.env.SIEM_MASTER_KEY = TEST_KEY;
      crypto.setMasterKey('1'.repeat(64));
      const ct = crypto.encrypt('runtime wins');
      // runtime key encrypted; env-key shouldn't decrypt
      crypto.setMasterKey(null);
      expect(() => crypto.decrypt(ct)).toThrow();
    });

    it('SHA-256-derives a 32-byte key from arbitrary string input', () => {
      crypto.setMasterKey('any short passphrase');
      const ct = crypto.encrypt('payload');
      expect(crypto.decrypt(ct)).toBe('payload');
    });
  });

  describe('generators', () => {
    it('generateMasterKey() returns 64 hex chars', () => {
      const k = crypto.generateMasterKey();
      expect(k).toMatch(/^[0-9a-f]{64}$/);
    });

    it('generateApiToken() returns 64 hex chars', () => {
      const t = crypto.generateApiToken();
      expect(t).toMatch(/^[0-9a-f]{64}$/);
    });

    it('successive calls produce different values', () => {
      expect(crypto.generateMasterKey()).not.toBe(crypto.generateMasterKey());
      expect(crypto.generateApiToken()).not.toBe(crypto.generateApiToken());
    });
  });

  describe('isEncrypted', () => {
    it('detects v1: prefix', () => {
      crypto.setMasterKey(TEST_KEY);
      expect(crypto.isEncrypted(crypto.encrypt('x'))).toBe(true);
      expect(crypto.isEncrypted('plaintext')).toBe(false);
      expect(crypto.isEncrypted('')).toBe(false);
      expect(crypto.isEncrypted(null)).toBe(false);
    });
  });

  describe('maskSensitive', () => {
    it('masks long values with last 4 visible', () => {
      expect(crypto.maskSensitive('sk-ant-1234567890abcdef')).toBe('••••••••cdef');
    });
    it('handles short and empty values', () => {
      expect(crypto.maskSensitive('')).toBe('');
      expect(crypto.maskSensitive('abcd')).toBe('••••');
    });
  });
});
