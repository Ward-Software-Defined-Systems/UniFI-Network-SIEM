// Tests for the WardSONDB queryEvents cursor encode/decode helpers.
// We don't talk to WardSONDB — these are private methods on the
// backend instance, so we instantiate it without initializing.

const WardsonDbBackend = require('../../src/db/backends/wardsondb');

function newBackend() {
  // Constructor does some setup (per-client undici Agent) but doesn't
  // talk to the network. Pass a minimal config.
  return new WardsonDbBackend({ host: 'localhost', port: 8080 });
}

describe('WardSONDB cursor helpers', () => {
  const b = newBackend();

  it('encodeCursor → decodeCursor round-trips received_at + id', () => {
    const encoded = b._encodeCursor('2026-04-27T10:00:00Z', '0195e3a1-2b3c-7d4e-8f5a-6b7c8d9e0f1a');
    const decoded = b._decodeCursor(encoded);
    expect(decoded).toEqual({
      received_at: '2026-04-27T10:00:00Z',
      id: '0195e3a1-2b3c-7d4e-8f5a-6b7c8d9e0f1a',
    });
  });

  it('decodeCursor returns null for malformed input rather than throwing', () => {
    expect(b._decodeCursor('not-base64!!')).toBeNull();
    expect(b._decodeCursor('')).toBeNull();
    expect(b._decodeCursor(null)).toBeNull();
    expect(b._decodeCursor(undefined)).toBeNull();
    expect(b._decodeCursor(123)).toBeNull();
  });

  it('decodeCursor returns null when the JSON parses but is missing fields', () => {
    const partial = Buffer.from(JSON.stringify({ id: 'a' }), 'utf8').toString('base64');
    expect(b._decodeCursor(partial)).toBeNull();
    const otherPartial = Buffer.from(JSON.stringify({ received_at: '2026-04-27T10:00:00Z' }), 'utf8').toString('base64');
    expect(b._decodeCursor(otherPartial)).toBeNull();
  });

  it('decodeCursor rejects non-string field types', () => {
    const numericId = Buffer.from(JSON.stringify({ received_at: '2026-04-27T10:00:00Z', id: 42 }), 'utf8').toString('base64');
    expect(b._decodeCursor(numericId)).toBeNull();
  });

  it('encoded cursors are URL-safe base64-ish (no whitespace, no quotes)', () => {
    const encoded = b._encodeCursor('2026-04-27T10:00:00Z', '0195e3a1-2b3c-7d4e-8f5a-6b7c8d9e0f1a');
    // Base64 alphabet plus padding
    expect(encoded).toMatch(/^[A-Za-z0-9+/=]+$/);
  });
});
