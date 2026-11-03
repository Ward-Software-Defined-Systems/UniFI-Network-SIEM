// Tests for the WardSONDB rollup `_id` helpers. WardSONDB refuses ids that
// carry a path separator or a control character (400 INVALID_DOCUMENT; a
// per-doc drop inside `_bulk`), and the sig rollup key is raw IDS signature
// text — so every id segment is percent-escaped. Pure functions, no network.

const { escapeIdSegment, rollupId, MAX_ID_BYTES } = require('../../src/db/backends/wardsondb-ids');

// What WardSONDB's `segment_fault` rejects inside an id.
const WARDSONDB_FORBIDDEN = /[\/\\\u0000-\u001f\u007f-\u009f]/;

describe('escapeIdSegment', () => {
  it('is the identity for clean rollup keys (existing ids stay byte-identical)', () => {
    const clean = [
      '2026-11-02T19:00:00Z',
      'firewall', 'block', '',
      '203.0.113.9', '2001:db8::1', 'src',
      'aa:bb:cc:dd:ee:ff', '443', 'TCP',
      'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)',
      'Attempted Information Leak', '(no signature)',
      'ET POLICY "quoted" & <angled> ~tilde~ #hash ?query',
    ];
    for (const s of clean) expect(escapeIdSegment(s)).toBe(s);
  });

  it('escapes path separators, percent and control characters as %XX', () => {
    expect(escapeIdSegment('ET WEB_SERVER /etc/passwd Detected in URI'))
      .toBe('ET WEB_SERVER %2Fetc%2Fpasswd Detected in URI');
    expect(escapeIdSegment('a\\b')).toBe('a%5Cb');
    expect(escapeIdSegment('100%')).toBe('100%25');
    expect(escapeIdSegment('tab\there')).toBe('tab%09here');
    expect(escapeIdSegment('nul\u0000')).toBe('nul%00');
    expect(escapeIdSegment('del\u007f')).toBe('del%7F');
    expect(escapeIdSegment('nel\u0085')).toBe('nel%85');
    expect(escapeIdSegment('apc\u009f')).toBe('apc%9F');
  });

  it('never emits a character WardSONDB refuses', () => {
    const everyControl = [];
    for (let cp = 0; cp <= 0x9f; cp++) everyControl.push(String.fromCharCode(cp));
    const hostile = everyControl.join('') + '/\\%' + 'ET WEB_SPECIFIC_APPS ../../wp-login.php \\x0d\\x0a';
    const escaped = escapeIdSegment(hostile);
    expect(escaped).not.toMatch(WARDSONDB_FORBIDDEN);
    // Printable ASCII above the control range passes through untouched.
    expect(escapeIdSegment(' !"#$&\'()*+,-.:;<=>?@[]^_`{|}~')).toBe(' !"#$&\'()*+,-.:;<=>?@[]^_`{|}~');
  });

  it('stays injective: a literal %2F differs from an escaped slash', () => {
    expect(escapeIdSegment('a/b')).not.toBe(escapeIdSegment('a%2Fb'));
    expect(escapeIdSegment('a%2Fb')).toBe('a%252Fb');
  });

  it('stringifies non-string segments and treats null/undefined as empty', () => {
    expect(escapeIdSegment(443)).toBe('443');
    expect(escapeIdSegment(null)).toBe('');
    expect(escapeIdSegment(undefined)).toBe('');
  });
});

describe('rollupId', () => {
  const bucket = '2026-11-02T19:00:00Z';
  const flushId = '1762140000000-7';

  it('builds bucket|segments|suffix with escaped segments', () => {
    expect(rollupId(bucket, ['ET WEB_SERVER /etc/passwd', 'Web Application Attack'], flushId))
      .toBe('2026-11-02T19:00:00Z|ET WEB_SERVER %2Fetc%2Fpasswd|Web Application Attack|1762140000000-7');
  });

  it('matches the pre-escape id scheme byte-for-byte for clean keys', () => {
    expect(rollupId(bucket, ['firewall', 'block'], flushId)).toBe(`${bucket}|firewall|block|${flushId}`);
    expect(rollupId(bucket, ['203.0.113.9', 'src'], 'c')).toBe(`${bucket}|203.0.113.9|src|c`);
    expect(rollupId(bucket, [443, 'TCP'], 'c')).toBe(`${bucket}|443|TCP|c`);
    expect(rollupId(bucket, ['aa:bb:cc:dd:ee:ff'], 'c')).toBe(`${bucket}|aa:bb:cc:dd:ee:ff|c`);
  });

  it('gives the delta and the canonical of one key the same natural-key prefix', () => {
    const delta = rollupId(bucket, ['ET WEB_SERVER /etc/passwd', 'cls'], flushId);
    const canonical = rollupId(bucket, ['ET WEB_SERVER /etc/passwd', 'cls'], 'c');
    expect(delta.endsWith(`|${flushId}`)).toBe(true);
    expect(canonical.endsWith('|c')).toBe(true);
    expect(delta.slice(0, -flushId.length)).toBe(canonical.slice(0, -1));
  });

  it('hashes an over-long key part and stays under the 512-byte cap, deterministically', () => {
    const long = 'ET HUNTING ' + 'x'.repeat(600);
    const id = rollupId(bucket, [long, 'cls'], flushId);
    expect(Buffer.byteLength(id, 'utf8')).toBeLessThan(MAX_ID_BYTES);
    expect(id).toMatch(/^2026-11-02T19:00:00Z\|#[0-9a-f]{64}\|1762140000000-7$/);
    expect(rollupId(bucket, [long, 'cls'], flushId)).toBe(id);
    // The hash decision is made on the key part alone, so the canonical agrees.
    expect(rollupId(bucket, [long, 'cls'], 'c')).toBe(id.slice(0, -flushId.length) + 'c');
    // A different long key hashes differently.
    expect(rollupId(bucket, [long + 'y', 'cls'], flushId)).not.toBe(id);
  });

  it('never produces an id WardSONDB would refuse', () => {
    const nasty = ['/\\\u0000\u001f\u007f\u0085', 'a/b', '..', '.', ''];
    for (const seg of nasty) {
      const id = rollupId(bucket, [seg, 'cls'], flushId);
      expect(id).not.toMatch(WARDSONDB_FORBIDDEN);
      expect(id).not.toBe('.');
      expect(id).not.toBe('..');
    }
  });
});
