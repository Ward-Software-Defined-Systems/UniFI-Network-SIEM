const {
  align5m, align1h, accumulateRollups, mergeRollups, newRollupBuffers,
} = require('../../src/db/rollups');

describe('rollups — bucket alignment', () => {
  it('align5m floors to a 5-minute boundary', () => {
    expect(align5m('2026-04-27T15:07:42.123Z')).toBe('2026-04-27T15:05:00.000Z');
    expect(align5m('2026-04-27T15:00:00.000Z')).toBe('2026-04-27T15:00:00.000Z');
    expect(align5m('2026-04-27T15:04:59.999Z')).toBe('2026-04-27T15:00:00.000Z');
  });
  it('align1h floors to the hour', () => {
    expect(align1h('2026-04-27T15:42:13.456Z')).toBe('2026-04-27T15:00:00.000Z');
    expect(align1h('2026-04-27T15:00:00.000Z')).toBe('2026-04-27T15:00:00.000Z');
  });
  it('alignXm() with no argument uses now (returns a valid ISO string)', () => {
    expect(align5m()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/);
    expect(align1h()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/);
  });
});

describe('accumulateRollups', () => {
  it('returns empty maps for an empty event list', () => {
    const r = accumulateRollups([]);
    expect(r.fiveMin.size).toBe(0);
    expect(r.ipHourly.size).toBe(0);
    expect(r.portHourly.size).toBe(0);
    expect(r.sigHourly.size).toBe(0);
    expect(r.clientHourly.size).toBe(0);
  });

  it('5m: groups by (bucket, event_type, action) and counts', () => {
    const e = (received_at, event_type, action) => ({ received_at, event_type, action });
    const r = accumulateRollups([
      e('2026-04-27T15:00:00Z', 'firewall', 'allow'),
      e('2026-04-27T15:02:00Z', 'firewall', 'allow'),
      e('2026-04-27T15:00:00Z', 'firewall', 'block'),
      e('2026-04-27T15:05:00Z', 'firewall', 'allow'),  // different 5m bucket
    ]);
    expect(r.fiveMin.size).toBe(3);
    expect(r.fiveMin.get('2026-04-27T15:00:00.000Z|firewall|allow').count).toBe(2);
    expect(r.fiveMin.get('2026-04-27T15:00:00.000Z|firewall|block').count).toBe(1);
    expect(r.fiveMin.get('2026-04-27T15:05:00.000Z|firewall|allow').count).toBe(1);
  });

  it('IP hourly: src + dst both contribute, blocked/threat counters track action/type', () => {
    const e = {
      received_at: '2026-04-27T15:30:00Z',
      event_type: 'firewall', action: 'block',
      src_ip: '8.8.8.8', dst_ip: '172.16.4.10',
    };
    const r = accumulateRollups([e, e]);
    const src = r.ipHourly.get('2026-04-27T15:00:00.000Z|8.8.8.8|src');
    const dst = r.ipHourly.get('2026-04-27T15:00:00.000Z|172.16.4.10|dst');
    expect(src).toEqual({
      bucket: '2026-04-27T15:00:00.000Z', ip: '8.8.8.8', direction: 'src',
      event_count: 2, blocked_count: 2, threat_count: 0,
    });
    expect(dst).toEqual({
      bucket: '2026-04-27T15:00:00.000Z', ip: '172.16.4.10', direction: 'dst',
      event_count: 2, blocked_count: 2, threat_count: 0,
    });
  });

  it('threat events bump threat_count on the IP rollup AND populate sigHourly', () => {
    const r = accumulateRollups([{
      received_at: '2026-04-27T15:00:00Z',
      event_type: 'threat', action: 'block',
      src_ip: '1.2.3.4', dst_ip: '172.16.4.1',
      ids_signature: 'ET INFO Test', ids_classification: 'Bad',
    }]);
    const src = r.ipHourly.get('2026-04-27T15:00:00.000Z|1.2.3.4|src');
    expect(src.threat_count).toBe(1);
    expect(src.blocked_count).toBe(1);
    const sig = r.sigHourly.get('2026-04-27T15:00:00.000Z|ET INFO Test|Bad');
    expect(sig.count).toBe(1);
  });

  it('threat without ids_signature gets the "(no signature)" fallback', () => {
    const r = accumulateRollups([{
      received_at: '2026-04-27T15:00:00Z',
      event_type: 'threat',
    }]);
    const sig = [...r.sigHourly.values()][0];
    expect(sig.signature).toBe('(no signature)');
    expect(sig.count).toBe(1);
  });

  it('non-threat events do NOT contribute to sigHourly', () => {
    const r = accumulateRollups([{
      received_at: '2026-04-27T15:00:00Z',
      event_type: 'firewall',
      ids_signature: 'should not appear',
    }]);
    expect(r.sigHourly.size).toBe(0);
  });

  it('portHourly groups by (bucket, dst_port, protocol)', () => {
    const r = accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', dst_port: 443, protocol: 'TCP' },
      { received_at: '2026-04-27T15:00:00Z', dst_port: 443, protocol: 'TCP' },
      { received_at: '2026-04-27T15:00:00Z', dst_port: 53, protocol: 'UDP' },
    ]);
    expect(r.portHourly.get('2026-04-27T15:00:00.000Z|443|TCP').count).toBe(2);
    expect(r.portHourly.get('2026-04-27T15:00:00.000Z|53|UDP').count).toBe(1);
  });

  it('events without dst_port skip portHourly', () => {
    const r = accumulateRollups([{ received_at: '2026-04-27T15:00:00Z', event_type: 'wifi' }]);
    expect(r.portHourly.size).toBe(0);
  });

  it('clientHourly uses first-non-null MAC fallback (client_mac > wifi_client_mac > dhcp_mac)', () => {
    const r = accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall', client_mac: 'aa:bb:cc:dd:ee:01' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'wifi', wifi_client_mac: 'aa:bb:cc:dd:ee:02' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'dhcp', dhcp_mac: 'aa:bb:cc:dd:ee:03' },
      // Both wifi_client_mac and dhcp_mac present — wifi wins
      { received_at: '2026-04-27T15:00:00Z', event_type: 'wifi',
        wifi_client_mac: 'aa:bb:cc:dd:ee:04', dhcp_mac: 'should-not-be-used' },
    ]);
    expect(r.clientHourly.size).toBe(4);
    const c1 = r.clientHourly.get('2026-04-27T15:00:00.000Z|aa:bb:cc:dd:ee:01');
    expect(c1).toMatchObject({ event_count: 1, firewall_count: 1, wifi_count: 0, dhcp_count: 0 });
  });

  it('clientHourly pivots event_type into wifi/dhcp/firewall counts', () => {
    const r = accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', event_type: 'wifi', client_mac: 'mac1' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'wifi', client_mac: 'mac1' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall', client_mac: 'mac1' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'dhcp', client_mac: 'mac1' },
      // 'system' (or anything else) only bumps event_count
      { received_at: '2026-04-27T15:00:00Z', event_type: 'system', client_mac: 'mac1' },
    ]);
    const c = r.clientHourly.get('2026-04-27T15:00:00.000Z|mac1');
    expect(c).toMatchObject({
      event_count: 5, wifi_count: 2, dhcp_count: 1, firewall_count: 1,
    });
  });

  it('events without received_at default to now (still produce a bucket key)', () => {
    const r = accumulateRollups([{ event_type: 'firewall', action: 'allow' }]);
    expect(r.fiveMin.size).toBe(1);
  });

  it('events with invalid received_at are silently skipped', () => {
    const r = accumulateRollups([
      { received_at: 'not-a-date', event_type: 'firewall' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall' },
    ]);
    expect(r.fiveMin.size).toBe(1);
  });

  it('events with empty event_type get the "unknown" fallback', () => {
    const r = accumulateRollups([{ received_at: '2026-04-27T15:00:00Z' }]);
    expect([...r.fiveMin.values()][0].event_type).toBe('unknown');
  });

  it('aggregates correctly across multiple buckets', () => {
    const r = accumulateRollups([
      { received_at: '2026-04-27T14:30:00Z', event_type: 'firewall', src_ip: '1.1.1.1', action: 'block' },
      { received_at: '2026-04-27T15:30:00Z', event_type: 'firewall', src_ip: '1.1.1.1', action: 'block' },
    ]);
    // Two distinct hourly buckets for the same src_ip
    expect(r.ipHourly.size).toBe(2);
    expect(r.ipHourly.get('2026-04-27T14:00:00.000Z|1.1.1.1|src').event_count).toBe(1);
    expect(r.ipHourly.get('2026-04-27T15:00:00.000Z|1.1.1.1|src').event_count).toBe(1);
  });
});

describe('mergeRollups', () => {
  it('sums counts on existing keys, adds new keys verbatim', () => {
    const target = newRollupBuffers();
    const a = accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall', action: 'allow', src_ip: '1.1.1.1' },
    ]);
    const b = accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall', action: 'allow', src_ip: '1.1.1.1' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall', action: 'allow', src_ip: '2.2.2.2' },
    ]);
    mergeRollups(target, a);
    mergeRollups(target, b);

    expect(target.fiveMin.get('2026-04-27T15:00:00.000Z|firewall|allow').count).toBe(3);
    expect(target.ipHourly.get('2026-04-27T15:00:00.000Z|1.1.1.1|src').event_count).toBe(2);
    expect(target.ipHourly.get('2026-04-27T15:00:00.000Z|2.2.2.2|src').event_count).toBe(1);
  });

  it('preserves blocked_count + threat_count on merge', () => {
    const target = newRollupBuffers();
    const e = { received_at: '2026-04-27T15:00:00Z', event_type: 'threat', action: 'block', src_ip: '8.8.8.8' };
    mergeRollups(target, accumulateRollups([e, e]));
    mergeRollups(target, accumulateRollups([e]));
    const r = target.ipHourly.get('2026-04-27T15:00:00.000Z|8.8.8.8|src');
    expect(r.event_count).toBe(3);
    expect(r.blocked_count).toBe(3);
    expect(r.threat_count).toBe(3);
  });

  it('clientHourly merges all four counters', () => {
    const target = newRollupBuffers();
    mergeRollups(target, accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', event_type: 'wifi', client_mac: 'mac1' },
      { received_at: '2026-04-27T15:00:00Z', event_type: 'dhcp', client_mac: 'mac1' },
    ]));
    mergeRollups(target, accumulateRollups([
      { received_at: '2026-04-27T15:00:00Z', event_type: 'firewall', client_mac: 'mac1' },
    ]));
    const c = target.clientHourly.get('2026-04-27T15:00:00.000Z|mac1');
    expect(c).toMatchObject({ event_count: 3, wifi_count: 1, dhcp_count: 1, firewall_count: 1 });
  });
});

describe('newRollupBuffers', () => {
  it('returns five empty maps with the expected names', () => {
    const b = newRollupBuffers();
    expect(b.fiveMin instanceof Map).toBe(true);
    expect(b.ipHourly instanceof Map).toBe(true);
    expect(b.portHourly instanceof Map).toBe(true);
    expect(b.sigHourly instanceof Map).toBe(true);
    expect(b.clientHourly instanceof Map).toBe(true);
    expect(b.fiveMin.size).toBe(0);
  });
  it('returns a fresh object each call (no shared state)', () => {
    const a = newRollupBuffers();
    const b = newRollupBuffers();
    a.fiveMin.set('x', 1);
    expect(b.fiveMin.has('x')).toBe(false);
  });
});
