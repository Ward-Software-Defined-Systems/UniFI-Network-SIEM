const { parseIds } = require('../../src/collector/parsers/ids');

const HEADER = { severity: 1, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('IDS (Suricata) parser', () => {
  it('classifies a real Suricata alert as a threat with full IDS fields', () => {
    const msg = 'suricata[1234]: [1:2027865:3] ET INFO Observed DNS Query to .cloud TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 172.16.4.10:55555 -> 1.1.1.1:53';
    const e = parseIds(msg, HEADER);
    expect(e.event_type).toBe('threat');
    expect(e.source_format).toBe('suricata');
    expect(e.action).toBe('block');
    expect(e.ids_signature_id).toBe('1:2027865:3');
    expect(e.ids_signature).toBe('ET INFO Observed DNS Query to .cloud TLD');
    expect(e.ids_classification).toBe('Potentially Bad Traffic');
    expect(e.ids_priority).toBe(2);
    expect(e.protocol).toBe('UDP');
    expect(e.src_ip).toBe('172.16.4.10');
    expect(e.src_port).toBe(55555);
    expect(e.dst_ip).toBe('1.1.1.1');
    expect(e.dst_port).toBe(53);
  });

  it('Suricata system messages (no alert structure) are classified as system, not threat', () => {
    const msg = 'suricata[1234]: This is not an alert, just a startup or rule reload message';
    const e = parseIds(msg, HEADER);
    expect(e.event_type).toBe('system');
    expect(e.source_format).toBe('suricata');
    // No IDS fields should be set
    expect(e.ids_signature).toBeUndefined();
    expect(e.ids_signature_id).toBeUndefined();
  });

  it('does not throw on malformed input', () => {
    expect(() => parseIds('suricata[1234]:', HEADER)).not.toThrow();
    expect(() => parseIds('', HEADER)).not.toThrow();
  });
});
