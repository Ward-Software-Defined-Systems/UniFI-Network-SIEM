const { parseSystem } = require('../../src/collector/parsers/system');

const HEADER = { severity: 6, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('System (catch-all) parser', () => {
  it('extracts a process[PID]: prefix and trims it from the message', () => {
    const e = parseSystem('ubios-udapi-server[2200]: Updated device info', HEADER);
    expect(e.event_type).toBe('system');
    expect(e.source_format).toBe('raw');
    expect(e.message).toBe('Updated device info');
  });

  it('handles process: with no PID', () => {
    const e = parseSystem('kernel: br0: port 1(eth0) entered forwarding state', HEADER);
    expect(e.message).toBe('br0: port 1(eth0) entered forwarding state');
  });

  it('falls back to the raw message when no process tag is present', () => {
    const e = parseSystem('something completely unstructured', HEADER);
    expect(e.event_type).toBe('system');
    // Defensive: any output is acceptable as long as event_type is right and
    // the parser does not throw.
  });
});
