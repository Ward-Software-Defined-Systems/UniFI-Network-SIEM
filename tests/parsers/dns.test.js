const { parseDns } = require('../../src/collector/parsers/dns');

const HEADER = { severity: 6, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('DNS (dnsmasq) parser', () => {
  it('parses a query', () => {
    const e = parseDns('dnsmasq[1]: query[A] google.com from 192.168.1.100', HEADER);
    expect(e.event_type).toBe('dns');
    expect(e.dns_action).toBe('query');
    expect(e.dns_type).toBe('A');
    expect(e.dns_name).toBe('google.com');
    expect(e.dns_client_ip).toBe('192.168.1.100');
  });

  it('parses a reply', () => {
    const e = parseDns('dnsmasq[1]: reply google.com is 142.250.80.46', HEADER);
    expect(e.dns_action).toBe('reply');
    expect(e.dns_name).toBe('google.com');
    expect(e.dns_result).toBe('142.250.80.46');
  });

  it('parses a forwarded entry', () => {
    const e = parseDns('dnsmasq[1]: forwarded google.com to 1.1.1.1', HEADER);
    expect(e.dns_action).toBe('forwarded');
    expect(e.dns_name).toBe('google.com');
    expect(e.dst_ip).toBe('1.1.1.1');
  });

  it('falls back to a generic dns event for unmatched dnsmasq lines', () => {
    const e = parseDns('dnsmasq[1]: some other dnsmasq detail line', HEADER);
    expect(e.event_type).toBe('dns');
    expect(e.dns_action).toBeUndefined();
  });
});
