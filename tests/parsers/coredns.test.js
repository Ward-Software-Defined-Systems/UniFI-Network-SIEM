const { parseCoreDns } = require('../../src/collector/parsers/coredns');

const HEADER = { severity: 5, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('CoreDNS parser', () => {
  it('parses a dnsAdBlock JSON event', () => {
    const json = JSON.stringify({
      timestamp: '2026-04-27T10:00:00Z',
      type: 'dnsAdBlock',
      category: 'ADVERTISEMENT',
      domain: 'ads.example.com',
      ip: '172.16.4.10',
      mac: 'aa:bb:cc:dd:ee:ff',
      src_ip: '172.16.4.10',
      src_port: 54321,
      dst_ip: '127.0.0.1',
      dst_port: 1053,
      protocol: 'udp',
    });
    const e = parseCoreDns(`coredns[2464464]: ${json}`, HEADER);
    expect(e.event_type).toBe('dns_filter');
    expect(e.source_format).toBe('coredns');
    expect(e.dns_filter_type).toBe('dnsAdBlock');
    expect(e.dns_filter_category).toBe('ADVERTISEMENT');
    expect(e.dns_name).toBe('ads.example.com');
    expect(e.action).toBe('block');
    expect(e.protocol).toBe('UDP');
    expect(e.dns_action).toBe('blocked');
  });

  it('parses a contentFilteringBlock event', () => {
    const json = JSON.stringify({
      type: 'contentFilteringBlock',
      category: 'ANONYMIZERS',
      domain: 'download.wireguard.com',
      ip: '172.16.8.5',
      mac: 'aa:bb:cc:dd:ee:00',
      src_ip: '172.16.8.5',
      src_port: 33333,
      dst_ip: '127.0.0.1',
      dst_port: 1053,
      protocol: 'udp',
    });
    const e = parseCoreDns(`coredns[2464464]: ${json}`, HEADER);
    expect(e.dns_filter_type).toBe('contentFilteringBlock');
    expect(e.dns_filter_category).toBe('ANONYMIZERS');
    expect(e.dns_name).toBe('download.wireguard.com');
  });

  it('falls back gracefully on malformed JSON', () => {
    const e = parseCoreDns('coredns[1]: {not valid json}', HEADER);
    expect(e.event_type).toBe('dns_filter');
    expect(e.source_format).toBe('coredns');
    expect(e.dns_name).toBeUndefined();
  });
});
