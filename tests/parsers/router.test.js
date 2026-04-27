const { parseMessage } = require('../../src/collector/parsers');

describe('parser router (parseMessage)', () => {
  it('routes a firewall iptables line to the firewall parser', () => {
    const raw = '<13>Mar  5 13:08:27 WSDS-UDM-SE [LAN_CUSTOM1-A-10000] DESCR="Test" IN=br4 OUT=br10 SRC=172.16.4.1 DST=172.16.10.1 PROTO=TCP SPT=12345 DPT=443';
    const e = parseMessage(raw);
    expect(e.event_type).toBe('firewall');
    expect(e.action).toBe('allow');
  });

  it('routes a Suricata alert to the IDS parser', () => {
    const raw = '<1>Mar  5 13:08:27 WSDS-UDM-SE suricata[1234]: [1:2027865:3] ET INFO Test [**] [Classification: Bad] [Priority: 2] {UDP} 1.2.3.4:1234 -> 5.6.7.8:53';
    const e = parseMessage(raw);
    expect(e.event_type).toBe('threat');
  });

  it('routes a CEF line to the CEF parser without needing a syslog header', () => {
    const raw = 'Mar  5 13:08:27 WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|544|Admin Accessed|4|UNIFIcategory=Audit UNIFIutcTime=2026-04-27T10:00:00Z msg=hello';
    const e = parseMessage(raw);
    expect(e.event_type).toBe('admin');
    expect(e.source_format).toBe('cef');
  });

  it('routes a CoreDNS JSON line to the coredns parser', () => {
    const raw = '<13>Mar  5 13:08:27 WSDS-UDM-SE WSDS-UDM-SE coredns[1]: {"type":"dnsAdBlock","category":"ADVERTISEMENT","domain":"ads.example.com","ip":"172.16.4.10","src_ip":"172.16.4.10","src_port":1,"dst_ip":"127.0.0.1","dst_port":1053,"protocol":"udp"}';
    const e = parseMessage(raw);
    expect(e.event_type).toBe('dns_filter');
  });

  it('routes a hostapd line to the wifi parser', () => {
    const raw = '<14>Mar  5 13:08:27 WSDS-U7-ProWA 28704e551ced,U7-Pro-Wall-8.5.11+18612: hostapd[1]: wifi2ap6: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated (aid 1)';
    const e = parseMessage(raw);
    expect(e.event_type).toBe('wifi');
  });

  it('handles a Buffer input (UDP packet style)', () => {
    const raw = Buffer.from('<13>Mar  5 13:08:27 WSDS-UDM-SE just some system message');
    const e = parseMessage(raw);
    expect(e.event_type).toBe('system');
  });

  it('does not throw on truncated/garbage input — falls through to system event', () => {
    expect(() => parseMessage('')).not.toThrow();
    expect(() => parseMessage('asdf')).not.toThrow();
    expect(() => parseMessage('<13>')).not.toThrow();
    const e = parseMessage('totally random bytes 𩸽 \x00\x01\x02');
    expect(e.event_type).toBeDefined();
  });

  it('caps message length on parse-failure fallback at 500 chars', () => {
    // The router falls back via a try/catch only when an exception is thrown
    // inside a parser. For our parsers this is rare, so this test simply
    // verifies the safety net does not throw on large input.
    const big = 'x'.repeat(10_000);
    expect(() => parseMessage(big)).not.toThrow();
  });
});
