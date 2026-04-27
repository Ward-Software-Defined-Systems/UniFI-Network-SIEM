const { parseSyslogHeader } = require('../../src/collector/parsers/syslog-header');

describe('syslog header parser', () => {
  it('Format 1: standard <PRI>Mon DD HH:MM:SS HOSTNAME message', () => {
    const h = parseSyslogHeader('<13>Mar  5 13:08:27 WSDS-UDM-SE some payload here');
    expect(h.priority).toBe(13);
    expect(h.severity).toBe(5);
    expect(h.hostname).toBe('WSDS-UDM-SE');
    expect(h.timestamp).toBe('Mar  5 13:08:27');
    expect(h.message).toBe('some payload here');
    expect(h.macModel).toBeNull();
  });

  it('Format 2: hostname + MAC,Model prefix + process tag', () => {
    const h = parseSyslogHeader('<14>Mar  7 07:25:08 WSDS-U7-ProWA 28704e551ced,U7-Pro-Wall-8.5.11+18612: hostapd[10034]: payload');
    expect(h.priority).toBe(14);
    expect(h.hostname).toBe('WSDS-U7-ProWA');
    expect(h.macModel).toBe('28704e551ced,U7-Pro-Wall-8.5.11+18612');
    expect(h.message).toBe('hostapd[10034]: payload');
  });

  it('Format 3: ECS switch — MAC,Model prefix with no <PRI>, plus daemon.severity', () => {
    const h = parseSyslogHeader('942a6f40d752,ECS-Aggregation-3.0.2+821 Mar  7 07:25:08 WSDS-ECS-Agg daemon.info dhcp_relay#dhcpsnpd[34]: ACK received: ...');
    expect(h.priority).toBe(30); // daemon.info
    expect(h.severity).toBe(6);
    expect(h.macModel).toBe('942a6f40d752,ECS-Aggregation-3.0.2+821');
    expect(h.hostname).toBe('WSDS-ECS-Agg');
    expect(h.message).toBe('dhcp_relay#dhcpsnpd[34]: ACK received: ...');
  });

  it('Format 4: doubled hostname (UDM-SE quirk)', () => {
    const h = parseSyslogHeader('<30>Mar  7 07:28:23 WSDS-UDM-SE WSDS-UDM-SE dnsmasq-dhcp[3861005]: DHCPACK(br4) 172.16.4.1 aa:bb:cc:dd:ee:ff');
    expect(h.priority).toBe(30);
    expect(h.hostname).toBe('WSDS-UDM-SE');
    expect(h.message).toBe('dnsmasq-dhcp[3861005]: DHCPACK(br4) 172.16.4.1 aa:bb:cc:dd:ee:ff');
  });

  it('Format 5: bare timestamp (CEF without <PRI>)', () => {
    const h = parseSyslogHeader('Mar  7 07:26:58 WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|544|...');
    expect(h.priority).toBeNull();
    expect(h.timestamp).toBe('Mar  7 07:26:58');
    expect(h.hostname).toBe('WSDS-UDM-SE');
    expect(h.message.startsWith('CEF:0|')).toBe(true);
  });

  it('handles malformed input without throwing', () => {
    expect(() => parseSyslogHeader('')).not.toThrow();
    expect(() => parseSyslogHeader('this is not syslog at all')).not.toThrow();
    expect(() => parseSyslogHeader('<')).not.toThrow();
  });
});
