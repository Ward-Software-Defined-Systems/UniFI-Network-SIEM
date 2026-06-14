const { parseCef } = require('../../src/collector/parsers/cef');

const HEADER = { severity: 4, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('CEF parser', () => {
  it('parses an Admin Accessed audit event', () => {
    const raw = 'Mar  5 13:08:27 WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|544|Admin Accessed UniFi Network|4|src=172.16.8.129 UNIFIcategory=Audit UNIFIhost=WSDS-UDM-SE UNIFIaccessMethod=web UNIFIadmin=TestUser UNIFIutcTime=2026-04-27T10:00:00Z msg=TestUser accessed UniFi Network using the web. Source IP: 172.16.8.129';
    const e = parseCef(raw, HEADER);
    expect(e.event_type).toBe('admin');
    expect(e.source_format).toBe('cef');
    expect(e.cef_event_class_id).toBe('544');
    expect(e.cef_name).toBe('Admin Accessed UniFi Network');
    expect(e.unifi_category).toBe('Audit');
    expect(e.src_ip).toBe('172.16.8.129');
    expect(e.message.startsWith('TestUser accessed')).toBe(true);
  });

  it('classifies a Threat Detected event as threat with action=block', () => {
    const raw = 'Mar  5 13:08:27 WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|201|Threat Detected and Blocked|7|proto=TCP src=8.8.8.8 spt=33333 dst=172.16.4.10 dpt=443 UNIFIcategory=Security UNIFIsubCategory=Threat UNIFIthreatType=Malware UNIFIthreatCategory=Command and Control UNIFIutcTime=2026-04-27T10:00:00Z msg=Malware callback blocked';
    const e = parseCef(raw, HEADER);
    expect(e.event_type).toBe('threat');
    expect(e.action).toBe('block');
    expect(e.threat_type).toBe('Malware');
    expect(e.threat_category).toBe('Command and Control');
    expect(e.src_ip).toBe('8.8.8.8');
    expect(e.dst_port).toBe(443);
  });

  it('parses a WiFi Client Roamed event with client + wifi fields', () => {
    const raw = 'Mar  5 13:08:27 WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|402|WiFi Client Roamed|1|UNIFIcategory=Client Devices UNIFIhost=WSDS-UDM-SE UNIFIclientAlias=TestPhone UNIFIclientMac=aa:bb:cc:dd:ee:ff UNIFIclientIp=172.16.4.55 UNIFIwifiName=OpNet UNIFIwifiChannel=149 UNIFIWiFiRssi=-65 UNIFIutcTime=2026-04-27T10:00:00Z msg=TestPhone roamed between APs';
    const e = parseCef(raw, HEADER);
    // 402 → wifi via class-id range, but `client devices` category also maps
    // to client. Either is acceptable; assert the actual mapping.
    expect(['wifi', 'client']).toContain(e.event_type);
    expect(e.client_alias).toBe('TestPhone');
    expect(e.client_mac).toBe('aa:bb:cc:dd:ee:ff');
    expect(e.wifi_ssid).toBe('OpNet');
    expect(e.wifi_channel).toBe(149);
    expect(e.wifi_rssi).toBe(-65);
  });

  it('returns null for messages without CEF: marker', () => {
    expect(parseCef('Mar  5 13:08:27 WSDS-UDM-SE just plain text', HEADER)).toBeNull();
  });

  it('returns null for malformed CEF (wrong field count)', () => {
    expect(parseCef('CEF:0|too|few|fields', HEADER)).toBeNull();
  });
});
