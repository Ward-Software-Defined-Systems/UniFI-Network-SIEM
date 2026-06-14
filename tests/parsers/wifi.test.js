const { parseWifi } = require('../../src/collector/parsers/wifi');

const HEADER = { severity: 6, hostname: 'WSDS-U7-ProWA', timestamp: 'Mar  5 13:08:27' };

describe('WiFi (hostapd) parser', () => {
  it('parses an IEEE 802.11 association', () => {
    const e = parseWifi('hostapd[10034]: wifi2ap6: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated (aid 1)', HEADER);
    expect(e.event_type).toBe('wifi');
    expect(e.source_format).toBe('hostapd');
    expect(e.wifi_radio).toBe('wifi2ap6');
    expect(e.wifi_client_mac).toBe('aa:bb:cc:dd:ee:ff');
    expect(e.wifi_action).toBe('associated (aid 1)');
  });

  it('parses an IEEE 802.11 disassociation', () => {
    const e = parseWifi('hostapd[10034]: wifi2ap6: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated', HEADER);
    expect(e.wifi_action).toBe('disassociated');
  });

  it('parses AP-STA-CONNECTED', () => {
    const e = parseWifi('hostapd[10035]: wifi2ap6: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff', HEADER);
    expect(e.wifi_action).toBe('connected');
    expect(e.wifi_client_mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('parses AP-STA-DISCONNECTED', () => {
    const e = parseWifi('hostapd[10035]: wifi2ap6: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:ff', HEADER);
    expect(e.wifi_action).toBe('disconnected');
  });

  it('parses a WPA handshake event', () => {
    const e = parseWifi('hostapd[10034]: wifi2ap6: STA aa:bb:cc:dd:ee:ff WPA: pairwise key handshake completed (RSN)', HEADER);
    expect(e.wifi_action).toBe('handshake');
    expect(e.wifi_client_mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('falls back to a generic hostapd event for unmatched formats', () => {
    const e = parseWifi('hostapd[10034]: wifi2ap6: some other line', HEADER);
    expect(e.event_type).toBe('wifi');
    expect(e.wifi_action).toBeUndefined();
  });
});
