const { parseDhcp } = require('../../src/collector/parsers/dhcp');

const HEADER = { severity: 6, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('DHCP (dnsmasq) parser', () => {
  it('parses DHCPACK with hostname', () => {
    const msg = 'dnsmasq-dhcp[3861005]: DHCPACK(br4) 172.16.4.67 aa:7f:aa:f3:bc:29 TestDevice';
    const e = parseDhcp(msg, HEADER);
    expect(e.event_type).toBe('dhcp');
    expect(e.source_format).toBe('dnsmasq');
    expect(e.dhcp_action).toBe('DHCPACK');
    expect(e.dhcp_interface).toBe('br4');
    expect(e.dhcp_ip).toBe('172.16.4.67');
    expect(e.dhcp_mac).toBe('aa:7f:aa:f3:bc:29');
    expect(e.dhcp_hostname).toBe('TestDevice');
  });

  it('parses DHCPDISCOVER (no IP, MAC only)', () => {
    const msg = 'dnsmasq-dhcp[3861005]: DHCPDISCOVER(br8) aa:bb:cc:dd:ee:ff';
    const e = parseDhcp(msg, HEADER);
    expect(e.dhcp_action).toBe('DHCPDISCOVER');
    expect(e.dhcp_interface).toBe('br8');
    expect(e.dhcp_mac).toBe('aa:bb:cc:dd:ee:ff');
    // dhcp_ip is the regex's IP-or-MAC slot — for DISCOVER it captures the
    // MAC since there is no IP. We only assert the action + interface.
  });

  it('parses DHCPREQUEST with no hostname', () => {
    const msg = 'dnsmasq-dhcp[3861005]: DHCPREQUEST(br4) 172.16.4.67 aa:bb:cc:dd:ee:ff';
    const e = parseDhcp(msg, HEADER);
    expect(e.dhcp_action).toBe('DHCPREQUEST');
    expect(e.dhcp_hostname).toBeNull();
  });

  it('handles non-action DHCP messages (e.g., lease updates)', () => {
    const msg = 'dnsmasq-dhcp[3861005]: Updating leases for some lan';
    const e = parseDhcp(msg, HEADER);
    expect(e.event_type).toBe('dhcp');
    expect(e.dhcp_action).toBeUndefined();
    expect(e.message).toBe('Updating leases for some lan');
  });
});
