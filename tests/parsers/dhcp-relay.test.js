const { parseDhcpRelay } = require('../../src/collector/parsers/dhcp-relay');

const HEADER = { severity: 6, hostname: 'WSDS-ECS-Agg', timestamp: 'Mar  5 13:08:27' };

describe('DHCP relay (switch dhcpsnpd) parser', () => {
  it('parses an ACK received line with full ifname/src/chaddr/yiaddr', () => {
    const msg = 'dhcp_relay#dhcpsnpd[34]: ACK received: ifname Ethernet46, src_ip 172.16.4.254, src_mac 60:22:32:80:f9:e0, chaddr aa:bb:cc:dd:ee:ff, yiaddr 172.16.4.67.';
    const e = parseDhcpRelay(msg, HEADER);
    expect(e.event_type).toBe('dhcp');
    expect(e.source_format).toBe('dhcp-relay');
    expect(e.dhcp_action).toBe('DHCPACK');
    expect(e.dhcp_interface).toBe('Ethernet46');
    expect(e.dhcp_ip).toBe('172.16.4.67');
    expect(e.dhcp_mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('parses a DHCP packet on VLAN line', () => {
    const msg = 'dhcp_relay#dhcpsnpd[34]: DHCP packet with source IP 0.0.0.0 received on VLAN 4';
    const e = parseDhcpRelay(msg, HEADER);
    expect(e.event_type).toBe('dhcp');
    expect(e.source_format).toBe('dhcp-relay');
    expect(e.dhcp_interface).toBe('VLAN4');
  });

  it('falls back to a generic relay event for unmatched formats', () => {
    const msg = 'dhcp_relay#dhcpsnpd[34]: some untracked message';
    const e = parseDhcpRelay(msg, HEADER);
    expect(e.event_type).toBe('dhcp');
    expect(e.source_format).toBe('dhcp-relay');
    expect(e.message).toBe('some untracked message');
  });
});
