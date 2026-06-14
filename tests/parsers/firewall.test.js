const { parseFirewall, isFirewallMessage } = require('../../src/collector/parsers/firewall');

const HEADER = { severity: 5, hostname: 'WSDS-UDM-SE', timestamp: 'Mar  5 13:08:27' };

describe('firewall parser', () => {
  it('parses an allow rule (intra-VLAN)', () => {
    const msg = '[LAN_CUSTOM1-A-10000] DESCR="OpNet_TO_Axiom" IN=br4 OUT=br10 MAC=60:22:32:80:f9:e0:aa:bb:cc:dd:ee:ff:08:00 SRC=172.16.4.10 DST=172.16.10.20 LEN=64 TOS=00 PREC=0x00 TTL=63 ID=0 DF PROTO=TCP SPT=54321 DPT=7000 SEQ=1 ACK=0 WINDOW=65535 SYN URGP=0 MARK=1a0000';
    const e = parseFirewall(msg, HEADER);
    expect(e.event_type).toBe('firewall');
    expect(e.source_format).toBe('iptables');
    expect(e.action).toBe('allow');
    expect(e.rule_prefix).toBe('LAN_CUSTOM1-A-10000');
    expect(e.message).toBe('OpNet_TO_Axiom');
    expect(e.interface_in).toBe('br4');
    expect(e.interface_out).toBe('br10');
    expect(e.protocol).toBe('TCP');
    expect(e.src_ip).toBe('172.16.4.10');
    expect(e.dst_ip).toBe('172.16.10.20');
    expect(e.src_port).toBe(54321);
    expect(e.dst_port).toBe(7000);
    expect(e.packet_length).toBe(64);
    expect(e.ttl).toBe(63);
    expect(e.tcp_flags).toContain('SYN');
    expect(e.direction).toBe('inter-vlan');
    expect(e.mac_dst).toBe('60:22:32:80:f9:e0');
    expect(e.mac_src).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('parses a block rule (blocked at WAN — empty OUT)', () => {
    const msg = '[WAN_CUSTOM1-D-20000] DESCR="Block_Inbound" IN=eth8 OUT= MAC=00:11:22:33:44:55 SRC=8.8.8.8 DST=172.16.8.254 LEN=44 PROTO=TCP SPT=80 DPT=22 SYN';
    const e = parseFirewall(msg, HEADER);
    expect(e.action).toBe('block');
    expect(e.rule_prefix).toBe('WAN_CUSTOM1-D-20000');
    expect(e.interface_in).toBe('eth8');
    expect(e.interface_out).toBeNull();
    expect(e.dst_port).toBe(22);
    // Real production behavior: when a firewall rule blocks an inbound packet
    // before it is routed out, OUT= is empty, and detectDirection returns
    // 'local' (since there is no out-interface to route on). The packet was
    // semantically inbound from WAN, but the parser cannot tell because the
    // routing never happened. This may warrant a follow-up: detect WAN-IN
    // with empty OUT as 'inbound' explicitly.
    expect(e.direction).toBe('local');
  });

  it('returns null for messages without a rule prefix', () => {
    expect(parseFirewall('IN=br4 SRC=172.16.4.1', HEADER)).toBeNull();
  });

  it('handles missing optional fields without throwing', () => {
    const msg = '[CUSTOM1_LAN-A-10001] IN=br4 SRC=172.16.4.1 DST=8.8.8.8';
    expect(() => parseFirewall(msg, HEADER)).not.toThrow();
    const e = parseFirewall(msg, HEADER);
    expect(e.protocol).toBeNull();
    expect(e.src_port).toBeNull();
    expect(e.dst_port).toBeNull();
    expect(e.tcp_flags).toBeNull();
  });

  describe('isFirewallMessage', () => {
    it('detects iptables format', () => {
      expect(isFirewallMessage('<13>Mar  5 13:08:27 host [WAN_CUSTOM1-A-10000] IN=br4 SRC=1.2.3.4'))
        .toBe(true);
    });
    it('rejects non-firewall messages', () => {
      expect(isFirewallMessage('<13>Mar  5 13:08:27 host hostapd[1]: foo')).toBe(false);
      expect(isFirewallMessage('')).toBe(false);
    });
  });
});
