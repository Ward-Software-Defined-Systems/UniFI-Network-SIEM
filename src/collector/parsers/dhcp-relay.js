// Parses DHCP relay messages from ECS switches
// Format: dhcp_relay#dhcpsnpd[34]: ACK received: ifname Ethernet46, src_ip 172.16.4.254, src_mac 60:22:32:80:f9:e0, chaddr aa:7f:aa:f3:bc:29, yiaddr 172.16.4.67.
// Format: dhcp_relay#dhcpsnpd[34]: DHCP packet with source IP 0.0.0.0 received on VLAN 4

const ACK_RE = /ACK received:\s+ifname\s+(\S+),\s+src_ip\s+(\d+\.\d+\.\d+\.\d+),\s+src_mac\s+([0-9a-f:]+),\s+chaddr\s+([0-9a-f:]+),\s+yiaddr\s+(\d+\.\d+\.\d+\.\d+)/i;
const DHCP_PACKET_RE = /DHCP (\w+) packet received on VLAN (\d+)/i;
const DHCP_SRC_RE = /DHCP packet with source IP (\S+) received on VLAN (\d+)/i;

function parseDhcpRelay(message, header) {
  const ackMatch = message.match(ACK_RE);
  if (ackMatch) {
    return {
      event_type: 'dhcp',
      source_format: 'dhcp-relay',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      dhcp_action: 'DHCPACK',
      dhcp_interface: ackMatch[1],
      dhcp_ip: ackMatch[5],
      dhcp_mac: ackMatch[4],
      message: `DHCPACK relay ${ackMatch[5]} ${ackMatch[4]} via ${ackMatch[1]}`,
    };
  }

  const packetMatch = message.match(DHCP_PACKET_RE) || message.match(DHCP_SRC_RE);
  if (packetMatch) {
    return {
      event_type: 'dhcp',
      source_format: 'dhcp-relay',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      dhcp_interface: `VLAN${packetMatch[2]}`,
      message: message.replace(/.*dhcpsnpd\[\d+\]:\s*/, ''),
    };
  }

  return {
    event_type: 'dhcp',
    source_format: 'dhcp-relay',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    message: message.replace(/.*dhcpsnpd\[\d+\]:\s*/, ''),
  };
}

module.exports = { parseDhcpRelay };
