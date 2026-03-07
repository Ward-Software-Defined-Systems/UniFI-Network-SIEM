// Parses dnsmasq-dhcp messages from gateway
// Format: dnsmasq-dhcp[PID]: DHCPACK(br4) 172.16.4.67 aa:7f:aa:f3:bc:29 hostname
// Also handles: "Updating leases", "DHCP, IP range", "not giving name" etc.

// Standard DHCP action: DHCPACK(iface) IP MAC [hostname]
const DHCP_ACTION_RE = /dnsmasq-dhcp\[\d+\]:\s+(DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPRELEASE|DHCPNAK|DHCPINFORM)\((\S+)\)\s+(\d+\.\d+\.\d+\.\d+)?\s*([0-9a-f:]{17})?\s*(.*)?/i;

function parseDhcp(message, header) {
  const match = message.match(DHCP_ACTION_RE);
  if (!match) {
    // Non-action DHCP messages (debug info, lease updates)
    return {
      event_type: 'dhcp',
      source_format: 'dnsmasq',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      message: message.replace(/.*dnsmasq-dhcp\[\d+\]:\s*/, ''),
    };
  }

  return {
    event_type: 'dhcp',
    source_format: 'dnsmasq',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    dhcp_action: match[1],
    dhcp_interface: match[2],
    dhcp_ip: match[3] || null,
    dhcp_mac: match[4] || null,
    dhcp_hostname: match[5] ? match[5].trim() : null,
    message: `${match[1]} ${match[3] || ''} ${match[4] || ''} ${match[5] || ''}`.trim(),
  };
}

module.exports = { parseDhcp };
