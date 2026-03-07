// Parses hostapd Wi-Fi client events
// Formats:
//   hostapd[PID]: wifi2ap6: STA ae:b0:59:e6:4f:57 IEEE 802.11: disassociated
//   hostapd[PID]: wifi2ap6: AP-STA-CONNECTED ae:b0:59:e6:4f:57
//   hostapd[PID]: wifi2ap6: AP-STA-DISCONNECTED ae:b0:59:e6:4f:57
//   hostapd[PID]: wifi2ap6: STA XX WPA: pairwise key handshake completed (RSN)

const IEEE_RE = /hostapd\[\d+\]:\s+(\S+):\s+STA\s+([0-9a-f:]{17})\s+IEEE 802\.11:\s+(.+)/i;
const AP_STA_RE = /hostapd\[\d+\]:\s+(\S+):\s+AP-STA-(CONNECTED|DISCONNECTED)\s+([0-9a-f:]{17})/i;
const WPA_RE = /hostapd\[\d+\]:\s+(\S+):\s+STA\s+([0-9a-f:]{17})\s+WPA:\s+(.+)/i;

function parseWifi(message, header) {
  // IEEE 802.11 events
  const ieeeMatch = message.match(IEEE_RE);
  if (ieeeMatch) {
    return {
      event_type: 'wifi',
      source_format: 'hostapd',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      wifi_radio: ieeeMatch[1],
      wifi_client_mac: ieeeMatch[2],
      wifi_action: ieeeMatch[3].trim(),
      message: `STA ${ieeeMatch[2]} ${ieeeMatch[3].trim()}`,
    };
  }

  // AP-STA-CONNECTED / AP-STA-DISCONNECTED
  const apStaMatch = message.match(AP_STA_RE);
  if (apStaMatch) {
    const action = apStaMatch[2] === 'CONNECTED' ? 'connected' : 'disconnected';
    return {
      event_type: 'wifi',
      source_format: 'hostapd',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      wifi_radio: apStaMatch[1],
      wifi_client_mac: apStaMatch[3],
      wifi_action: action,
      message: `STA ${apStaMatch[3]} ${action}`,
    };
  }

  // WPA handshake events
  const wpaMatch = message.match(WPA_RE);
  if (wpaMatch) {
    return {
      event_type: 'wifi',
      source_format: 'hostapd',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      wifi_radio: wpaMatch[1],
      wifi_client_mac: wpaMatch[2],
      wifi_action: 'handshake',
      message: `STA ${wpaMatch[2]} WPA: ${wpaMatch[3]}`,
    };
  }

  // Catch-all hostapd
  return {
    event_type: 'wifi',
    source_format: 'hostapd',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    message: message.replace(/.*hostapd\[\d+\]:\s*/, ''),
  };
}

module.exports = { parseWifi };
