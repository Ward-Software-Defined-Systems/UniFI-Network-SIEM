// Parses Suricata IDS/IPS alerts
// Format: suricata[PID]: [1:2027865:3] ET INFO ... [**] [Classification: ...] [Priority: N] {PROTO} src:port -> dst:port

const SURICATA_RE = /\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)/;

function parseIds(message, header) {
  const match = message.match(SURICATA_RE);
  if (!match) {
    return {
      event_type: 'threat',
      source_format: 'suricata',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      message: message,
    };
  }

  return {
    event_type: 'threat',
    source_format: 'suricata',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    ids_signature_id: `${match[1]}:${match[2]}:${match[3]}`,
    ids_signature: match[4],
    ids_classification: match[5],
    ids_priority: parseInt(match[6], 10),
    protocol: match[7],
    src_ip: match[8],
    src_port: parseInt(match[9], 10),
    dst_ip: match[10],
    dst_port: parseInt(match[11], 10),
    action: 'block',
    message: match[4],
  };
}

module.exports = { parseIds };
