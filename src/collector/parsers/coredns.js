// Parses CoreDNS JSON log messages (ad-block and content filtering)
// Format: coredns[PID]: {"timestamp":"...","type":"dnsAdBlock","category":"ADVERTISEMENT","domain":"...","ip":"...","mac":"...","src_ip":"...","src_port":N,"dst_ip":"...","dst_port":N,"protocol":"..."}

function parseCoreDns(message, header) {
  // Extract JSON from after "coredns[PID]: "
  const jsonStart = message.indexOf('{');
  if (jsonStart === -1) {
    return {
      event_type: 'dns_filter',
      source_format: 'coredns',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      message: message,
    };
  }

  let data;
  try {
    data = JSON.parse(message.slice(jsonStart));
  } catch {
    return {
      event_type: 'dns_filter',
      source_format: 'coredns',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      message: message,
    };
  }

  return {
    event_type: 'dns_filter',
    source_format: 'coredns',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: data.timestamp || header.timestamp,
    dns_name: data.domain || null,
    dns_action: 'blocked',
    dns_filter_type: data.type || null,       // dnsAdBlock, contentFilteringBlock
    dns_filter_category: data.category || null, // ADVERTISEMENT, ANONYMIZERS, etc.
    dns_client_ip: data.ip || data.src_ip || null,
    client_mac: data.mac || null,
    src_ip: data.src_ip || null,
    src_port: data.src_port || null,
    dst_ip: data.dst_ip || null,
    dst_port: data.dst_port || null,
    protocol: data.protocol ? data.protocol.toUpperCase() : null,
    action: 'block',
    message: `${data.type}: ${data.domain} (${data.category}) from ${data.ip || data.src_ip}`,
  };
}

module.exports = { parseCoreDns };
