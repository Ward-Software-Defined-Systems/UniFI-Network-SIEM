// Parses dnsmasq DNS query/reply messages (if DNS logging is enabled)
// Format: dnsmasq[PID]: query[A] google.com from 192.168.1.100
// Format: dnsmasq[PID]: reply google.com is 142.250.80.46
// Format: dnsmasq[PID]: forwarded google.com to 1.1.1.1

const QUERY_RE = /dnsmasq\[\d+\]:\s+query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/;
const REPLY_RE = /dnsmasq\[\d+\]:\s+reply\s+(\S+)\s+is\s+(\S+)/;
const FORWARD_RE = /dnsmasq\[\d+\]:\s+forwarded\s+(\S+)\s+to\s+(\S+)/;

function parseDns(message, header) {
  const queryMatch = message.match(QUERY_RE);
  if (queryMatch) {
    return {
      event_type: 'dns',
      source_format: 'dnsmasq',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      dns_action: 'query',
      dns_type: queryMatch[1],
      dns_name: queryMatch[2],
      dns_client_ip: queryMatch[3],
      message: `query[${queryMatch[1]}] ${queryMatch[2]} from ${queryMatch[3]}`,
    };
  }

  const replyMatch = message.match(REPLY_RE);
  if (replyMatch) {
    return {
      event_type: 'dns',
      source_format: 'dnsmasq',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      dns_action: 'reply',
      dns_name: replyMatch[1],
      dns_result: replyMatch[2],
      message: `reply ${replyMatch[1]} is ${replyMatch[2]}`,
    };
  }

  const fwdMatch = message.match(FORWARD_RE);
  if (fwdMatch) {
    return {
      event_type: 'dns',
      source_format: 'dnsmasq',
      severity: header.severity,
      hostname: header.hostname,
      timestamp: header.timestamp,
      dns_action: 'forwarded',
      dns_name: fwdMatch[1],
      dst_ip: fwdMatch[2],
      message: `forwarded ${fwdMatch[1]} to ${fwdMatch[2]}`,
    };
  }

  return {
    event_type: 'dns',
    source_format: 'dnsmasq',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    message: message.replace(/.*dnsmasq\[\d+\]:\s*/, ''),
  };
}

module.exports = { parseDns };
