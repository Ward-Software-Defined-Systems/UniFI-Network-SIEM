// Parses firewall (iptables) messages from UDM-SE
// Actual format: <13>Mar  5 13:08:27 WSDS-UDM-SE [LAN_CUSTOM1-A-10000] DESCR="OpNet_TO_Axiom" IN=br4 OUT=br10 ...
// NO kernel: tag — rule prefix [RULE] comes directly after hostname

const { detectDirection } = require('../../utils/ip-utils');

// Match rule prefix like [LAN_CUSTOM1-A-10000] or [BLOCK-WAN_IN-D]
const RULE_PREFIX_RE = /\[([A-Z0-9_]+-[A-Z]-[A-Z0-9_-]*?\d*)\]/;

// Key=value pairs in iptables log
const KV_RE = /\b([A-Z]+)=(\S+)/g;

// DESCR="rule name" field
const DESCR_RE = /DESCR="([^"]*)"/;

// TCP flags that appear as bare words (no key=value)
const TCP_FLAGS = new Set(['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG', 'ECE', 'CWR', 'DF']);

function parseFirewall(message, header) {
  const prefixMatch = message.match(RULE_PREFIX_RE);
  if (!prefixMatch) return null;

  const rulePrefix = prefixMatch[1];

  // Determine action from prefix: -A- = allow, -D- = drop/block
  let action = 'allow';
  if (/-D-/.test(rulePrefix) || /DROP|BLOCK|DENY|REJECT/i.test(rulePrefix)) {
    action = 'block';
  } else if (/REJECT/i.test(rulePrefix)) {
    action = 'reject';
  }

  // Extract DESCR
  const descrMatch = message.match(DESCR_RE);
  const ruleDescription = descrMatch ? descrMatch[1] : null;

  // Extract key=value pairs
  const fields = {};
  let kvMatch;
  while ((kvMatch = KV_RE.exec(message)) !== null) {
    fields[kvMatch[1]] = kvMatch[2];
  }

  // Extract TCP flags
  const flags = [];
  const words = message.split(/\s+/);
  for (const w of words) {
    if (TCP_FLAGS.has(w)) flags.push(w);
  }

  const srcIp = fields.SRC || null;
  const dstIp = fields.DST || null;
  const interfaceIn = fields.IN || null;
  const interfaceOut = fields.OUT || null;

  const direction = detectDirection(interfaceIn, interfaceOut, srcIp, dstIp);

  // Parse MAC field: first 6 bytes = dst, next 6 = src, last 2 = ethertype
  let macSrc = null;
  let macDst = null;
  if (fields.MAC) {
    const macParts = fields.MAC.split(':');
    if (macParts.length >= 12) {
      macDst = macParts.slice(0, 6).join(':');
      macSrc = macParts.slice(6, 12).join(':');
    }
  }

  return {
    event_type: 'firewall',
    source_format: 'iptables',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    action,
    direction,
    rule_prefix: rulePrefix,
    message: ruleDescription || rulePrefix,
    interface_in: interfaceIn,
    interface_out: interfaceOut || null,
    protocol: fields.PROTO || null,
    src_ip: srcIp,
    src_port: fields.SPT ? parseInt(fields.SPT, 10) : null,
    dst_ip: dstIp,
    dst_port: fields.DPT ? parseInt(fields.DPT, 10) : null,
    packet_length: fields.LEN ? parseInt(fields.LEN, 10) : null,
    ttl: fields.TTL ? parseInt(fields.TTL, 10) : null,
    tcp_flags: flags.length > 0 ? flags.join(',') : null,
    mac_src: macSrc,
    mac_dst: macDst,
  };
}

// Check if a raw message looks like a firewall log
function isFirewallMessage(message) {
  return RULE_PREFIX_RE.test(message) && /\bIN=/.test(message) && /\bSRC=/.test(message);
}

module.exports = { parseFirewall, isFirewallMessage };
