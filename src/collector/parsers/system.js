// Catch-all parser for unrecognized syslog messages

function parseSystem(message, header) {
  // Try to extract process name and PID
  const procMatch = message.match(/^(\S+?)(?:\[(\d+)\])?:\s*(.*)/);

  return {
    event_type: 'system',
    source_format: 'raw',
    severity: header.severity,
    hostname: header.hostname,
    timestamp: header.timestamp,
    message: procMatch ? procMatch[3] : message,
  };
}

module.exports = { parseSystem };
