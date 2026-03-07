const dgram = require('dgram');
const logger = require('../utils/logger');
const { parseMessage } = require('./parsers');

function createSyslogServer(port, onEvent) {
  const server = dgram.createSocket('udp4');

  server.on('message', (msg, rinfo) => {
    const raw = msg.toString('utf8').trim();
    if (!raw) return;

    const event = parseMessage(raw);
    if (event) {
      event.received_at = new Date().toISOString();
      // Store raw if configured
      event._raw = raw;
      event._rinfo = { address: rinfo.address, port: rinfo.port };
      onEvent(event);
    }
  });

  server.on('error', (err) => {
    logger.error({ err }, 'Syslog server error');
    server.close();
  });

  server.bind(port, () => {
    logger.info({ port }, 'Syslog UDP server listening');
  });

  return server;
}

module.exports = { createSyslogServer };
