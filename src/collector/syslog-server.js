const dgram = require('dgram');
const config = require('../config');
const logger = require('../utils/logger');
const { compileCidrs, ipMatchesAny } = require('../utils/cidr');
const { parseMessage } = require('./parsers');

let paused = false;

// Lazy-compiled allowlist. Recomputed when the schema setting changes —
// supports live updates from the Settings UI without a restart.
let _cachedAllowCsv = null;
let _cachedAllowList = null;
function getAllowlist() {
  const csv = config.network.syslogAllowedSources;
  if (csv === _cachedAllowCsv) return _cachedAllowList;
  _cachedAllowCsv = csv;
  _cachedAllowList = compileCidrs(csv);
  if (_cachedAllowList) {
    logger.info({ entries: _cachedAllowList.length, csv }, 'Syslog source allowlist active');
  }
  return _cachedAllowList;
}

// Per-source rate counter. Map<ip, {windowStart, count, dropped}> with
// 1-second windows. Periodic logger surfaces sources that exceeded the cap.
const sourceCounters = new Map();

function checkRate(ip) {
  const limit = config.performance.syslogRateLimitPerSourcePerSec;
  if (!limit || limit <= 0) return true;

  const now = Date.now();
  let c = sourceCounters.get(ip);
  if (!c || now - c.windowStart >= 1000) {
    c = { windowStart: now, count: 0, dropped: 0 };
    sourceCounters.set(ip, c);
  }
  if (c.count >= limit) {
    c.dropped++;
    return false;
  }
  c.count++;
  return true;
}

// Per-minute summary of dropped packets per source. Avoids log-spam from
// chatty rate-limited sources.
let dropSummaryInterval = null;
function startDropSummary() {
  if (dropSummaryInterval) return;
  dropSummaryInterval = setInterval(() => {
    const limit = config.performance.syslogRateLimitPerSourcePerSec;
    const now = Date.now();
    for (const [ip, c] of sourceCounters) {
      if (c.dropped > 0) {
        logger.warn({ ip, dropped: c.dropped, limit }, 'Syslog source rate-limited');
        c.dropped = 0;
      }
      // Evict idle counters so the Map doesn't grow unbounded.
      if (now - c.windowStart > 5 * 60 * 1000) {
        sourceCounters.delete(ip);
      }
    }
  }, 60 * 1000);
  // Don't keep the process alive solely for the summary timer.
  dropSummaryInterval.unref?.();
}

let _allowDropSummaryInterval = null;
let _allowDroppedCount = 0;
function startAllowDropSummary() {
  if (_allowDropSummaryInterval) return;
  _allowDropSummaryInterval = setInterval(() => {
    if (_allowDroppedCount > 0) {
      logger.warn({ dropped: _allowDroppedCount }, 'Syslog packets dropped (source not in allowlist)');
      _allowDroppedCount = 0;
    }
  }, 60 * 1000);
  _allowDropSummaryInterval.unref?.();
}

function createSyslogServer(port, onEvent) {
  const server = dgram.createSocket('udp4');

  server.on('message', (msg, rinfo) => {
    if (paused) return;

    // Source allowlist (if configured)
    const allow = getAllowlist();
    if (allow && !ipMatchesAny(rinfo.address, allow)) {
      _allowDroppedCount++;
      return;
    }

    // Per-source rate cap (if configured)
    if (!checkRate(rinfo.address)) {
      return;
    }

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
    // Pre-compute the allowlist and start the summary timers
    getAllowlist();
    startDropSummary();
    startAllowDropSummary();
  });

  return server;
}

function pause() {
  paused = true;
  logger.info('Syslog ingestion paused');
}

function resume() {
  paused = false;
  logger.info('Syslog ingestion resumed');
}

module.exports = { createSyslogServer, pause, resume };
