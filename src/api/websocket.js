const { WebSocketServer } = require('ws');
const config = require('../config');
const logger = require('../utils/logger');
const { validateWsToken } = require('./middleware/auth');

let wss = null;
const clientFilters = new WeakMap();
const clientFilterDebounce = new WeakMap();
let broadcastQueue = [];
let broadcastTimer = null;
let sequence = 0;

const FILTER_DEBOUNCE_MS = 200;
const MAX_PAYLOAD = 64 * 1024;

function createWebSocketServer(server) {
  wss = new WebSocketServer({
    server,
    path: '/ws/events',
    maxPayload: MAX_PAYLOAD,
    verifyClient: (info, cb) => {
      // Tokens travel as a query param because browser WebSocket clients
      // can't set custom headers. Default HTTP_HOST is 127.0.0.1 so the
      // token isn't exposed to a LAN unless the operator opts in.
      try {
        const url = new URL(info.req.url, 'http://localhost');
        const token = url.searchParams.get('token') || '';
        if (!validateWsToken(token)) {
          return cb(false, 401, 'Unauthorized');
        }
        cb(true);
      } catch {
        cb(false, 400, 'Bad Request');
      }
    },
  });

  wss.on('connection', (ws, req) => {
    logger.info({ ip: req.socket.remoteAddress }, 'WebSocket client connected');
    clientFilters.set(ws, {}); // no filter = all events

    ws.on('message', (data) => {
      // Debounce per-client filter updates so chatty clients can't
      // saturate the main loop.
      const now = Date.now();
      const last = clientFilterDebounce.get(ws) || 0;
      if (now - last < FILTER_DEBOUNCE_MS) return;
      clientFilterDebounce.set(ws, now);

      try {
        const msg = JSON.parse(data);
        if (!isValidFilterMessage(msg)) {
          logger.debug({ msg: typeof msg === 'object' ? msg.type : typeof msg }, 'Rejected invalid WS filter message');
          return;
        }
        clientFilters.set(ws, msg.data || {});
      } catch {
        // Drop malformed JSON silently — payload size is already capped.
      }
    });

    ws.on('close', () => {
      logger.debug('WebSocket client disconnected');
    });
  });

  return wss;
}

/**
 * Schema check for client → server filter messages. We currently accept:
 *   { type: 'filter', data?: { event_type?: string|string[], action?: string } }
 */
function isValidFilterMessage(msg) {
  if (!msg || typeof msg !== 'object') return false;
  if (msg.type !== 'filter') return false;
  if (msg.data === undefined || msg.data === null) return true;
  if (typeof msg.data !== 'object') return false;
  if (msg.data.event_type !== undefined) {
    const v = msg.data.event_type;
    if (!(typeof v === 'string' || (Array.isArray(v) && v.every((s) => typeof s === 'string')))) return false;
  }
  if (msg.data.action !== undefined && typeof msg.data.action !== 'string') return false;
  return true;
}

function matchesFilter(event, filter) {
  if (!filter || Object.keys(filter).length === 0) return true;

  if (filter.event_type) {
    const types = Array.isArray(filter.event_type) ? filter.event_type : [filter.event_type];
    if (!types.includes(event.event_type)) return false;
  }
  if (filter.action && event.action !== filter.action) return false;

  return true;
}

function broadcastEvent(event) {
  if (!wss) return;

  broadcastQueue.push(event);

  if (!broadcastTimer) {
    broadcastTimer = setTimeout(flushBroadcast, config.performance.wsBroadcastThrottleMs);
  }
}

function flushBroadcast() {
  broadcastTimer = null;
  if (!wss || broadcastQueue.length === 0) return;

  const events = broadcastQueue;
  broadcastQueue = [];

  for (const client of wss.clients) {
    if (client.readyState !== 1) continue; // OPEN

    const filter = clientFilters.get(client) || {};
    const matching = events.filter(e => matchesFilter(e, filter));

    if (matching.length === 0) continue;

    try {
      for (const event of matching) {
        sequence++;
        client.send(JSON.stringify({
          type: 'event',
          seq: sequence,
          data: event,
        }));
      }
    } catch {
      // client disconnected mid-send
    }
  }
}

function broadcastStats(stats) {
  if (!wss) return;

  const msg = JSON.stringify({ type: 'stats', data: stats });

  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try {
        client.send(msg);
      } catch {
        // ignore
      }
    }
  }
}

function getClientCount() {
  return wss ? wss.clients.size : 0;
}

module.exports = { createWebSocketServer, broadcastEvent, broadcastStats, getClientCount };
