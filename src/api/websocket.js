const { WebSocketServer } = require('ws');
const config = require('../config');
const logger = require('../utils/logger');

let wss = null;
const clientFilters = new WeakMap();
let broadcastQueue = [];
let broadcastTimer = null;
let sequence = 0;

function createWebSocketServer(server) {
  wss = new WebSocketServer({ server, path: '/ws/events' });

  wss.on('connection', (ws) => {
    logger.info('WebSocket client connected');
    clientFilters.set(ws, {}); // no filter = all events

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type === 'filter') {
          clientFilters.set(ws, msg.data || {});
          logger.debug({ filter: msg.data }, 'Client filter updated');
        }
      } catch {
        // ignore invalid messages
      }
    });

    ws.on('close', () => {
      logger.debug('WebSocket client disconnected');
    });
  });

  return wss;
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

module.exports = { createWebSocketServer, broadcastEvent, broadcastStats };
