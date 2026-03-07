import { useState, useEffect, useRef, useCallback } from 'react';

export function useWebSocket(maxEvents = 200) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState(null);
  const wsRef = useRef(null);
  const reconnectRef = useRef(null);
  const pausedRef = useRef(false);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/ws/events`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current);
        reconnectRef.current = null;
      }
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'event' && !pausedRef.current) {
          setEvents(prev => {
            const next = [msg.data, ...prev];
            return next.length > maxEvents ? next.slice(0, maxEvents) : next;
          });
        } else if (msg.type === 'stats') {
          setStats(msg.data);
        }
      } catch {}
    };

    ws.onclose = () => {
      setConnected(false);
      // Exponential backoff reconnect
      const delay = reconnectRef.current ? 5000 : 1000;
      reconnectRef.current = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [maxEvents]);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };
  }, [connect]);

  const sendFilter = useCallback((filter) => {
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: 'filter', data: filter }));
    }
  }, []);

  const setPaused = useCallback((paused) => {
    pausedRef.current = paused;
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return { events, connected, stats, sendFilter, setPaused, clearEvents };
}
