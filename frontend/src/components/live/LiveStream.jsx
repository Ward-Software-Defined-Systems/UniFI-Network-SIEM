import React, { useState, useEffect, useMemo } from 'react';
import { useWebSocket } from '../../hooks/useWebSocket';
import StreamFilters from './StreamFilters';
import EventRow from './EventRow';
import EventDetail from './EventDetail';
import { EVENT_TYPES } from '../../lib/constants';

export default function LiveStream() {
  const { events, connected, sendFilter, setPaused, clearEvents } = useWebSocket(500);
  const [activeTypes, setActiveTypes] = useState(new Set(Object.keys(EVENT_TYPES)));
  const [search, setSearch] = useState('');
  const [paused, setPausedState] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const handleToggleType = (type) => {
    setActiveTypes(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  // Send filter to server when types change
  useEffect(() => {
    const types = Array.from(activeTypes);
    if (types.length === Object.keys(EVENT_TYPES).length) {
      sendFilter({});
    } else {
      sendFilter({ event_type: types });
    }
  }, [activeTypes, sendFilter]);

  const handlePauseToggle = () => {
    const next = !paused;
    setPausedState(next);
    setPaused(next);
  };

  // Client-side search filter
  const filteredEvents = useMemo(() => {
    if (!search) return events;
    const term = search.toLowerCase();
    return events.filter(e =>
      (e.message && e.message.toLowerCase().includes(term)) ||
      (e.src_ip && e.src_ip.includes(term)) ||
      (e.dst_ip && e.dst_ip.includes(term)) ||
      (e.dns_name && e.dns_name.toLowerCase().includes(term)) ||
      (e.hostname && e.hostname.toLowerCase().includes(term))
    );
  }, [events, search]);

  return (
    <div className="flex flex-col h-full">
      <StreamFilters
        activeTypes={activeTypes}
        onToggleType={handleToggleType}
        search={search}
        onSearchChange={setSearch}
        paused={paused}
        onPauseToggle={handlePauseToggle}
        onClear={clearEvents}
      />

      <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-900/50 border-b border-gray-800 text-xs text-gray-500">
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
        <span>{connected ? 'Connected' : 'Disconnected'}</span>
        <span className="ml-auto">{filteredEvents.length} events</span>
        {paused && <span className="text-yellow-400 font-medium">PAUSED</span>}
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-700">
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Time</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Type</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Action</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Source</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Dest</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Port</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Proto</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Message</th>
              <th className="px-3 py-2 text-xs font-medium text-gray-400">Host</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((event, i) => (
              <EventRow
                key={event.id || `ws-${i}`}
                event={event}
                onClick={setSelectedEvent}
              />
            ))}
          </tbody>
        </table>

        {filteredEvents.length === 0 && (
          <div className="flex items-center justify-center h-48 text-gray-600">
            {connected ? 'Waiting for events...' : 'Connecting...'}
          </div>
        )}
      </div>

      <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
}
