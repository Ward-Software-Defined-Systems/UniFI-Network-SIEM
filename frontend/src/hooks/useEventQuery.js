import { useState, useEffect, useCallback } from 'react';
import { getEvents } from '../lib/api';

export function useEventQuery(initialFilters = {}) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState(initialFilters);

  const fetchEvents = useCallback(async (overrides = {}) => {
    setLoading(true);
    try {
      const params = { ...filters, ...overrides };
      const data = await getEvents(params);
      // M4: `/api/events` now returns `{events, hasMore, nextCursor}`.
      // Tolerate the older array-shaped response for forward/back-
      // compat across server upgrades — if `data` is an array, treat
      // it as the events list directly.
      if (Array.isArray(data)) {
        setEvents(data);
      } else {
        setEvents(data.events || []);
      }
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  return { events, loading, filters, setFilters, refetch: fetchEvents };
}
