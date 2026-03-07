const BASE = '';

export async function fetchApi(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, value);
    }
  }
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export const getEvents = (params) => fetchApi('/api/events', params);
export const getEvent = (id) => fetchApi(`/api/events/${id}`);
export const getHealth = () => fetchApi('/api/health');
export const getStatsOverview = (period) => fetchApi('/api/stats/overview', { period });
export const getTimeline = (period, bucket, event_type) => fetchApi('/api/stats/timeline', { period, bucket, event_type });
export const getTopTalkers = (period, limit, direction, exclude_private) => fetchApi('/api/stats/top-talkers', { period, limit, direction, exclude_private });
export const getTopBlocked = (period, limit, direction, exclude_private) => fetchApi('/api/stats/top-blocked', { period, limit, direction, exclude_private });
export const getTopPorts = (period, limit) => fetchApi('/api/stats/top-ports', { period, limit });
export const getTopClients = (period, limit) => fetchApi('/api/stats/top-clients', { period, limit });
export const getTopThreats = (period, limit) => fetchApi('/api/stats/top-threats', { period, limit });
export const getThreatIntel = (period, limit) => fetchApi('/api/stats/threat-intel', { period, limit });
export const getGeoEvents = (period, limit) => fetchApi('/api/stats/geo-events', { period, limit });
export const getRecentGeoEvents = (limit) => fetchApi('/api/stats/recent-geo-events', { limit });
