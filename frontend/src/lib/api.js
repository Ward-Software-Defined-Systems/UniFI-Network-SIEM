// Token helpers — single source of truth for the SIEM_API_TOKEN that the
// dashboard sends with every API request and the WebSocket upgrade.
const TOKEN_KEY = 'siem_api_token';

export function getStoredToken() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}
export function setStoredToken(t) {
  try { localStorage.setItem(TOKEN_KEY, t); } catch {}
}
export function clearStoredToken() {
  try { localStorage.removeItem(TOKEN_KEY); } catch {}
}

function authHeaders() {
  const t = getStoredToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

function dispatchAuthRequired() {
  try { window.dispatchEvent(new CustomEvent('siem:auth-required')); } catch {}
}

async function jsonFetch(url, init = {}) {
  const res = await fetch(url, {
    ...init,
    headers: { ...(init.headers || {}), ...authHeaders() },
  });
  if (res.status === 401) {
    dispatchAuthRequired();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    let err = `API error: ${res.status}`;
    try { const j = await res.json(); if (j?.error) err = j.error; } catch {}
    throw new Error(err);
  }
  return res.json();
}

export async function fetchApi(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, value);
    }
  }
  return jsonFetch(url);
}

export const postApi = (path, body) => jsonFetch(new URL(path, window.location.origin), {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export const putApi = (path, body) => jsonFetch(new URL(path, window.location.origin), {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

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
