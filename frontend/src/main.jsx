import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { getStoredToken } from './lib/api';

// Global fetch wrapper — injects `Authorization: Bearer <token>` on every
// /api/* request and dispatches `siem:auth-required` on 401 so TokenGate
// can react. Catches call sites that bypass the typed helpers in lib/api.js
// (Settings.jsx, ThreatHunt.jsx streaming, SchemaSettings.jsx, etc.).
const originalFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : (input?.url || '');
  const isApi = url.includes('/api/') || url.startsWith('/api');
  if (isApi) {
    const token = getStoredToken();
    if (token) {
      init = {
        ...init,
        headers: { ...(init.headers || {}), Authorization: `Bearer ${token}` },
      };
    }
  }
  const res = await originalFetch(input, init);
  if (res.status === 401 && isApi) {
    try { window.dispatchEvent(new CustomEvent('siem:auth-required')); } catch {}
  }
  return res;
};

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
