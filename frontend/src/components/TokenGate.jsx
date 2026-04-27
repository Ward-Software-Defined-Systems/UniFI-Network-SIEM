import React, { useState, useEffect } from 'react';
import { Lock } from 'lucide-react';
import { getStoredToken, setStoredToken, clearStoredToken } from '../lib/api';

/**
 * Auth gate for the SIEM dashboard. On mount, checks localStorage for a
 * SIEM_API_TOKEN. If absent (or rejected by the server via the global
 * `siem:auth-required` event), shows a login form; otherwise renders
 * children. The token entered here is verified against /api/health
 * before being stored.
 */
export default function TokenGate({ children }) {
  const [authed, setAuthed] = useState(() => !!getStoredToken());
  const [token, setToken] = useState('');
  const [error, setError] = useState(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    const handler = () => {
      clearStoredToken();
      setToken('');
      setAuthed(false);
      setError('Token rejected by server. Sign in again.');
    };
    window.addEventListener('siem:auth-required', handler);
    return () => window.removeEventListener('siem:auth-required', handler);
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setChecking(true);
    setError(null);
    const t = token.trim();
    try {
      // Verify against /api/health before persisting. We can't use the
      // global fetch wrapper here (no token in localStorage yet) — call
      // the original fetch with an inline header.
      const res = await window.fetch('/api/health', {
        headers: { Authorization: `Bearer ${t}` },
      });
      if (res.status === 401) {
        setError('Invalid token');
      } else if (res.status === 503) {
        setError('Server has no auth token configured. Check SIEM startup logs for the auto-generated SIEM_API_TOKEN.');
      } else if (res.ok) {
        setStoredToken(t);
        setAuthed(true);
        setToken('');
      } else {
        setError(`Server error: ${res.status}`);
      }
    } catch (e) {
      setError('Failed to reach server. Is the SIEM running?');
    }
    setChecking(false);
  };

  if (!authed) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <form onSubmit={submit} className="w-[420px] space-y-4 p-8 bg-gray-900 border border-gray-800 rounded-lg shadow-2xl">
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-blue-400" />
            <h1 className="text-base font-semibold text-gray-200">UniFi Network SIEM</h1>
          </div>
          <p className="text-xs text-gray-500 leading-relaxed">
            Enter your <code className="text-gray-400">SIEM_API_TOKEN</code>.
            The token was logged once at SIEM startup with a
            "<code className="text-gray-400">BOOTSTRAP:</code>" notice — check
            the server stdout or systemd journal. You can rotate it any time
            via <span className="text-gray-300">Settings → Authentication → auth.apiToken → Regenerate</span>.
          </p>
          <input
            type="password"
            placeholder="Token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoFocus
            spellCheck="false"
            autoComplete="off"
            className="w-full px-3 py-2 text-sm bg-gray-800 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={!token.trim() || checking}
            className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {checking ? 'Verifying…' : 'Sign in'}
          </button>
        </form>
      </div>
    );
  }

  return children;
}
