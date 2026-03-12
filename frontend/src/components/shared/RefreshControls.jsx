import React from 'react';

const REFRESH_OPTIONS = [
  { label: '1m', value: 60000 },
  { label: '2m', value: 120000 },
  { label: '5m', value: 300000 },
];

export default function RefreshControls({ refreshRate, setRefreshRate, paused, setPaused, onRefresh, loading }) {
  return (
    <div className="flex items-center gap-1 bg-gray-800 rounded-lg border border-gray-700 p-0.5">
      {/* Manual refresh button */}
      <button
        onClick={onRefresh}
        disabled={loading}
        title="Refresh now"
        className="p-1.5 rounded-md text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      >
        <svg className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      </button>

      {/* Pause/resume button */}
      <button
        onClick={() => setPaused(!paused)}
        title={paused ? 'Resume auto-refresh' : 'Pause auto-refresh'}
        className={`p-1.5 rounded-md transition-colors ${
          paused
            ? 'text-yellow-400 bg-yellow-500/10 hover:bg-yellow-500/20'
            : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'
        }`}
      >
        {paused ? (
          <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M8 5v14l11-7z" />
          </svg>
        ) : (
          <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
          </svg>
        )}
      </button>

      {/* Divider */}
      <div className="w-px h-5 bg-gray-700" />

      {/* Refresh rate options */}
      {REFRESH_OPTIONS.map(opt => (
        <button
          key={opt.value}
          onClick={() => { setRefreshRate(opt.value); setPaused(false); }}
          className={`px-2 py-1 text-xs rounded-md transition-colors ${
            refreshRate === opt.value && !paused
              ? 'bg-blue-600/20 text-blue-400'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export function PausedIndicator({ paused, loading }) {
  if (!paused || loading) return null;
  return (
    <div className="flex items-center gap-2 text-xs text-yellow-400/70">
      <svg className="h-3 w-3" fill="currentColor" viewBox="0 0 24 24">
        <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
      </svg>
      Auto-refresh paused
    </div>
  );
}
