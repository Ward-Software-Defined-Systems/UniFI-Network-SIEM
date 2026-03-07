import React, { useState, useEffect } from 'react';
import { getHealth, fetchApi } from '../lib/api';
import { CheckCircle, XCircle } from 'lucide-react';

export default function Settings() {
  const [health, setHealth] = useState(null);
  const [abuseKey, setAbuseKey] = useState('');
  const [hasExistingKey, setHasExistingKey] = useState(false);
  const [saved, setSaved] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetDone, setResetDone] = useState(false);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => {});
    // Load existing settings
    fetchApi('/api/settings').then((s) => {
      if (s.abuseIpDbKey) setHasExistingKey(true);
    }).catch(() => {});
  }, []);

  const handleSaveAbuseKey = async () => {
    try {
      await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ abuseIpDbKey: abuseKey }),
      });
      setSaved(true);
      // Refresh health to show updated status
      setTimeout(() => {
        getHealth().then(setHealth).catch(() => {});
        setSaved(false);
      }, 2000);
    } catch {}
  };

  const enrichment = health?.enrichment || {};

  return (
    <div className="p-6 space-y-6 overflow-auto h-full max-w-3xl">
      <h2 className="text-lg font-semibold text-gray-200">Settings</h2>

      {/* Enrichment Status */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
        <h3 className="text-sm font-medium text-gray-300">Enrichment Status</h3>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-200">GeoIP (MaxMind GeoLite2)</p>
              <p className="text-xs text-gray-500">Offline IP geolocation — country, city, coordinates</p>
            </div>
            {enrichment.geoip ? (
              <span className="flex items-center gap-1.5 text-xs text-green-400">
                <CheckCircle className="w-4 h-4" /> Active
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-xs text-gray-500">
                <XCircle className="w-4 h-4" /> Not configured
              </span>
            )}
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-200">AbuseIPDB</p>
              <p className="text-xs text-gray-500">Threat intelligence — abuse confidence scores</p>
            </div>
            {enrichment.abuseipdb ? (
              <span className="flex items-center gap-1.5 text-xs text-green-400">
                <CheckCircle className="w-4 h-4" /> Active
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-xs text-gray-500">
                <XCircle className="w-4 h-4" /> Not configured
              </span>
            )}
          </div>

          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400">Enrichment queue</span>
            <span className="text-xs text-gray-300">{enrichment.queueSize ?? 0} IPs pending</span>
          </div>
        </div>
      </div>

      {/* GeoIP Setup */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
        <h3 className="text-sm font-medium text-gray-300">GeoIP Setup</h3>
        <p className="text-xs text-gray-500">
          Download the free GeoLite2-City.mmdb database from MaxMind and place it in the <code className="text-gray-400">data/</code> directory.
        </p>
        <ol className="text-xs text-gray-500 list-decimal list-inside space-y-1">
          <li>Sign up at maxmind.com/en/geolite2/signup (free)</li>
          <li>Generate a license key under Account &gt; Manage License Keys</li>
          <li>Download GeoLite2-City.mmdb</li>
          <li>Place in <code className="text-gray-400">./data/GeoLite2-City.mmdb</code></li>
          <li>Restart the application</li>
        </ol>
      </div>

      {/* AbuseIPDB Setup */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
        <h3 className="text-sm font-medium text-gray-300">AbuseIPDB API Key</h3>
        <p className="text-xs text-gray-500">
          Get a free API key (1,000 checks/day) at abuseipdb.com. Save it here or set <code className="text-gray-400">ABUSEIPDB_API_KEY</code> in <code className="text-gray-400">.env</code>. Takes effect immediately — no restart required.
        </p>
        <div className="flex gap-2">
          <input
            type="password"
            value={abuseKey}
            onChange={(e) => setAbuseKey(e.target.value)}
            placeholder={hasExistingKey ? 'Key saved — enter new key to replace' : 'Enter API key'}
            className="flex-1 px-3 py-2 text-sm bg-gray-800 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleSaveAbuseKey}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-500 transition-colors"
          >
            Save
          </button>
        </div>
        {saved && <p className="text-xs text-green-400">Saved! AbuseIPDB enrichment is now active.</p>}
      </div>

      {/* System Info */}
      {health && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-2">
          <h3 className="text-sm font-medium text-gray-300">System</h3>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <span className="text-gray-500">Uptime</span>
            <span className="text-gray-300">{Math.floor(health.uptime / 3600)}h {Math.floor((health.uptime % 3600) / 60)}m</span>
            <span className="text-gray-500">Total events</span>
            <span className="text-gray-300">{health.eventsTotal?.toLocaleString()}</span>
            <span className="text-gray-500">Events today</span>
            <span className="text-gray-300">{health.eventsToday?.toLocaleString()}</span>
            <span className="text-gray-500">Database size</span>
            <span className="text-gray-300">{health.dbSizeMB} MB</span>
          </div>
        </div>
      )}

      {/* Database Reset */}
      <div className="bg-gray-900 border border-red-900/50 rounded-lg p-5 space-y-3">
        <h3 className="text-sm font-medium text-red-400">Danger Zone</h3>
        <p className="text-xs text-gray-500">
          Clear all events and enrichment cache. Settings are preserved. This cannot be undone.
        </p>
        {!confirmReset ? (
          <button
            onClick={() => setConfirmReset(true)}
            className="px-4 py-2 text-sm bg-gray-800 border border-red-700 text-red-400 rounded hover:bg-red-900/30 transition-colors"
          >
            Initialize Database
          </button>
        ) : (
          <div className="flex items-center gap-3">
            <button
              onClick={async () => {
                try {
                  await fetch('/api/settings/reset-db', { method: 'POST' });
                  setResetDone(true);
                  setConfirmReset(false);
                  getHealth().then(setHealth).catch(() => {});
                  setTimeout(() => setResetDone(false), 5000);
                } catch {}
              }}
              className="px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-500 transition-colors"
            >
              Confirm — Delete All Data
            </button>
            <button
              onClick={() => setConfirmReset(false)}
              className="px-4 py-2 text-sm bg-gray-800 text-gray-400 rounded hover:text-gray-200 transition-colors"
            >
              Cancel
            </button>
          </div>
        )}
        {resetDone && <p className="text-xs text-green-400">Database cleared successfully.</p>}
      </div>
    </div>
  );
}
