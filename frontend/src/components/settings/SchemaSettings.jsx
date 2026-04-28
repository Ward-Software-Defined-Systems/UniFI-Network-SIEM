import React, { useState, useEffect, useCallback } from 'react';
import { Settings as SettingsIcon, RotateCcw, Save, Check, RefreshCw, Eye, EyeOff } from 'lucide-react';

// Categories that should expand by default (most-used).
const DEFAULT_OPEN = new Set(['network', 'enrichment', 'auth']);

// Friendly category labels.
const CATEGORY_LABEL = {
  network: 'Network',
  storage: 'Storage',
  enrichment: 'Enrichment',
  performance: 'Performance',
  wardsondb: 'WardSONDB Backend',
  opensearch: 'OpenSearch Backend',
  health: 'Health Monitor',
  logging: 'Logging',
  auth: 'Authentication',
  security: 'Security',
};

export default function SchemaSettings() {
  const [data, setData] = useState(null);   // { categories, entries }
  const [error, setError] = useState(null);

  const reload = useCallback(async (cancelledRef) => {
    try {
      const res = await fetch('/api/settings/v2');
      if (cancelledRef?.current) return;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      if (cancelledRef?.current) return;
      setData(body);
      setError(null);
    } catch (err) {
      if (cancelledRef?.current) return;
      setError(err.message || 'Failed to load settings');
    }
  }, []);

  useEffect(() => {
    const cancelledRef = { current: false };
    reload(cancelledRef);
    return () => { cancelledRef.current = true; };
  }, [reload]);

  if (error) {
    return (
      <div className="bg-gray-900 border border-red-900/50 rounded-lg p-5">
        <p className="text-sm text-red-400">Failed to load settings: {error}</p>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <p className="text-sm text-gray-500">Loading settings…</p>
      </div>
    );
  }

  // Group entries by category, preserving CATEGORY_ORDER from the API
  const grouped = {};
  for (const entry of data.entries) {
    if (!grouped[entry.category]) grouped[entry.category] = [];
    grouped[entry.category].push(entry);
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
      <div className="flex items-center gap-2">
        <SettingsIcon className="w-4 h-4 text-blue-400" />
        <h3 className="text-sm font-medium text-gray-300">Operator Settings</h3>
      </div>
      <p className="text-xs text-gray-500">
        All operational settings. Values stored in the SQLite database take
        precedence over <code className="text-gray-400">.env</code>. Sensitive
        values are encrypted at rest. Some settings require a restart — those
        are flagged.
      </p>

      <div className="space-y-2">
        {data.categories.map((cat) => {
          const entries = grouped[cat] || [];
          if (entries.length === 0) return null;
          return (
            <CategorySection
              key={cat}
              name={cat}
              entries={entries}
              defaultOpen={DEFAULT_OPEN.has(cat)}
              onChange={reload}
            />
          );
        })}
      </div>
    </div>
  );
}

function CategorySection({ name, entries, defaultOpen, onChange }) {
  const [open, setOpen] = useState(defaultOpen);
  const label = CATEGORY_LABEL[name] || name;
  return (
    <div className="border border-gray-800 rounded">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-left hover:bg-gray-800/30 transition-colors"
      >
        <span className="text-xs font-medium text-gray-300 uppercase tracking-wide">{label}</span>
        <span className="text-xs text-gray-500">{entries.length} setting{entries.length === 1 ? '' : 's'}</span>
      </button>
      {open && (
        <div className="border-t border-gray-800 divide-y divide-gray-800">
          {entries.map((entry) => (
            <SettingRow key={entry.key} entry={entry} onChange={onChange} />
          ))}
        </div>
      )}
    </div>
  );
}

function SettingRow({ entry, onChange }) {
  const initial = entry.value ?? (entry.type === 'boolean' ? false : '');
  const [draft, setDraft] = useState(initial);
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState(0);
  const [revealed, setRevealed] = useState('');  // plaintext after regenerate
  const [showSecret, setShowSecret] = useState(false);
  const [err, setErr] = useState(null);

  const isPassword = entry.sensitivity === 'private';
  const isToken = entry.key === 'auth.apiToken';

  // For sensitive entries, the displayed value is "(set)" or "(not set)".
  // The draft starts empty; user types a new value to replace.
  const sensitiveDraftEmpty = isPassword && draft === '' || draft === entry.value;
  const isDirty = isPassword
    ? draft !== '' && draft !== entry.value
    : draft !== entry.value;

  const save = async () => {
    setSaving(true);
    setErr(null);
    try {
      const res = await fetch('/api/settings/v2', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: entry.key, value: draft }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${res.status}`);
      }
      setSavedAt(Date.now());
      setRevealed('');
      setShowSecret(false);
      onChange?.();
    } catch (e) {
      setErr(e.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const reset = async () => {
    setSaving(true);
    setErr(null);
    try {
      const res = await fetch('/api/settings/v2/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: entry.key }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${res.status}`);
      }
      setDraft(entry.type === 'boolean' ? false : '');
      setSavedAt(Date.now());
      setRevealed('');
      onChange?.();
    } catch (e) {
      setErr(e.message || 'Reset failed');
    } finally {
      setSaving(false);
    }
  };

  const regenerateToken = async () => {
    setSaving(true);
    setErr(null);
    try {
      const res = await fetch('/api/settings/v2/regenerate-token', { method: 'POST' });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${res.status}`);
      }
      const body = await res.json();
      setRevealed(body.token);
      setShowSecret(true);
      setSavedAt(Date.now());
      onChange?.();
    } catch (e) {
      setErr(e.message || 'Regenerate failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="px-3 py-3 space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <code className="text-xs text-gray-300">{entry.key}</code>
            {entry.requiresRestart && (
              <span className="px-1.5 py-0.5 text-[10px] bg-yellow-900/50 text-yellow-400 rounded">RESTART REQUIRED</span>
            )}
            {entry.envVar && (
              <span className="px-1.5 py-0.5 text-[10px] bg-gray-800 text-gray-500 rounded">env: {entry.envVar}</span>
            )}
            {entry.readOnly && (
              <span className="px-1.5 py-0.5 text-[10px] bg-gray-800 text-gray-500 rounded">READ-ONLY</span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-1">{entry.description}</p>
          {!isPassword && entry.default !== '' && entry.default !== undefined && (
            <p className="text-[11px] text-gray-600 mt-0.5">
              Default: <code className="text-gray-500">{String(entry.default)}</code>
            </p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2">
        {entry.type === 'boolean' ? (
          <button
            disabled={entry.readOnly || saving}
            onClick={() => setDraft(!draft)}
            className={`px-3 py-1 text-xs rounded ${draft ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400'} disabled:opacity-50`}
          >
            {draft ? 'Enabled' : 'Disabled'}
          </button>
        ) : isPassword ? (
          <div className="flex-1 flex items-center gap-2">
            <input
              type={showSecret ? 'text' : 'password'}
              value={draft}
              disabled={entry.readOnly || saving}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={entry.isSet ? entry.value : 'Not set'}
              className="flex-1 px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 disabled:opacity-50"
            />
            <button
              onClick={() => setShowSecret(!showSecret)}
              className="text-gray-500 hover:text-gray-300"
              title={showSecret ? 'Hide' : 'Show'}
            >
              {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        ) : entry.type === 'number' ? (
          <input
            type="number"
            value={draft}
            disabled={entry.readOnly || saving}
            onChange={(e) => setDraft(e.target.value === '' ? '' : Number(e.target.value))}
            className="w-32 px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
          />
        ) : (
          <input
            type="text"
            value={draft}
            disabled={entry.readOnly || saving}
            onChange={(e) => setDraft(e.target.value)}
            className="flex-1 px-3 py-1.5 text-xs bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
          />
        )}

        <button
          disabled={!isDirty || saving || entry.readOnly}
          onClick={save}
          className="flex items-center gap-1 px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {Date.now() - savedAt < 2000 ? <Check className="w-3 h-3" /> : <Save className="w-3 h-3" />}
          Save
        </button>

        <button
          disabled={saving || entry.readOnly}
          onClick={reset}
          title="Reset to default"
          className="flex items-center gap-1 px-2 py-1.5 text-xs bg-gray-800 text-gray-400 rounded hover:bg-gray-700 disabled:opacity-50 transition-colors"
        >
          <RotateCcw className="w-3 h-3" />
        </button>

        {isToken && (
          <button
            disabled={saving}
            onClick={regenerateToken}
            title="Generate a new token"
            className="flex items-center gap-1 px-3 py-1.5 text-xs bg-yellow-700 text-white rounded hover:bg-yellow-600 disabled:opacity-50 transition-colors"
          >
            <RefreshCw className="w-3 h-3" />
            Regenerate
          </button>
        )}
      </div>

      {revealed && (
        <div className="p-2 bg-yellow-900/20 border border-yellow-800/40 rounded space-y-1">
          <p className="text-[11px] text-yellow-400 font-medium">New token — copy it now, you won't see it again:</p>
          <code className="block text-xs text-yellow-200 break-all select-all">{revealed}</code>
        </div>
      )}

      {err && <p className="text-[11px] text-red-400">{err}</p>}
    </div>
  );
}
