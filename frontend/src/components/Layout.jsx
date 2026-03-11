import React, { useState, useEffect } from 'react';
import { Activity, BarChart3, Crosshair, Globe, Heart, Settings, Shield } from 'lucide-react';
import { getHealth } from '../lib/api';
import { formatNumber } from '../lib/format';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
  { id: 'map', label: 'Live Map', icon: Globe },
  { id: 'intel', label: 'Threat Intel', icon: Shield },
  { id: 'hunt', label: 'Threat Hunt', icon: Crosshair, badge: 'BETA' },
  { id: 'live', label: 'Live Stream', icon: Activity },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export default function Layout({ activeView, onViewChange, children }) {
  const [health, setHealth] = useState(null);
  const [dismissRebuilding, setDismissRebuilding] = useState(false);

  // Reset dismiss flag when rebuilding clears
  useEffect(() => {
    if (!health?.rebuilding && dismissRebuilding) setDismissRebuilding(false);
  }, [health?.rebuilding]);

  useEffect(() => {
    const fetchHealth = () => getHealth().then(setHealth).catch(() => {});
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex h-screen bg-gray-950">
      {/* Sidebar */}
      <div className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <h1 className="text-lg font-bold text-gray-100">UniFi Network</h1>
          <p className="text-xs text-gray-500 mt-0.5">SIEM</p>
        </div>

        <nav className="flex-1 p-2 space-y-1">
          {NAV_ITEMS.map(({ id, label, icon: Icon, badge }) => (
            <button
              key={id}
              onClick={() => onViewChange(id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                activeView === id
                  ? 'bg-blue-600/20 text-blue-400'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
              {badge && (
                <span className="ml-auto text-[0.6rem] font-semibold bg-amber-500 text-black px-1.5 py-0.5 rounded-full leading-none">
                  {badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Health status */}
        {health && (
          <div className="p-3 border-t border-gray-800 space-y-1">
            <div className="flex items-center gap-1.5">
              <Heart className={`w-3 h-3 ${health.status === 'ok' ? 'text-green-500' : 'text-red-500'}`} />
              <span className="text-xs text-gray-500">System</span>
            </div>
            <div className="text-xs text-gray-500 space-y-0.5">
              <div className="flex justify-between">
                <span>Total events</span>
                <span className="text-gray-300">{formatNumber(health.eventsTotal)}</span>
              </div>
              <div className="flex justify-between">
                <span>Today</span>
                <span className="text-gray-300">{formatNumber(health.eventsToday)}</span>
              </div>
              {health.dbSizeMB ? (
                <div className="flex justify-between">
                  <span>DB size</span>
                  <span className="text-gray-300">{health.dbSizeMB} MB</span>
                </div>
              ) : null}
              {health.totalDocuments != null ? (
                <div className="flex justify-between">
                  <span>Documents</span>
                  <span className="text-gray-300">{formatNumber(health.totalDocuments)}</span>
                </div>
              ) : null}
            </div>
          </div>
        )}
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {health?.rebuilding && !dismissRebuilding ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center space-y-3">
              <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto" />
              <h2 className="text-lg font-medium text-gray-200">
                {health.writePressure === 'high' ? 'Database Under Heavy Load' : 'Rebuilding Database'}
              </h2>
              <p className="text-sm text-gray-500">
                {health.writePressure === 'high'
                  ? 'Write pressure is high — compaction in progress. Dashboard will resume automatically when the database stabilizes.'
                  : 'Indexes are being rebuilt. Dashboard will resume automatically.'}
              </p>
              <p className="text-xs text-gray-600">Events are still being ingested during this time.</p>
              <button
                onClick={() => setDismissRebuilding(true)}
                className="mt-2 px-4 py-1.5 text-xs bg-gray-800 border border-gray-700 text-gray-400 rounded hover:bg-gray-700 hover:text-gray-200 transition-colors"
              >
                Dismiss — Load Dashboard Anyway
              </button>
            </div>
          </div>
        ) : children}
      </div>
    </div>
  );
}
