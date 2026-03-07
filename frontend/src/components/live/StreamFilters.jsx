import React from 'react';
import { EVENT_TYPES } from '../../lib/constants';
import { Search, Pause, Play, Trash2 } from 'lucide-react';

export default function StreamFilters({ activeTypes, onToggleType, search, onSearchChange, paused, onPauseToggle, onClear }) {
  return (
    <div className="flex flex-wrap items-center gap-3 p-3 bg-gray-900 border-b border-gray-800">
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(EVENT_TYPES).map(([type, config]) => (
          <button
            key={type}
            onClick={() => onToggleType(type)}
            className={`px-2 py-1 text-xs rounded font-medium transition-all ${
              activeTypes.has(type)
                ? `${config.color} text-white`
                : 'bg-gray-800 text-gray-500 hover:text-gray-300'
            }`}
          >
            {config.label}
          </button>
        ))}
      </div>

      <div className="flex-1 min-w-[200px]">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search IPs, domains, messages..."
            className="w-full pl-8 pr-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      <div className="flex gap-1.5">
        <button
          onClick={onPauseToggle}
          className={`p-1.5 rounded ${paused ? 'bg-yellow-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'}`}
          title={paused ? 'Resume' : 'Pause'}
        >
          {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
        </button>
        <button
          onClick={onClear}
          className="p-1.5 rounded bg-gray-800 text-gray-400 hover:text-white"
          title="Clear"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
