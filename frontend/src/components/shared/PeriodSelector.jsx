import React from 'react';

const PERIODS = ['1h', '6h', '24h', '7d', '30d'];

export default function PeriodSelector({ value, onChange }) {
  return (
    <div className="flex gap-1">
      {PERIODS.map(p => (
        <button
          key={p}
          onClick={() => onChange(p)}
          className={`px-3 py-1 text-xs rounded font-medium transition-colors ${
            value === p
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          {p}
        </button>
      ))}
    </div>
  );
}
