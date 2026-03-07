import React from 'react';
import { formatNumber } from '../../lib/format';

export default function TopTalkers({ data, title = 'Top Talkers' }) {
  if (!data || data.length === 0) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-300 mb-3">{title}</h3>
        <p className="text-gray-600 text-sm">No data</p>
      </div>
    );
  }

  const maxCount = data[0]?.count || 1;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-medium text-gray-300 mb-3">{title}</h3>
      <div className="space-y-2">
        {data.map((row, i) => (
          <div key={i} className="relative">
            <div
              className="absolute inset-0 bg-blue-500/10 rounded"
              style={{ width: `${(row.count / maxCount) * 100}%` }}
            />
            <div className="relative flex items-center justify-between px-2 py-1.5">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500 w-5">{i + 1}</span>
                <span className="text-xs font-mono text-gray-200">{row.ip}</span>
                {row.country && <span className="text-xs text-gray-500">{row.country}</span>}
                {row.hostname && <span className="text-xs text-gray-500">{row.hostname}</span>}
              </div>
              <span className="text-xs font-medium text-gray-300">{formatNumber(row.count)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
