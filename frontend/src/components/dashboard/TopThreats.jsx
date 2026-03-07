import React from 'react';
import { formatNumber, formatDateTime } from '../../lib/format';

export default function TopThreats({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-300 mb-3">Top Threats</h3>
        <p className="text-gray-600 text-sm">No data</p>
      </div>
    );
  }

  const maxCount = data[0]?.count || 1;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-medium text-gray-300 mb-3">Top Threats</h3>
      <div className="space-y-2">
        {data.map((row, i) => (
          <div key={i} className="relative">
            <div
              className="absolute inset-0 bg-red-500/10 rounded"
              style={{ width: `${(row.count / maxCount) * 100}%` }}
            />
            <div className="relative px-2 py-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-gray-200 truncate max-w-[75%]">{row.signature}</span>
                <span className="text-xs font-medium text-gray-300">{formatNumber(row.count)}</span>
              </div>
              {row.classification && (
                <span className="text-xs text-gray-500">{row.classification}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
