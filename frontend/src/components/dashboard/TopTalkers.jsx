import React from 'react';
import { formatNumber, countryFlag, abuseScoreColor } from '../../lib/format';

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
            <div className="relative flex items-center justify-between px-2 py-1.5 gap-2">
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <span className="text-xs text-gray-500 w-5 shrink-0">{i + 1}</span>
                <span className="text-xs font-mono text-gray-200 shrink-0">{row.ip}</span>
                {row.abuseScore > 0 && (() => { const c = abuseScoreColor(row.abuseScore); return c ? <span className={`text-[10px] px-1.5 py-0.5 rounded-full border shrink-0 ${c.bg} ${c.text} ${c.border}`}>{row.abuseScore}%</span> : null; })()}
                {row.country && <span className="text-xs text-gray-500 shrink-0">{countryFlag(row.country)} {row.country}</span>}
                {row.hostname && <span className="text-xs text-gray-500 truncate min-w-0" title={row.hostname}>{row.hostname}</span>}
              </div>
              <span className="text-xs font-medium text-gray-300 shrink-0">{formatNumber(row.count)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
