import React from 'react';
import { formatNumber } from '../../lib/format';

export default function TopClients({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-300 mb-3">Top Clients</h3>
        <p className="text-gray-600 text-sm">No data</p>
      </div>
    );
  }

  const maxCount = data[0]?.eventCount || 1;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-medium text-gray-300 mb-3">Top Clients</h3>
      <div className="space-y-2">
        {data.map((row, i) => (
          <div key={i} className="relative">
            <div
              className="absolute inset-0 bg-indigo-500/10 rounded"
              style={{ width: `${(row.eventCount / maxCount) * 100}%` }}
            />
            <div className="relative px-2 py-1.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-xs text-gray-500 w-5 shrink-0">{i + 1}</span>
                  <span className="text-xs text-gray-200 truncate">
                    {row.alias || row.ip || row.mac}
                  </span>
                </div>
                <span className="text-xs font-medium text-gray-300 shrink-0 ml-2">{formatNumber(row.eventCount)}</span>
              </div>
              <div className="flex items-center gap-3 ml-7 mt-0.5">
                {row.ip && <span className="text-xs font-mono text-gray-500">{row.ip}</span>}
                {row.wifiEvents > 0 && <span className="text-xs text-purple-400">wifi:{row.wifiEvents}</span>}
                {row.dhcpEvents > 0 && <span className="text-xs text-green-400">dhcp:{row.dhcpEvents}</span>}
                {row.firewallEvents > 0 && <span className="text-xs text-blue-400">fw:{row.firewallEvents}</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
