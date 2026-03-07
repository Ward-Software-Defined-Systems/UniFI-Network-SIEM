import React from 'react';
import { formatNumber } from '../../lib/format';

const PORT_NAMES = {
  22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB',
  993: 'IMAPS', 1053: 'CoreDNS', 3389: 'RDP', 5353: 'mDNS', 7000: 'AirPlay',
  8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 51820: 'WireGuard',
};

export default function TopPorts({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-300 mb-3">Top Ports</h3>
        <p className="text-gray-600 text-sm">No data</p>
      </div>
    );
  }

  const maxCount = data[0]?.count || 1;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-medium text-gray-300 mb-3">Top Ports</h3>
      <div className="space-y-2">
        {data.map((row, i) => (
          <div key={i} className="relative">
            <div
              className="absolute inset-0 bg-cyan-500/10 rounded"
              style={{ width: `${(row.count / maxCount) * 100}%` }}
            />
            <div className="relative flex items-center justify-between px-2 py-1.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-gray-200">{row.port}</span>
                <span className="text-xs text-gray-500">{row.protocol}</span>
                {PORT_NAMES[row.port] && (
                  <span className="text-xs text-cyan-400">{PORT_NAMES[row.port]}</span>
                )}
              </div>
              <span className="text-xs font-medium text-gray-300">{formatNumber(row.count)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
