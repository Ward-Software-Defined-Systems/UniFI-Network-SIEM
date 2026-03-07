import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { EVENT_TYPES } from '../../lib/constants';

export default function Timeline({ data }) {
  if (!data || data.length === 0) {
    return <div className="h-64 flex items-center justify-center text-gray-600">No data</div>;
  }

  // Format timestamps for display
  const formatted = data.map(d => ({
    ...d,
    label: d.ts ? new Date(d.ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }) : '',
  }));

  // Determine which series are present
  const seriesKeys = Object.keys(data[0]).filter(k => k !== 'ts' && k !== 'label' && k !== 'total');
  const hasFirewallView = seriesKeys.includes('allowed');

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <h3 className="text-sm font-medium text-gray-300 mb-3">Event Timeline</h3>
      <ResponsiveContainer width="100%" height={250}>
        <AreaChart data={formatted}>
          <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#6b7280' }} />
          <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} width={40} />
          <Tooltip
            contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
            labelStyle={{ color: '#9ca3af' }}
          />
          <Legend wrapperStyle={{ fontSize: '12px' }} />
          {hasFirewallView ? (
            <>
              <Area type="monotone" dataKey="allowed" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.3} />
              <Area type="monotone" dataKey="blocked" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3} />
            </>
          ) : (
            seriesKeys.map(key => {
              const config = EVENT_TYPES[key];
              const color = config ? config.hex : '#6b7280';
              return (
                <Area
                  key={key}
                  type="monotone"
                  dataKey={key}
                  stackId="1"
                  stroke={color}
                  fill={color}
                  fillOpacity={0.3}
                />
              );
            })
          )}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
