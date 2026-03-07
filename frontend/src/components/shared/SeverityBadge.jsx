import React from 'react';
import { SEVERITY_LABELS } from '../../lib/constants';

const SEV_COLORS = [
  'bg-red-600', 'bg-red-500', 'bg-orange-500', 'bg-orange-400',
  'bg-yellow-500', 'bg-blue-400', 'bg-gray-400', 'bg-gray-500',
];

export default function SeverityBadge({ severity }) {
  if (severity == null) return null;
  const label = SEVERITY_LABELS[severity] || `Sev ${severity}`;
  const color = SEV_COLORS[severity] || 'bg-gray-500';
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${color} text-white`}>
      {label}
    </span>
  );
}
