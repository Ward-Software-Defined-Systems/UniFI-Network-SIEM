import React from 'react';
import { EVENT_TYPES } from '../../lib/constants';

export default function EventTypeBadge({ type }) {
  const config = EVENT_TYPES[type] || EVENT_TYPES.system;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${config.color} text-white`}>
      {config.label}
    </span>
  );
}
