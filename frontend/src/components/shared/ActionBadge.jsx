import React from 'react';
import { ACTION_COLORS } from '../../lib/constants';

export default function ActionBadge({ action }) {
  if (!action) return null;
  const config = ACTION_COLORS[action] || ACTION_COLORS.allow;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${config.bg} ${config.text} ${config.border}`}>
      {action}
    </span>
  );
}
