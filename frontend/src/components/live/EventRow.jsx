import React from 'react';
import EventTypeBadge from '../shared/EventTypeBadge';
import ActionBadge from '../shared/ActionBadge';
import { formatTimestamp, truncate, countryFlag, abuseScoreColor } from '../../lib/format';

export default function EventRow({ event, onClick }) {
  return (
    <tr
      onClick={() => onClick(event)}
      className="border-b border-gray-800/50 hover:bg-gray-800/50 cursor-pointer transition-colors"
    >
      <td className="px-3 py-1.5 text-xs text-gray-500 whitespace-nowrap font-mono">
        {formatTimestamp(event.received_at)}
      </td>
      <td className="px-3 py-1.5">
        <EventTypeBadge type={event.event_type} />
      </td>
      <td className="px-3 py-1.5">
        <ActionBadge action={event.action} />
      </td>
      <td className="px-3 py-1.5 text-xs text-gray-400 whitespace-nowrap font-mono">
        <span className="inline-flex items-center gap-1">
          {event.src_ip || event.dns_client_ip || event.dhcp_ip || event.client_ip || '-'}
          {event.src_geo_country && <span className="text-gray-500">{countryFlag(event.src_geo_country)} {event.src_geo_country}</span>}
          {event.src_abuse_score > 0 && (() => { const c = abuseScoreColor(event.src_abuse_score); return c ? <span className={`text-[10px] px-1 py-0 rounded border ${c.bg} ${c.text} ${c.border}`}>{event.src_abuse_score}</span> : null; })()}
        </span>
      </td>
      <td className="px-3 py-1.5 text-xs text-gray-400 whitespace-nowrap font-mono">
        <span className="inline-flex items-center gap-1">
          {event.dst_ip || '-'}
          {event.dst_geo_country && <span className="text-gray-500">{countryFlag(event.dst_geo_country)} {event.dst_geo_country}</span>}
          {event.dst_abuse_score > 0 && (() => { const c = abuseScoreColor(event.dst_abuse_score); return c ? <span className={`text-[10px] px-1 py-0 rounded border ${c.bg} ${c.text} ${c.border}`}>{event.dst_abuse_score}</span> : null; })()}
        </span>
      </td>
      <td className="px-3 py-1.5 text-xs text-gray-400 whitespace-nowrap font-mono">
        {event.dst_port || '-'}
      </td>
      <td className="px-3 py-1.5 text-xs text-gray-400 whitespace-nowrap">
        {event.protocol || '-'}
      </td>
      <td className="px-3 py-1.5 text-xs text-gray-300 max-w-xs truncate">
        {truncate(event.message, 80)}
      </td>
      <td className="px-3 py-1.5 text-xs text-gray-500 whitespace-nowrap">
        {event.hostname || '-'}
      </td>
    </tr>
  );
}
