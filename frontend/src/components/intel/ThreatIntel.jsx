import React, { useState, useEffect, useMemo } from 'react';
import { ChevronUp, ChevronDown } from 'lucide-react';
import PeriodSelector from '../shared/PeriodSelector';
import { getThreatIntel } from '../../lib/api';
import { formatNumber, formatDateTime, countryFlag } from '../../lib/format';

function AbuseScoreBar({ score }) {
  if (score == null) return <span className="text-gray-600 text-xs">—</span>;
  let color = 'bg-green-500';
  let textColor = 'text-green-400';
  if (score >= 75) { color = 'bg-red-500'; textColor = 'text-red-400'; }
  else if (score >= 50) { color = 'bg-orange-500'; textColor = 'text-orange-400'; }
  else if (score >= 25) { color = 'bg-yellow-500'; textColor = 'text-yellow-400'; }

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-medium ${textColor}`}>{score}%</span>
    </div>
  );
}

function SummaryCard({ label, value, color = 'text-gray-200' }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{formatNumber(value)}</p>
    </div>
  );
}

function SortHeader({ label, field, sortField, sortDir, onSort, align = 'left' }) {
  const active = sortField === field;
  return (
    <th
      className={`text-${align} px-4 py-3 font-medium cursor-pointer select-none hover:text-gray-200 transition-colors ${active ? 'text-blue-400' : ''}`}
      onClick={() => onSort(field)}
    >
      <div className={`flex items-center gap-1 ${align === 'right' ? 'justify-end' : ''}`}>
        {label}
        <span className="inline-flex flex-col leading-none">
          <ChevronUp className={`w-3 h-3 -mb-0.5 ${active && sortDir === 'asc' ? 'text-blue-400' : 'text-gray-700'}`} />
          <ChevronDown className={`w-3 h-3 -mt-0.5 ${active && sortDir === 'desc' ? 'text-blue-400' : 'text-gray-700'}`} />
        </span>
      </div>
    </th>
  );
}

const COLUMNS = [
  { field: 'ip', label: 'IP Address', align: 'left', type: 'string' },
  { field: 'hostname', label: 'Hostname', align: 'left', type: 'string' },
  { field: 'country', label: 'Location', align: 'left', type: 'string' },
  { field: 'abuse_score', label: 'Abuse Score', align: 'left', type: 'number' },
  { field: 'event_count', label: 'Events', align: 'right', type: 'number' },
  { field: 'blocked_count', label: 'Blocked', align: 'right', type: 'number' },
  { field: 'threat_count', label: 'Threats', align: 'right', type: 'number' },
  { field: 'lastSeen', label: 'Last Seen', align: 'right', type: 'string' },
];

export default function ThreatIntel({ period, setPeriod }) {
  const [data, setData] = useState({ summary: { totalEnriched: 0, withAbuseScore: 0, highThreat: 0, countries: 0 }, periodSummary: { enriched: 0, flagged: 0, highThreat: 0, countries: 0 }, ips: [] });
  const [sortField, setSortField] = useState('event_count');
  const [sortDir, setSortDir] = useState('desc');
  const [filters, setFilters] = useState({});
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const fetchData = () => {
      getThreatIntel(period, 200).then(d => {
        if (!cancelled) setData(d);
      }).catch(() => {});
    };
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [period]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const setFilter = (field, value) => {
    setFilters(f => {
      const next = { ...f };
      if (value === '') delete next[field];
      else next[field] = value;
      return next;
    });
  };

  const processed = useMemo(() => {
    let rows = [...data.ips];

    // Apply filters
    for (const [field, value] of Object.entries(filters)) {
      if (!value) continue;
      const lower = value.toLowerCase();
      rows = rows.filter(row => {
        const col = COLUMNS.find(c => c.field === field);
        if (!col) return true;
        if (col.type === 'number') {
          // Support operators: >50, <10, >=75, =0
          const match = value.match(/^([><=!]+)?\s*(\d+)$/);
          if (match) {
            const op = match[1] || '>=';
            const num = parseFloat(match[2]);
            const val = row[field] ?? 0;
            if (op === '>') return val > num;
            if (op === '<') return val < num;
            if (op === '>=') return val >= num;
            if (op === '<=') return val <= num;
            if (op === '=' || op === '==') return val === num;
            if (op === '!=' || op === '!') return val !== num;
          }
          return String(row[field] ?? '').includes(value);
        }
        // String fields — substring match
        if (field === 'country') {
          const loc = row.city && row.country ? `${row.city}, ${row.country}` : row.country || '';
          return loc.toLowerCase().includes(lower);
        }
        return String(row[field] ?? '').toLowerCase().includes(lower);
      });
    }

    // Apply sort
    rows.sort((a, b) => {
      let av = a[sortField];
      let bv = b[sortField];
      if (av == null) av = sortField === 'lastSeen' ? '' : -1;
      if (bv == null) bv = sortField === 'lastSeen' ? '' : -1;
      const col = COLUMNS.find(c => c.field === sortField);
      if (col?.type === 'number') {
        return sortDir === 'desc' ? bv - av : av - bv;
      }
      const cmp = String(av).localeCompare(String(bv));
      return sortDir === 'desc' ? -cmp : cmp;
    });

    return rows;
  }, [data.ips, sortField, sortDir, filters]);

  const { summary, periodSummary } = data;
  const activeFilterCount = Object.keys(filters).length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        <h2 className="text-lg font-semibold text-gray-200">Threat Intel</h2>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
              showFilters || activeFilterCount > 0
                ? 'bg-blue-600/20 border-blue-500/50 text-blue-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
            }`}
          >
            Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}
          </button>
          {activeFilterCount > 0 && (
            <button
              onClick={() => setFilters({})}
              className="px-3 py-1.5 text-xs rounded-lg border bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
            >
              Clear
            </button>
          )}
          <PeriodSelector value={period} onChange={setPeriod} />
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* All-time summary cards */}
        <div className="grid grid-cols-4 gap-3">
          <SummaryCard label="Enriched IPs (All Time)" value={summary.totalEnriched} />
          <SummaryCard label="Flagged IPs (All Time)" value={summary.withAbuseScore} color="text-yellow-400" />
          <SummaryCard label="High Threat 50%+ (All Time)" value={summary.highThreat} color="text-red-400" />
          <SummaryCard label="Countries (All Time)" value={summary.countries} color="text-blue-400" />
        </div>

        {/* Period-filtered summary cards */}
        <div className="grid grid-cols-4 gap-3">
          <SummaryCard label={`Enriched IPs (${period})`} value={periodSummary.enriched} />
          <SummaryCard label={`Flagged IPs (${period})`} value={periodSummary.flagged} color="text-yellow-400" />
          <SummaryCard label={`High Threat 50%+ (${period})`} value={periodSummary.highThreat} color="text-red-400" />
          <SummaryCard label={`Countries (${period})`} value={periodSummary.countries} color="text-blue-400" />
        </div>

        {/* IP table */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="text-xs text-gray-500 px-4 py-2 border-b border-gray-800 flex justify-between">
            <span>{formatNumber(processed.length)} IPs{activeFilterCount > 0 ? ' (filtered)' : ''}</span>
            <span>Click column headers to sort</span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 text-xs">
                {COLUMNS.map(col => (
                  <SortHeader
                    key={col.field}
                    label={col.label}
                    field={col.field}
                    align={col.align}
                    sortField={sortField}
                    sortDir={sortDir}
                    onSort={handleSort}
                  />
                ))}
              </tr>
              {showFilters && (
                <tr className="border-b border-gray-800 bg-gray-800/30">
                  {COLUMNS.map(col => (
                    <th key={col.field} className="px-3 py-2">
                      <input
                        type="text"
                        value={filters[col.field] || ''}
                        onChange={(e) => setFilter(col.field, e.target.value)}
                        placeholder={col.type === 'number' ? '>0, <50...' : 'Filter...'}
                        className="w-full px-2 py-1 text-xs bg-gray-900 border border-gray-700 rounded text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
                      />
                    </th>
                  ))}
                </tr>
              )}
            </thead>
            <tbody>
              {processed.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-gray-500">
                    {activeFilterCount > 0
                      ? 'No IPs match the current filters.'
                      : 'No enriched IPs found for this period. Enrichment runs automatically on external IPs from firewall/threat events.'}
                  </td>
                </tr>
              )}
              {processed.map((ip, i) => (
                <tr key={`${ip.ip}-${i}`} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2.5">
                    <span className="font-mono text-gray-200">{ip.ip}</span>
                  </td>
                  <td className="px-4 py-2.5 text-gray-400 text-xs max-w-[160px] truncate">
                    {ip.hostname || '—'}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-400">
                    {ip.country && <span className="mr-1">{countryFlag(ip.country)}</span>}
                    {ip.city && ip.country ? `${ip.city}, ${ip.country}` : ip.country || '—'}
                  </td>
                  <td className="px-4 py-2.5">
                    <AbuseScoreBar score={ip.abuse_score} />
                  </td>
                  <td className="px-4 py-2.5 text-right text-gray-300 font-medium">
                    {formatNumber(ip.event_count)}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {ip.blocked_count > 0 ? (
                      <span className="text-orange-400 font-medium">{formatNumber(ip.blocked_count)}</span>
                    ) : (
                      <span className="text-gray-600">0</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {ip.threat_count > 0 ? (
                      <span className="text-red-400 font-medium">{formatNumber(ip.threat_count)}</span>
                    ) : (
                      <span className="text-gray-600">0</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right text-xs text-gray-500">
                    {formatDateTime(ip.lastSeen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
