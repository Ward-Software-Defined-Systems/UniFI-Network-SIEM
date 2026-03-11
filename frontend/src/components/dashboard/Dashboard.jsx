import React, { useState, useEffect } from 'react';
import PeriodSelector from '../shared/PeriodSelector';
import StatsCards from './StatsCards';
import Timeline from './Timeline';
import TopTalkers from './TopTalkers';
import TopPorts from './TopPorts';
import TopThreats from './TopThreats';
import TopClients from './TopClients';
import { getStatsOverview, getTimeline, getTopTalkers, getTopBlocked, getTopPorts, getTopThreats, getTopClients } from '../../lib/api';

export default function Dashboard({ period, setPeriod }) {
  const [excludePrivate, setExcludePrivate] = useState(true);
  const [overview, setOverview] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [topSrc, setTopSrc] = useState([]);
  const [topBlockedSrc, setTopBlockedSrc] = useState([]);
  const [topBlockedDst, setTopBlockedDst] = useState([]);
  const [topPorts, setTopPorts] = useState([]);
  const [topThreats, setTopThreats] = useState([]);
  const [topClients, setTopClients] = useState([]);
  const [topDst, setTopDst] = useState([]);

  useEffect(() => {
    const bucket = period === '1h' ? '5m' : period === '6h' ? '15m' : '1h';
    const ep = excludePrivate ? '1' : undefined;

    let cancelled = false;

    const fetchAll = () => {
      Promise.all([
        getStatsOverview(period),
        getTimeline(period, bucket),
        getTopTalkers(period, 10, 'src'),
        getTopBlocked(period, 10, 'src', ep),
        getTopBlocked(period, 10, 'dst', ep),
        getTopPorts(period, 10),
        getTopThreats(period, 10),
        getTopClients(period, 10),
        getTopTalkers(period, 10, 'dst', ep),
      ]).then(([overview, timeline, src, blockedSrc, blockedDst, ports, threats, clients, dst]) => {
        if (cancelled) return;
        setOverview(overview);
        setTimeline(timeline);
        setTopSrc(src);
        setTopBlockedSrc(blockedSrc);
        setTopBlockedDst(blockedDst);
        setTopPorts(ports);
        setTopThreats(threats);
        setTopClients(clients);
        setTopDst(dst);
      }).catch(() => {});
    };

    fetchAll();
    const interval = setInterval(fetchAll, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [period, excludePrivate]);

  return (
    <div className="p-4 space-y-4 overflow-auto h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-200">Dashboard</h2>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setExcludePrivate(!excludePrivate)}
            className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
              excludePrivate
                ? 'bg-blue-600/20 border-blue-500/50 text-blue-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
            }`}
          >
            {excludePrivate ? 'Private IPs hidden' : 'Showing all IPs'}
          </button>
          <PeriodSelector value={period} onChange={setPeriod} />
        </div>
      </div>

      <StatsCards overview={overview} />
      <Timeline data={timeline} />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <TopTalkers data={topBlockedDst} title="Top Blocked Destinations" />
        <TopTalkers data={topBlockedSrc} title="Top Blocked Sources" />
        <TopThreats data={topThreats} />
        <TopPorts data={topPorts} />
        <TopClients data={topClients} />
        <TopTalkers data={topSrc} title="Top Sources" />
        <TopTalkers data={topDst} title="Top Destinations" />
      </div>
    </div>
  );
}
