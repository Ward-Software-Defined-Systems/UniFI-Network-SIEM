import React, { useState, useEffect, useCallback, useRef } from 'react';
import PeriodSelector from '../shared/PeriodSelector';
import RefreshControls, { PausedIndicator } from '../shared/RefreshControls';
import StatsCards from './StatsCards';
import Timeline from './Timeline';
import TopTalkers from './TopTalkers';
import TopPorts from './TopPorts';
import TopThreats from './TopThreats';
import TopClients from './TopClients';
import { getStatsOverview, getTimeline, getTopTalkers, getTopBlocked, getTopPorts, getTopThreats, getTopClients } from '../../lib/api';

const TOTAL_QUERIES = 9;

export default function Dashboard({ period, setPeriod, refreshRate, setRefreshRate, paused, setPaused }) {
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
  const [loadProgress, setLoadProgress] = useState({ completed: 0, total: TOTAL_QUERIES, loading: false });
  const fetchRef = useRef(null);

  const doFetch = useCallback(() => {
    const bucket = period === '1h' ? '5m' : period === '6h' ? '15m' : '1h';
    const ep = excludePrivate ? '1' : undefined;

    let completed = 0;
    setLoadProgress({ completed: 0, total: TOTAL_QUERIES, loading: true });

    const track = (promise, setter) =>
      promise.then(data => {
        if (setter) setter(data);
        completed++;
        setLoadProgress({ completed, total: TOTAL_QUERIES, loading: completed < TOTAL_QUERIES });
      }).catch(() => {
        completed++;
        setLoadProgress({ completed, total: TOTAL_QUERIES, loading: completed < TOTAL_QUERIES });
      });

    Promise.all([
      track(getStatsOverview(period), setOverview),
      track(getTimeline(period, bucket), setTimeline),
      track(getTopTalkers(period, 10, 'src'), setTopSrc),
      track(getTopBlocked(period, 10, 'src', ep), setTopBlockedSrc),
      track(getTopBlocked(period, 10, 'dst', ep), setTopBlockedDst),
      track(getTopPorts(period, 10), setTopPorts),
      track(getTopThreats(period, 10), setTopThreats),
      track(getTopClients(period, 10), setTopClients),
      track(getTopTalkers(period, 10, 'dst', ep), setTopDst),
    ]);
  }, [period, excludePrivate]);

  useEffect(() => { fetchRef.current = doFetch; }, [doFetch]);

  // Initial fetch + auto-refresh interval
  useEffect(() => {
    doFetch();
    if (paused) return;
    const interval = setInterval(() => fetchRef.current?.(), refreshRate);
    return () => clearInterval(interval);
  }, [doFetch, refreshRate, paused]);

  return (
    <div className="p-4 space-y-4 overflow-auto h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-200">Dashboard</h2>
        <div className="flex items-center gap-3">
          <RefreshControls
            refreshRate={refreshRate}
            setRefreshRate={setRefreshRate}
            paused={paused}
            setPaused={setPaused}
            onRefresh={() => fetchRef.current?.()}
            loading={loadProgress.loading}
          />
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

      {loadProgress.loading && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span className="flex items-center gap-2">
              <svg className="animate-spin h-3 w-3 text-blue-400" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Loading dashboard data…
            </span>
            <span>{loadProgress.completed}/{loadProgress.total}</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-blue-500 h-1.5 rounded-full transition-all duration-300 ease-out"
              style={{ width: `${(loadProgress.completed / loadProgress.total) * 100}%` }}
            />
          </div>
        </div>
      )}

      <PausedIndicator paused={paused} loading={loadProgress.loading} />

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
