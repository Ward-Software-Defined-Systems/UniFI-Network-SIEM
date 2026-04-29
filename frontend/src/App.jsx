import React, { useState, lazy, Suspense } from 'react';
import Layout from './components/Layout';
import TokenGate from './components/TokenGate';

const LiveStream = lazy(() => import('./components/live/LiveStream'));
const Dashboard = lazy(() => import('./components/dashboard/Dashboard'));
const LiveMap = lazy(() => import('./components/map/LiveMap'));
const ThreatIntel = lazy(() => import('./components/intel/ThreatIntel'));
const ThreatHunt = lazy(() => import('./components/hunt/ThreatHunt'));
const Settings = lazy(() => import('./components/Settings'));

const DEFAULT_REFRESH = 60000;

function ViewFallback() {
  return (
    <div className="flex items-center justify-center py-16 text-gray-500">
      Loading…
    </div>
  );
}

export default function App() {
  const [view, setView] = useState('dashboard');
  const [period, setPeriod] = useState('1h');
  const [refreshRate, setRefreshRate] = useState(DEFAULT_REFRESH);
  const [paused, setPaused] = useState(true);
  const [rebuilding, setRebuilding] = useState(false);

  const refreshProps = { refreshRate, setRefreshRate, paused, setPaused };

  return (
    <TokenGate>
      <Layout activeView={view} onViewChange={setView} rebuilding={rebuilding} setRebuilding={setRebuilding}>
        <Suspense fallback={<ViewFallback />}>
          {view === 'live' && <LiveStream />}
          {view === 'dashboard' && <Dashboard period={period} setPeriod={setPeriod} {...refreshProps} />}
          {view === 'map' && <LiveMap period={period} setPeriod={setPeriod} {...refreshProps} />}
          {view === 'intel' && <ThreatIntel period={period} setPeriod={setPeriod} {...refreshProps} />}
          {view === 'hunt' && <ThreatHunt period={period} setPeriod={setPeriod} />}
          {view === 'settings' && <Settings setRebuilding={setRebuilding} />}
        </Suspense>
      </Layout>
    </TokenGate>
  );
}
