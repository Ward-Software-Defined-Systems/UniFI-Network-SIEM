import React, { useState } from 'react';
import Layout from './components/Layout';
import LiveStream from './components/live/LiveStream';
import Dashboard from './components/dashboard/Dashboard';
import LiveMap from './components/map/LiveMap';
import ThreatIntel from './components/intel/ThreatIntel';
import ThreatHunt from './components/hunt/ThreatHunt';
import Settings from './components/Settings';

const DEFAULT_REFRESH = 60000;

export default function App() {
  const [view, setView] = useState('dashboard');
  const [period, setPeriod] = useState('1h');
  const [refreshRate, setRefreshRate] = useState(DEFAULT_REFRESH);
  const [paused, setPaused] = useState(true);

  const refreshProps = { refreshRate, setRefreshRate, paused, setPaused };

  return (
    <Layout activeView={view} onViewChange={setView}>
      {view === 'live' && <LiveStream />}
      {view === 'dashboard' && <Dashboard period={period} setPeriod={setPeriod} {...refreshProps} />}
      {view === 'map' && <LiveMap period={period} setPeriod={setPeriod} {...refreshProps} />}
      {view === 'intel' && <ThreatIntel period={period} setPeriod={setPeriod} {...refreshProps} />}
      {view === 'hunt' && <ThreatHunt />}
      {view === 'settings' && <Settings />}
    </Layout>
  );
}
