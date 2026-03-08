import React, { useState } from 'react';
import Layout from './components/Layout';
import LiveStream from './components/live/LiveStream';
import Dashboard from './components/dashboard/Dashboard';
import LiveMap from './components/map/LiveMap';
import ThreatIntel from './components/intel/ThreatIntel';
import ThreatHunt from './components/hunt/ThreatHunt';
import Settings from './components/Settings';

export default function App() {
  const [view, setView] = useState('dashboard');
  const [period, setPeriod] = useState('1h');

  return (
    <Layout activeView={view} onViewChange={setView}>
      {view === 'live' && <LiveStream />}
      {view === 'dashboard' && <Dashboard period={period} setPeriod={setPeriod} />}
      {view === 'map' && <LiveMap period={period} setPeriod={setPeriod} />}
      {view === 'intel' && <ThreatIntel period={period} setPeriod={setPeriod} />}
      {view === 'hunt' && <ThreatHunt />}
      {view === 'settings' && <Settings />}
    </Layout>
  );
}
