import React, { useState } from 'react';
import Layout from './components/Layout';
import LiveStream from './components/live/LiveStream';
import Dashboard from './components/dashboard/Dashboard';
import LiveMap from './components/map/LiveMap';
import ThreatIntel from './components/intel/ThreatIntel';
import Settings from './components/Settings';

export default function App() {
  const [view, setView] = useState('dashboard');

  return (
    <Layout activeView={view} onViewChange={setView}>
      {view === 'live' && <LiveStream />}
      {view === 'dashboard' && <Dashboard />}
      {view === 'map' && <LiveMap />}
      {view === 'intel' && <ThreatIntel />}
      {view === 'settings' && <Settings />}
    </Layout>
  );
}
