import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Wifi, Server, Activity } from 'lucide-react';
import { formatNumber } from '../../lib/format';

function Card({ label, value, icon: Icon, color }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-gray-500 font-medium">{label}</p>
          <p className="text-2xl font-bold text-gray-100 mt-1">{formatNumber(value)}</p>
        </div>
        <Icon className={`w-8 h-8 ${color}`} />
      </div>
    </div>
  );
}

export default function StatsCards({ overview }) {
  if (!overview) return null;
  const { total, byType = {}, firewall = {} } = overview;

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      <Card label="Total Events" value={total} icon={Activity} color="text-blue-400" />
      <Card label="Firewall" value={byType.firewall || 0} icon={Shield} color="text-blue-400" />
      <Card label="Blocked" value={firewall.blocked || 0} icon={ShieldAlert} color="text-red-400" />
      <Card label="Threats" value={firewall.threats || 0} icon={ShieldAlert} color="text-red-500" />
      <Card label="Wi-Fi Events" value={byType.wifi || 0} icon={Wifi} color="text-purple-400" />
      <Card label="DNS Filtered" value={byType.dns_filter || 0} icon={ShieldCheck} color="text-orange-400" />
    </div>
  );
}
