export const EVENT_TYPES = {
  firewall: { label: 'Firewall', color: 'bg-blue-500', text: 'text-blue-400', hex: '#3b82f6' },
  threat: { label: 'Threat', color: 'bg-red-500', text: 'text-red-400', hex: '#ef4444' },
  dhcp: { label: 'DHCP', color: 'bg-green-500', text: 'text-green-400', hex: '#22c55e' },
  dns: { label: 'DNS', color: 'bg-cyan-500', text: 'text-cyan-400', hex: '#06b6d4' },
  dns_filter: { label: 'DNS Filter', color: 'bg-orange-500', text: 'text-orange-400', hex: '#f97316' },
  wifi: { label: 'Wi-Fi', color: 'bg-purple-500', text: 'text-purple-400', hex: '#a855f7' },
  admin: { label: 'Admin', color: 'bg-yellow-500', text: 'text-yellow-400', hex: '#eab308' },
  device: { label: 'Device', color: 'bg-teal-500', text: 'text-teal-400', hex: '#14b8a6' },
  client: { label: 'Client', color: 'bg-indigo-500', text: 'text-indigo-400', hex: '#6366f1' },
  vpn: { label: 'VPN', color: 'bg-emerald-500', text: 'text-emerald-400', hex: '#10b981' },
  system: { label: 'System', color: 'bg-gray-500', text: 'text-gray-400', hex: '#6b7280' },
};

export const ACTION_COLORS = {
  allow: { bg: 'bg-green-900/50', text: 'text-green-400', border: 'border-green-700' },
  block: { bg: 'bg-red-900/50', text: 'text-red-400', border: 'border-red-700' },
  reject: { bg: 'bg-orange-900/50', text: 'text-orange-400', border: 'border-orange-700' },
  drop: { bg: 'bg-red-900/50', text: 'text-red-400', border: 'border-red-700' },
};

export const SEVERITY_LABELS = ['Emergency','Alert','Critical','Error','Warning','Notice','Info','Debug'];
