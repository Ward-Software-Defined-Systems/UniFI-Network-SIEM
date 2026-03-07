const EVENT_TYPES = {
  FIREWALL: 'firewall',
  THREAT: 'threat',
  DHCP: 'dhcp',
  DNS: 'dns',
  DNS_FILTER: 'dns_filter',
  WIFI: 'wifi',
  ADMIN: 'admin',
  DEVICE: 'device',
  CLIENT: 'client',
  VPN: 'vpn',
  SYSTEM: 'system',
};

const VALID_EVENT_TYPES = new Set(Object.values(EVENT_TYPES));

function isValidEventType(type) {
  return VALID_EVENT_TYPES.has(type);
}

module.exports = { EVENT_TYPES, VALID_EVENT_TYPES, isValidEventType };
