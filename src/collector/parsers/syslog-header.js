// Parses syslog header from multiple UniFi device formats:
// 1. Standard:    <N>Mon DD HH:MM:SS HOSTNAME message
// 2. MAC prefix:  <N>Mon DD HH:MM:SS HOSTNAME MAC,Model-Version: process[PID]: message
// 3. ECS switch:  MAC,Model-Version Mon DD HH:MM:SS HOSTNAME facility.severity process[PID]: message
// 4. Doubled hostname (UDM-SE): <N>Mon DD HH:MM:SS HOSTNAME HOSTNAME process[PID]: message
// 5. CEF syslog:  Mon DD HH:MM:SS HOSTNAME CEF:0|...

const FACILITY_SEVERITY_MAP = {
  'kern.emerg': 0, 'kern.alert': 1, 'kern.crit': 2, 'kern.err': 3,
  'kern.warning': 4, 'kern.notice': 5, 'kern.info': 6, 'kern.debug': 7,
  'user.emerg': 8, 'user.alert': 9, 'user.crit': 10, 'user.err': 11,
  'user.warning': 12, 'user.notice': 13, 'user.info': 14, 'user.debug': 15,
  'daemon.emerg': 24, 'daemon.alert': 25, 'daemon.crit': 26, 'daemon.err': 27,
  'daemon.warning': 28, 'daemon.notice': 29, 'daemon.info': 30, 'daemon.debug': 31,
};

const SEVERITY_FROM_TEXT = {
  emerg: 0, alert: 1, crit: 2, err: 3, warning: 4, notice: 5, info: 6, debug: 7,
};

// Standard syslog priority <N>
const PRIORITY_RE = /^<(\d{1,3})>/;

// MAC,Model-Version prefix (e.g., "d8b3706f246b,USW-Enterprise-8-PoE-7.3.125+16842:")
const MAC_MODEL_RE = /^([0-9a-f]{12},[A-Za-z0-9._-]+\+\d+):?\s*/;

// Syslog timestamp: Mon DD HH:MM:SS
const TIMESTAMP_RE = /^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+/;

// Text facility.severity (ECS switches): daemon.info, user.err, kern.warning
const FACILITY_SEV_RE = /^([a-z]+\.(?:emerg|alert|crit|err|warning|notice|info|debug))\s+/;

function parseSyslogHeader(raw) {
  let remaining = raw;
  let priority = null;
  let severity = null;
  let hostname = null;
  let macModel = null;
  let timestamp = null;

  // Format 3: ECS switch — MAC,Model prefix with no <N>
  // e.g., "942a6f40d752,ECS-Aggregation-3.0.2+821 Mar  7 07:25:08 WSDS-ECS-Agg daemon.info ..."
  let macMatch = remaining.match(MAC_MODEL_RE);
  if (macMatch && !remaining.startsWith('<')) {
    macModel = macMatch[1];
    remaining = remaining.slice(macMatch[0].length);

    // Parse timestamp
    const tsMatch = remaining.match(TIMESTAMP_RE);
    if (tsMatch) {
      timestamp = tsMatch[1];
      remaining = remaining.slice(tsMatch[0].length);
    }

    // Parse hostname
    const hostMatch = remaining.match(/^(\S+)\s+/);
    if (hostMatch) {
      hostname = hostMatch[1];
      remaining = remaining.slice(hostMatch[0].length);
    }

    // Parse facility.severity
    const facMatch = remaining.match(FACILITY_SEV_RE);
    if (facMatch) {
      const facSev = facMatch[1];
      const sevText = facSev.split('.')[1];
      severity = SEVERITY_FROM_TEXT[sevText] ?? 6;
      priority = FACILITY_SEVERITY_MAP[facSev] ?? null;
      remaining = remaining.slice(facMatch[0].length);
    }

    return { priority, severity, timestamp, hostname, macModel, message: remaining };
  }

  // Format 1/2/4/5: Standard syslog with optional <N>
  const priMatch = remaining.match(PRIORITY_RE);
  if (priMatch) {
    priority = parseInt(priMatch[1], 10);
    severity = priority & 0x7; // low 3 bits
    remaining = remaining.slice(priMatch[0].length);
  }

  // Parse timestamp
  const tsMatch = remaining.match(TIMESTAMP_RE);
  if (tsMatch) {
    timestamp = tsMatch[1];
    remaining = remaining.slice(tsMatch[0].length);
  }

  // Format 5: CEF without <N> — "Mon DD HH:MM:SS HOSTNAME CEF:..."
  if (!priMatch && !tsMatch) {
    // Check for bare timestamp at start (CEF syslog)
    const bareTsMatch = raw.match(TIMESTAMP_RE);
    if (bareTsMatch) {
      timestamp = bareTsMatch[1];
      remaining = raw.slice(bareTsMatch[0].length);
    }
  }

  // Parse hostname
  const hostMatch = remaining.match(/^(\S+)\s+/);
  if (hostMatch) {
    hostname = hostMatch[1];
    remaining = remaining.slice(hostMatch[0].length);
  }

  // Format 2: MAC,Model prefix after hostname
  // e.g., "WSDS-U5GMax 1c0b8b082dea,U5G-Max-7.3.37+18253: ubnt-fanctrl[553]: ..."
  macMatch = remaining.match(MAC_MODEL_RE);
  if (macMatch) {
    macModel = macMatch[1];
    remaining = remaining.slice(macMatch[0].length);
  }

  // Format 4: Doubled hostname (UDM-SE quirk)
  // e.g., after removing "<30>Mar 7 07:28:23 WSDS-UDM-SE" we have "WSDS-UDM-SE dnsmasq-dhcp[...]"
  if (hostname && remaining.startsWith(hostname + ' ')) {
    remaining = remaining.slice(hostname.length + 1);
  }

  return { priority, severity, timestamp, hostname, macModel, message: remaining };
}

module.exports = { parseSyslogHeader };
