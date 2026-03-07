const PORT_NAMES = {
  20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
  53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
  123: 'NTP', 143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
  1194: 'OpenVPN', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
  5060: 'SIP', 5353: 'mDNS', 5432: 'PostgreSQL', 6379: 'Redis',
  7000: 'AirPlay', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8883: 'MQTT-TLS',
  9100: 'Printing', 27017: 'MongoDB', 51820: 'WireGuard',
};

function getPortName(port) {
  return PORT_NAMES[port] || null;
}

module.exports = { getPortName, PORT_NAMES };
