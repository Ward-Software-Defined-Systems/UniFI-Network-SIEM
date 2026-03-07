// Parser router: detects message format and dispatches to the correct parser
const { parseSyslogHeader } = require('./syslog-header');
const { parseFirewall, isFirewallMessage } = require('./firewall');
const { parseIds } = require('./ids');
const { parseDhcp } = require('./dhcp');
const { parseDhcpRelay } = require('./dhcp-relay');
const { parseDns } = require('./dns');
const { parseCoreDns } = require('./coredns');
const { parseWifi } = require('./wifi');
const { parseCef } = require('./cef');
const { parseSystem } = require('./system');
const logger = require('../../utils/logger');

function parseMessage(raw) {
  try {
    const rawStr = typeof raw === 'string' ? raw : raw.toString('utf8');

    // 1. CEF detection — can appear with or without syslog header
    if (rawStr.includes('CEF:')) {
      const header = parseSyslogHeader(rawStr);
      const event = parseCef(rawStr, header);
      if (event) return event;
    }

    // Parse syslog header for all non-CEF messages
    const header = parseSyslogHeader(rawStr);
    const msg = header.message;

    // 2. CoreDNS JSON logs (dns_filter)
    if (msg.includes('coredns[') || (rawStr.includes('coredns[') && msg.includes('{'))) {
      return parseCoreDns(msg, header);
    }

    // 3. Firewall (iptables) — detect by [RULE_PREFIX] + IN= + SRC=
    if (isFirewallMessage(rawStr)) {
      const event = parseFirewall(rawStr, header);
      if (event) return event;
    }

    // 4. Suricata IDS/IPS
    if (msg.includes('suricata[') || msg.includes('suricata:')) {
      return parseIds(msg, header);
    }

    // 5. DHCP (dnsmasq-dhcp)
    if (msg.includes('dnsmasq-dhcp[') || msg.includes('dnsmasq-dhcp:')) {
      return parseDhcp(msg, header);
    }

    // 6. DHCP relay (switches)
    if (msg.includes('dhcp_relay#dhcpsnpd') || msg.includes('dhcpsnpd[')) {
      return parseDhcpRelay(msg, header);
    }

    // 7. DNS (dnsmasq without -dhcp)
    if ((msg.includes('dnsmasq[') || msg.includes('dnsmasq:')) && !msg.includes('dnsmasq-dhcp')) {
      return parseDns(msg, header);
    }

    // 8. Wi-Fi (hostapd)
    if (msg.includes('hostapd[') || msg.includes('hostapd:')) {
      return parseWifi(msg, header);
    }

    // 9. VPN events from ubios-udapi-server
    if (msg.includes('wireguard:') || msg.includes('EVT_VPN')) {
      const sysEvent = parseSystem(msg, header);
      sysEvent.event_type = 'vpn';
      return sysEvent;
    }

    // 10. System (catch-all)
    return parseSystem(msg, header);
  } catch (err) {
    logger.debug({ err, raw: typeof raw === 'string' ? raw.slice(0, 200) : '' }, 'Failed to parse syslog message');
    return {
      event_type: 'system',
      source_format: 'raw',
      message: typeof raw === 'string' ? raw.slice(0, 500) : raw.toString('utf8').slice(0, 500),
    };
  }
}

module.exports = { parseMessage };
