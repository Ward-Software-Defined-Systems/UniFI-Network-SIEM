#!/usr/bin/env node
// Sends test syslog messages to localhost for development/testing
const dgram = require('dgram');

const PORT = parseInt(process.env.SYSLOG_PORT || '5514', 10);
const HOST = '127.0.0.1';
const RATE = parseInt(process.env.RATE || '10', 10); // messages per second

function randomIp(prefix) {
  if (prefix) return `${prefix}.${Math.floor(Math.random() * 254) + 1}`;
  return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
}

function randomMac() {
  return Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':');
}

function randomPort() {
  return Math.floor(Math.random() * 64000) + 1024;
}

function ts() {
  const d = new Date();
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${months[d.getMonth()]}  ${String(d.getDate()).padStart(2)} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
}

const samples = [
  // Firewall allow (inter-VLAN) — actual UDM-SE format
  () => `<13>${ts()} WSDS-UDM-SE [LAN_CUSTOM1-A-10000] DESCR="OpNet_TO_Axiom" IN=br4 OUT=br10 MAC=60:22:32:80:f9:e0:${randomMac()}:08:00 SRC=${randomIp('172.16.4')} DST=${randomIp('172.16.10')} LEN=64 TOS=00 PREC=0x00 TTL=63 ID=0 DF PROTO=TCP SPT=${randomPort()} DPT=7000 SEQ=${Math.floor(Math.random()*4294967295)} ACK=0 WINDOW=65535 SYN URGP=0 MARK=1a0000`,

  // Firewall allow (outbound)
  () => `<6>${ts()} WSDS-UDM-SE [CUSTOM1_LAN-A-10001] DESCR="Allow_Outbound" IN=br4 OUT=eth8 MAC=60:22:32:80:f9:e0:${randomMac()}:08:00 SRC=${randomIp('172.16.4')} DST=${randomIp()} LEN=52 TOS=00 PREC=0x00 TTL=64 ID=${Math.floor(Math.random()*65535)} DF PROTO=TCP SPT=${randomPort()} DPT=443 SEQ=${Math.floor(Math.random()*4294967295)} ACK=0 WINDOW=65535 SYN URGP=0 MARK=0`,

  // Firewall block (inbound)
  () => `<4>${ts()} WSDS-UDM-SE [WAN_CUSTOM1-D-20000] DESCR="Block_Inbound" IN=eth8 OUT= MAC=60:22:32:80:f9:e0:${randomMac()}:08:00 SRC=${randomIp()} DST=172.16.8.254 LEN=44 TOS=00 PREC=0x00 TTL=53 ID=0 DF PROTO=TCP SPT=80 DPT=22 SEQ=0 ACK=0 WINDOW=1024 SYN URGP=0 MARK=0`,

  // IDS/IPS (Suricata)
  () => `<1>${ts()} WSDS-UDM-SE suricata[1234]: [1:2027865:3] ET INFO Observed DNS Query to .cloud TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} ${randomIp('172.16.4')}:${randomPort()} -> 1.1.1.1:53`,

  // DHCP (dnsmasq)
  () => `<30>${ts()} WSDS-UDM-SE WSDS-UDM-SE dnsmasq-dhcp[3861005]: DHCPACK(br4) ${randomIp('172.16.4')} ${randomMac()} TestDevice`,
  () => `<30>${ts()} WSDS-UDM-SE WSDS-UDM-SE dnsmasq-dhcp[3861005]: DHCPREQUEST(br4) ${randomIp('172.16.4')} ${randomMac()}`,
  () => `<30>${ts()} WSDS-UDM-SE WSDS-UDM-SE dnsmasq-dhcp[3861005]: DHCPDISCOVER(br8) ${randomMac()}`,

  // CoreDNS ad-block
  () => {
    const domain = ['www.googletagmanager.com','logs.netflix.com','ads.google.com','tracking.facebook.com','browser-intake-datadoghq.com'][Math.floor(Math.random()*5)];
    const ip = randomIp('172.16.4');
    return `<13>${ts()} WSDS-UDM-SE WSDS-UDM-SE coredns[2464464]: {"timestamp":"${new Date().toISOString()}","unix_milli_timestamp":${Date.now()},"type":"dnsAdBlock","category":"ADVERTISEMENT","domain":"${domain}","ip":"${ip}","mac":"${randomMac()}","src_ip":"${ip}","src_port":${randomPort()},"dst_ip":"127.0.0.1","dst_port":1053,"protocol":"udp"}`;
  },

  // CoreDNS content filter
  () => {
    const ip = randomIp('172.16.8');
    return `<13>${ts()} WSDS-UDM-SE WSDS-UDM-SE coredns[2464464]: {"timestamp":"${new Date().toISOString()}","unix_milli_timestamp":${Date.now()},"type":"contentFilteringBlock","category":"ANONYMIZERS","domain":"download.wireguard.com","ip":"${ip}","mac":"${randomMac()}","src_ip":"${ip}","src_port":${randomPort()},"dst_ip":"127.0.0.1","dst_port":1053,"protocol":"udp"}`;
  },

  // Wi-Fi (hostapd) — actual AP format
  () => `<14>${ts()} WSDS-U7-ProWA 28704e551ced,U7-Pro-Wall-8.5.11+18612: hostapd[10034]: wifi2ap6: STA ${randomMac()} IEEE 802.11: associated (aid 1)`,
  () => `<14>${ts()} WSDS-U7-ProWA 28704e551ced,U7-Pro-Wall-8.5.11+18612: hostapd[10034]: wifi2ap6: STA ${randomMac()} IEEE 802.11: disassociated`,
  () => `<13>${ts()} WSDS-U7-ProWB 28704e551c25,U7-Pro-Wall-8.5.11+18612: hostapd[10035]: wifi2ap6: AP-STA-CONNECTED ${randomMac()}`,
  () => `<13>${ts()} WSDS-U7-ProWB 28704e551c25,U7-Pro-Wall-8.5.11+18612: hostapd[10035]: wifi2ap6: AP-STA-DISCONNECTED ${randomMac()}`,

  // CEF: Admin access
  () => `${ts()} WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|544|Admin Accessed UniFi Network|4|src=172.16.8.129 UNIFIcategory=Audit UNIFIhost=WSDS-UDM-SE UNIFIaccessMethod=web UNIFIadmin=TestUser UNIFIutcTime=${new Date().toISOString()} msg=TestUser accessed UniFi Network using the web. Source IP: 172.16.8.129`,

  // CEF: Config change
  () => `${ts()} WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|546|Admin Made Config Changes|5|src=172.16.8.129 UNIFIcategory=Audit UNIFIhost=WSDS-UDM-SE UNIFIsettingsSection=Firewall UNIFIadmin=TestUser cnt=2 UNIFIutcTime=${new Date().toISOString()} msg=TestUser made 2 changes to Firewall settings.`,

  // CEF: WiFi client roam
  () => `${ts()} WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|402|WiFi Client Roamed|1|UNIFIcategory=Client Devices UNIFIhost=WSDS-UDM-SE UNIFIclientAlias=TestPhone UNIFIclientMac=${randomMac()} UNIFIclientIp=${randomIp('172.16.4')} UNIFIwifiName=OpNet UNIFIwifiChannel=197 UNIFIWiFiRssi=-${Math.floor(Math.random()*40+50)} UNIFIutcTime=${new Date().toISOString()} msg=TestPhone roamed between APs`,

  // CEF: Threat
  () => `${ts()} WSDS-UDM-SE CEF:0|Ubiquiti|UniFi Network|10.2.84|201|Threat Detected and Blocked|7|proto=TCP src=${randomIp('172.16.4')} spt=${randomPort()} dst=${randomIp()} dpt=443 UNIFIcategory=Security UNIFIsubCategory=Threat UNIFIthreatType=Malware UNIFIthreatCategory=Command and Control UNIFIutcTime=${new Date().toISOString()} msg=Malware callback blocked`,

  // ECS switch system message
  () => `942a6f40d752,ECS-Aggregation-3.0.2+821 ${ts()} WSDS-ECS-Agg daemon.info swss#autodetectd[125]: [${Math.floor(Math.random()*9999999)}.${Math.floor(Math.random()*999999)}][INFO WAIT2] Port: Ethernet52, Status: WAIT2`,

  // DHCP relay from switch
  () => `942a6f40d752,ECS-Aggregation-3.0.2+821 ${ts()} WSDS-ECS-Agg daemon.info dhcp_relay#dhcpsnpd[34]: ACK received: ifname Ethernet46, src_ip 172.16.4.254, src_mac 60:22:32:80:f9:e0, chaddr ${randomMac()}, yiaddr ${randomIp('172.16.4')}.`,

  // System messages
  () => `<14>${ts()} WSDS-UDM-SE WSDS-UDM-SE ubios-udapi-server[2200]: ubnt-systool: Updated device info`,
  () => `<6>${ts()} WSDS-UDM-SE WSDS-UDM-SE kernel: [12345.678901] br0: port 1(eth0) entered forwarding state`,

  // VPN
  () => `<14>${ts()} WSDS-UDM-SE WSDS-UDM-SE ubios-udapi-server[2200]: wireguard: Site-to-site Wireguard Peer (#1000) has got peer bD9I... ${randomIp()}:${randomPort()} (via wgsts1000 0.0.0.0/0) connected`,
];

const client = dgram.createSocket('udp4');

let count = 0;
const interval = setInterval(() => {
  for (let i = 0; i < RATE; i++) {
    const gen = samples[Math.floor(Math.random() * samples.length)];
    const msg = Buffer.from(gen());
    client.send(msg, 0, msg.length, PORT, HOST);
    count++;
  }
}, 1000);

console.log(`Sending ${RATE} messages/sec to ${HOST}:${PORT}. Press Ctrl+C to stop.`);

process.on('SIGINT', () => {
  clearInterval(interval);
  client.close();
  console.log(`\nSent ${count} messages total.`);
  process.exit(0);
});
