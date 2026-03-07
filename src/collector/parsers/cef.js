// Parses CEF (Common Event Format) messages from UniFi Activity Logging
// Format: CEF:0|Vendor|Product|Version|EventClassID|Name|Severity|Extensions
// May have syslog prefix: Mar 07 07:26:58 HOSTNAME CEF:0|...

const CEF_HEADER_RE = /CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)$/;

// Map UNIFIcategory + UNIFIsubCategory to event_type
function mapCefEventType(category, subCategory, eventClassId) {
  const cat = (category || '').toLowerCase();
  const sub = (subCategory || '').toLowerCase();

  if (sub === 'threat' || sub === 'security') return 'threat';
  if (sub === 'admin') return 'admin';
  if (sub === 'device') return 'device';
  if (sub === 'wifi') return 'wifi';
  if (sub === 'client') return 'client';
  if (sub === 'vpn') return 'vpn';

  if (cat === 'audit') return 'admin';
  if (cat === 'security') return 'threat';
  if (cat === 'client devices') return 'client';

  // By event class ID ranges
  const ecid = parseInt(eventClassId, 10);
  if (ecid >= 200 && ecid < 300) return 'threat';
  if (ecid >= 300 && ecid < 400) return 'device';
  if (ecid >= 400 && ecid < 500) return 'wifi';
  if (ecid >= 500 && ecid < 600) return 'admin';

  return 'system';
}

function parseCefExtensions(extensionStr) {
  const extensions = {};
  // CEF extensions are key=value pairs where value runs until the next key=
  // Keys can contain letters/numbers. Values can contain spaces.
  // Special handling for msg= which always comes last and can contain anything
  const msgIdx = extensionStr.indexOf(' msg=');
  let mainPart = extensionStr;
  if (msgIdx !== -1) {
    extensions.msg = extensionStr.slice(msgIdx + 5);
    mainPart = extensionStr.slice(0, msgIdx);
  }

  // Parse remaining key=value pairs
  // Match: word boundary, key (letters/numbers), =, value (until next key= or end)
  const kvRe = /\b([a-zA-Z]\w*)=(.*?)(?=\s+[a-zA-Z]\w+=|$)/g;
  let match;
  while ((match = kvRe.exec(mainPart)) !== null) {
    extensions[match[1]] = match[2].trim();
  }

  return extensions;
}

function parseCef(raw, header) {
  // Find CEF: in the message
  const cefIdx = raw.indexOf('CEF:');
  if (cefIdx === -1) return null;

  const cefPart = raw.slice(cefIdx);
  const match = cefPart.match(CEF_HEADER_RE);
  if (!match) return null;

  const cefVersion = match[1];
  const vendor = match[2];
  const product = match[3];
  const deviceVersion = match[4];
  const eventClassId = match[5];
  const name = match[6];
  const severity = parseInt(match[7], 10);
  const extensionStr = match[8];

  const ext = parseCefExtensions(extensionStr);

  const category = ext.UNIFIcategory || null;
  const subCategory = ext.UNIFIsubCategory || null;
  const eventType = mapCefEventType(category, subCategory, eventClassId);

  const event = {
    event_type: eventType,
    source_format: 'cef',
    severity: header.severity,
    hostname: header.hostname || ext.UNIFIhost,
    timestamp: ext.UNIFIutcTime || header.timestamp,
    cef_event_class_id: eventClassId,
    cef_name: name,
    cef_severity: severity,
    unifi_category: category,
    unifi_subcategory: subCategory,
    unifi_host: ext.UNIFIhost || null,
    message: ext.msg || name,

    // Network fields (if present)
    src_ip: ext.src || null,
    src_port: ext.spt ? parseInt(ext.spt, 10) : null,
    dst_ip: ext.dst || null,
    dst_port: ext.dpt ? parseInt(ext.dpt, 10) : null,
    protocol: ext.proto || null,

    // Threat fields
    threat_type: ext.UNIFIthreatType || null,
    threat_category: ext.UNIFIthreatCategory || null,

    // Client fields
    client_alias: ext.UNIFIclientAlias || null,
    client_mac: ext.UNIFIclientMac || null,
    client_ip: ext.UNIFIclientIp || null,

    // WiFi fields
    wifi_ssid: ext.UNIFIwifiName || null,
    wifi_channel: ext.UNIFIwifiChannel ? parseInt(ext.UNIFIwifiChannel, 10) : null,
    wifi_rssi: ext.UNIFIWiFiRssi ? parseInt(ext.UNIFIWiFiRssi, 10) : null,
  };

  // Threat events get action=block
  if (eventType === 'threat') {
    event.action = 'block';
  }

  return event;
}

module.exports = { parseCef };
