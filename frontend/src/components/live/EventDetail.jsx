import React from 'react';
import EventTypeBadge from '../shared/EventTypeBadge';
import ActionBadge from '../shared/ActionBadge';
import SeverityBadge from '../shared/SeverityBadge';
import { formatDateTime } from '../../lib/format';
import { X } from 'lucide-react';

function Field({ label, value }) {
  if (value == null || value === '') return null;
  return (
    <div className="flex gap-2 py-1">
      <span className="text-gray-500 text-xs w-32 shrink-0">{label}</span>
      <span className="text-gray-200 text-xs font-mono break-all">{String(value)}</span>
    </div>
  );
}

export default function EventDetail({ event, onClose }) {
  if (!event) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-gray-900 border-l border-gray-700 shadow-2xl z-50 overflow-y-auto">
      <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <EventTypeBadge type={event.event_type} />
          <ActionBadge action={event.action} />
          <SeverityBadge severity={event.severity} />
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-white">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="p-4 space-y-1">
        <Field label="Time" value={formatDateTime(event.received_at)} />
        <Field label="Hostname" value={event.hostname} />
        <Field label="Source Format" value={event.source_format} />
        <Field label="Message" value={event.message} />

        {(event.src_ip || event.dst_ip) && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">Network</span>
            </div>
            <Field label="Direction" value={event.direction} />
            <Field label="Protocol" value={event.protocol} />
            <Field label="Source IP" value={event.src_ip} />
            <Field label="Source Port" value={event.src_port} />
            <Field label="Dest IP" value={event.dst_ip} />
            <Field label="Dest Port" value={event.dst_port} />
            <Field label="Interface In" value={event.interface_in} />
            <Field label="Interface Out" value={event.interface_out} />
            <Field label="Rule" value={event.rule_prefix} />
            <Field label="Packet Length" value={event.packet_length} />
            <Field label="TTL" value={event.ttl} />
            <Field label="TCP Flags" value={event.tcp_flags} />
            <Field label="MAC Src" value={event.mac_src} />
            <Field label="MAC Dst" value={event.mac_dst} />
          </>
        )}

        {event.ids_signature && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">IDS/IPS</span>
            </div>
            <Field label="Signature" value={event.ids_signature} />
            <Field label="Signature ID" value={event.ids_signature_id} />
            <Field label="Classification" value={event.ids_classification} />
            <Field label="Priority" value={event.ids_priority} />
          </>
        )}

        {event.threat_type && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">Threat</span>
            </div>
            <Field label="Threat Type" value={event.threat_type} />
            <Field label="Category" value={event.threat_category} />
          </>
        )}

        {event.dhcp_action && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">DHCP</span>
            </div>
            <Field label="Action" value={event.dhcp_action} />
            <Field label="IP" value={event.dhcp_ip} />
            <Field label="MAC" value={event.dhcp_mac} />
            <Field label="Hostname" value={event.dhcp_hostname} />
            <Field label="Interface" value={event.dhcp_interface} />
          </>
        )}

        {event.dns_name && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">DNS</span>
            </div>
            <Field label="Action" value={event.dns_action} />
            <Field label="Domain" value={event.dns_name} />
            <Field label="Type" value={event.dns_type} />
            <Field label="Result" value={event.dns_result} />
            <Field label="Client IP" value={event.dns_client_ip} />
            <Field label="Filter Type" value={event.dns_filter_type} />
            <Field label="Filter Category" value={event.dns_filter_category} />
          </>
        )}

        {event.wifi_client_mac && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">Wi-Fi</span>
            </div>
            <Field label="Action" value={event.wifi_action} />
            <Field label="Client MAC" value={event.wifi_client_mac} />
            <Field label="Radio" value={event.wifi_radio} />
            <Field label="SSID" value={event.wifi_ssid} />
            <Field label="Channel" value={event.wifi_channel} />
            <Field label="RSSI" value={event.wifi_rssi} />
          </>
        )}

        {event.cef_name && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">CEF</span>
            </div>
            <Field label="Event" value={event.cef_name} />
            <Field label="Class ID" value={event.cef_event_class_id} />
            <Field label="Severity" value={event.cef_severity} />
            <Field label="Category" value={event.unifi_category} />
            <Field label="Sub-Category" value={event.unifi_subcategory} />
            <Field label="Host" value={event.unifi_host} />
            <Field label="Client Alias" value={event.client_alias} />
            <Field label="Client MAC" value={event.client_mac} />
            <Field label="Client IP" value={event.client_ip} />
          </>
        )}

        {(event.src_geo_country || event.src_abuse_score != null) && (
          <>
            <div className="border-t border-gray-800 mt-3 pt-2 mb-1">
              <span className="text-gray-400 text-xs font-medium">Enrichment</span>
            </div>
            <Field label="Src Country" value={event.src_geo_country} />
            <Field label="Src City" value={event.src_geo_city} />
            <Field label="Dst Country" value={event.dst_geo_country} />
            <Field label="Dst City" value={event.dst_geo_city} />
            <Field label="Src Abuse Score" value={event.src_abuse_score} />
            <Field label="Dst Abuse Score" value={event.dst_abuse_score} />
            <Field label="Src Hostname" value={event.src_hostname} />
            <Field label="Dst Hostname" value={event.dst_hostname} />
          </>
        )}
      </div>
    </div>
  );
}
