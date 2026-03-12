import React, { useState, useEffect, useRef, useCallback } from 'react';
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup, useMap } from 'react-leaflet';
import PeriodSelector from '../shared/PeriodSelector';
import RefreshControls, { PausedIndicator } from '../shared/RefreshControls';
import { getGeoEvents, getRecentGeoEvents } from '../../lib/api';
import { formatNumber, formatDateTime, countryFlag } from '../../lib/format';
import 'leaflet/dist/leaflet.css';

function isPrivateIp(ip) {
  if (!ip) return false;
  return ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip);
}

function getMarkerColor(event) {
  if (event.threats > 0 || event.abuseScore > 50) return '#ef4444'; // red
  if (event.blocked > 0) return '#f97316'; // orange
  return '#3b82f6'; // blue
}

function getMarkerRadius(count) {
  return Math.max(4, Math.min(14, Math.log2(count + 1) * 3));
}

function getLineColor(event) {
  if (event.action === 'block' || event.event_type === 'threat') return '#ef4444';
  return '#3b82f680';
}

function FlowLines({ events }) {
  // Draw lines from source to destination for events that have both geo coords
  const lines = events
    .filter(e => e.src_geo_lat && e.src_geo_lon && e.dst_geo_lat && e.dst_geo_lon)
    .slice(0, 30); // limit to 30 most recent lines

  return lines.map((e, i) => (
    <Polyline
      key={`line-${e.id}-${i}`}
      positions={[
        [e.src_geo_lat, e.src_geo_lon],
        [e.dst_geo_lat, e.dst_geo_lon],
      ]}
      pathOptions={{
        color: getLineColor(e),
        weight: 1.5,
        opacity: 0.5,
        dashArray: '4 6',
      }}
    />
  ));
}

function MapLegend() {
  return (
    <div className="absolute bottom-4 left-4 z-[1000] bg-gray-900/90 border border-gray-700 rounded-lg p-3 space-y-1.5">
      <div className="text-xs font-medium text-gray-300 mb-1">Legend</div>
      <div className="flex items-center gap-2">
        <span className="w-3 h-3 rounded-full bg-blue-500 inline-block" />
        <span className="text-xs text-gray-400">Normal traffic</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="w-3 h-3 rounded-full bg-orange-500 inline-block" />
        <span className="text-xs text-gray-400">Blocked</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="w-3 h-3 rounded-full bg-red-500 inline-block" />
        <span className="text-xs text-gray-400">Threat / High abuse</span>
      </div>
    </div>
  );
}

function StatsOverlay({ geoEvents, recentEvents }) {
  const totalIPs = geoEvents.length;
  const threatIPs = geoEvents.filter(e => e.threats > 0).length;
  const blockedIPs = geoEvents.filter(e => e.blocked > 0).length;
  const countries = new Set(geoEvents.map(e => e.country).filter(Boolean)).size;

  return (
    <div className="absolute top-4 right-4 z-[1000] bg-gray-900/90 border border-gray-700 rounded-lg p-3 space-y-1">
      <div className="text-xs font-medium text-gray-300 mb-1">Map Stats</div>
      <div className="text-xs text-gray-400">
        <span className="text-gray-200 font-medium">{formatNumber(totalIPs)}</span> IPs plotted
      </div>
      <div className="text-xs text-gray-400">
        <span className="text-gray-200 font-medium">{countries}</span> countries
      </div>
      {blockedIPs > 0 && (
        <div className="text-xs text-orange-400">
          <span className="font-medium">{formatNumber(blockedIPs)}</span> blocked
        </div>
      )}
      {threatIPs > 0 && (
        <div className="text-xs text-red-400">
          <span className="font-medium">{formatNumber(threatIPs)}</span> threats
        </div>
      )}
    </div>
  );
}

const DEFAULT_REFRESH = 60000;

export default function LiveMap({ period, setPeriod }) {
  const [geoEvents, setGeoEvents] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [refreshRate, setRefreshRate] = useState(DEFAULT_REFRESH);
  const [paused, setPaused] = useState(true);
  const fetchRef = useRef(null);

  const doFetch = useCallback(() => {
    setLoading(true);
    Promise.all([
      getGeoEvents(period, 1000),
      getRecentGeoEvents(50),
    ]).then(([geo, recent]) => {
      setGeoEvents(geo);
      setRecentEvents(recent);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [period]);

  useEffect(() => { fetchRef.current = doFetch; }, [doFetch]);

  useEffect(() => {
    doFetch();
    if (paused) return;
    const interval = setInterval(() => fetchRef.current?.(), refreshRate);
    return () => clearInterval(interval);
  }, [doFetch, refreshRate, paused]);

  const filteredEvents = geoEvents.filter(e => !isPrivateIp(e.ip));
  const hasData = filteredEvents.length > 0;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        <h2 className="text-lg font-semibold text-gray-200">Live Map</h2>
        <div className="flex items-center gap-3">
          <RefreshControls
            refreshRate={refreshRate}
            setRefreshRate={setRefreshRate}
            paused={paused}
            setPaused={setPaused}
            onRefresh={() => fetchRef.current?.()}
            loading={loading}
          />
          <PeriodSelector value={period} onChange={setPeriod} />
        </div>
      </div>

      <div className="flex-1 relative">
        {!hasData && (
          <div className="absolute inset-0 z-[1000] flex items-center justify-center bg-gray-950/80">
            <div className="text-center space-y-2">
              <p className="text-gray-400">No geo-enriched events yet</p>
              <p className="text-xs text-gray-600">
                Place GeoLite2-City.mmdb in the data/ directory to enable GeoIP enrichment
              </p>
            </div>
          </div>
        )}

        <MapContainer
          center={[25, 0]}
          zoom={2}
          minZoom={2}
          maxZoom={12}
          className="h-full w-full"
          style={{ background: '#0f172a' }}
          worldCopyJump={true}
        >
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />

          {/* Aggregated IP markers */}
          {filteredEvents.map((event, i) => (
            <CircleMarker
              key={`geo-${event.ip}-${event.direction}-${i}`}
              center={[event.lat, event.lon]}
              radius={getMarkerRadius(event.count)}
              pathOptions={{
                color: getMarkerColor(event),
                fillColor: getMarkerColor(event),
                fillOpacity: 0.6,
                weight: 1,
              }}
            >
              <Popup>
                <div className="text-xs space-y-1 min-w-[180px]">
                  <div className="font-bold text-sm">{event.ip}</div>
                  {event.city && event.country && (
                    <div>{countryFlag(event.country)} {event.city}, {event.country}</div>
                  )}
                  {!event.city && event.country && <div>{countryFlag(event.country)} {event.country}</div>}
                  <div>Events: <strong>{formatNumber(event.count)}</strong></div>
                  {event.blocked > 0 && (
                    <div style={{ color: '#f97316' }}>Blocked: {formatNumber(event.blocked)}</div>
                  )}
                  {event.threats > 0 && (
                    <div style={{ color: '#ef4444' }}>Threats: {formatNumber(event.threats)}</div>
                  )}
                  {event.abuseScore != null && event.abuseScore > 0 && (
                    <div style={{ color: event.abuseScore > 50 ? '#ef4444' : '#eab308' }}>
                      Abuse score: {event.abuseScore}%
                    </div>
                  )}
                  <div style={{ color: '#6b7280' }}>
                    Direction: {event.direction === 'src' ? 'Source' : 'Destination'}
                  </div>
                  <div style={{ color: '#6b7280' }}>Last seen: {formatDateTime(event.lastSeen)}</div>
                </div>
              </Popup>
            </CircleMarker>
          ))}

          {/* Flow lines for recent events */}
          <FlowLines events={recentEvents} />
        </MapContainer>

        <MapLegend />
        <StatsOverlay geoEvents={filteredEvents} recentEvents={recentEvents} />
      </div>
    </div>
  );
}
