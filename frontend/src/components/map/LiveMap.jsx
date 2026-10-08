import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup } from 'react-leaflet';
import PeriodSelector from '../shared/PeriodSelector';
import RefreshControls, { PausedIndicator } from '../shared/RefreshControls';
import { getGeoEvents, getRecentGeoEvents, getMapConfig } from '../../lib/api';
import { formatNumber, formatDateTime, countryFlag } from '../../lib/format';
import 'leaflet/dist/leaflet.css';
import { isPrivateIp } from '../../lib/ip-utils';
import MaplibreLayer from './MaplibreLayer';

// Used only when /api/map/config itself is unreachable. The server normally
// supplies the same descriptor as `rasterFallback` (src/map/providers.js).
const CLIENT_FALLBACK = {
  provider: 'osm',
  kind: 'raster',
  label: 'OpenStreetMap',
  url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors',
  maxZoom: 19,
  dark: false,
};

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
    <div className="absolute bottom-4 left-4 z-1000 bg-gray-900/90 border border-gray-700 rounded-lg p-3 space-y-1.5">
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
    <div className="absolute top-4 right-4 z-1000 bg-gray-900/90 border border-gray-700 rounded-lg p-3 space-y-1">
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

// Dismissible strip between the header and the map for provider warnings
// (no CARTO key, invalid custom URL), the WebGL fallback, and stale-CSP hints.
function MapNotice({ notice, onDismiss }) {
  if (!notice) return null;
  const tone = notice.level === 'error'
    ? 'bg-red-900/30 border-red-800/50 text-red-300'
    : 'bg-yellow-900/30 border-yellow-800/50 text-yellow-300';
  return (
    <div className={`mx-4 mt-2 px-3 py-2 text-xs border rounded-sm flex items-start justify-between gap-3 ${tone}`}>
      <span>{notice.text}</span>
      <button onClick={onDismiss} className="text-gray-400 hover:text-gray-200 leading-none" title="Dismiss">×</button>
    </div>
  );
}

export default function LiveMap({ period, setPeriod, refreshRate, setRefreshRate, paused, setPaused }) {
  const [geoEvents, setGeoEvents] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [mapConfig, setMapConfig] = useState(null);
  const [glFailed, setGlFailed] = useState(false);
  const [notice, setNotice] = useState(null);
  const fetchRef = useRef(null);

  // Basemap provider — resolved server-side from the map.* settings, so a
  // Settings change shows up the next time this view mounts.
  useEffect(() => {
    let cancelled = false;
    getMapConfig()
      .then((cfg) => {
        if (cancelled) return;
        setMapConfig(cfg);
        if (cfg.warning) setNotice({ level: 'warn', text: cfg.warning });
      })
      .catch((err) => {
        if (cancelled) return;
        setMapConfig(CLIENT_FALLBACK);
        setNotice({ level: 'error', text: `Could not load the map provider settings (${err.message}); showing OpenStreetMap tiles.` });
      });
    return () => { cancelled = true; };
  }, []);

  // A page's CSP is fixed when it loads. If the provider's host changed after
  // that (custom raster), the browser blocks the tiles silently — say so.
  useEffect(() => {
    const onViolation = (e) => {
      const directive = e.violatedDirective || e.effectiveDirective || '';
      if (/^(img-src|connect-src|worker-src)/.test(directive)) {
        setNotice({ level: 'warn', text: 'The browser blocked map tiles under this page\'s security policy — the map provider changed after the page loaded. Reload the page to apply the new provider.' });
      }
    };
    document.addEventListener('securitypolicyviolation', onViolation);
    return () => document.removeEventListener('securitypolicyviolation', onViolation);
  }, []);

  useEffect(() => {
    let cancelled = false;

    const doFetch = () => {
      if (cancelled) return;
      setLoading(true);
      Promise.all([
        getGeoEvents(period, 1000),
        getRecentGeoEvents(50),
      ]).then(([geo, recent]) => {
        if (cancelled) return;
        setGeoEvents(geo);
        setRecentEvents(recent);
      }).catch(() => {}).finally(() => {
        if (!cancelled) setLoading(false);
      });
    };

    fetchRef.current = doFetch;
    doFetch();
    if (paused) return () => { cancelled = true; };
    const interval = setInterval(doFetch, refreshRate);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [period, refreshRate, paused]);

  const filteredEvents = geoEvents.filter(e => !isPrivateIp(e.ip));
  const hasData = filteredEvents.length > 0;

  const basemap = mapConfig
    ? (glFailed ? (mapConfig.rasterFallback || CLIENT_FALLBACK) : mapConfig)
    : null;
  const isVector = basemap?.kind === 'vector';

  const onGlFail = (err) => {
    setGlFailed(true);
    setNotice({ level: 'warn', text: `Vector basemap unavailable (${err.message}); showing OpenStreetMap raster tiles instead.` });
  };

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

      <MapNotice notice={notice} onDismiss={() => setNotice(null)} />

      {loading && (
        <div className="px-4 py-2 space-y-1">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <svg className="animate-spin h-3 w-3 text-blue-400" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading map data…
          </div>
          <div className="w-full bg-gray-800 rounded-full h-1 overflow-hidden">
            <div className="bg-blue-500 h-1 rounded-full animate-pulse w-full" />
          </div>
        </div>
      )}

      <PausedIndicator paused={paused} loading={loading} />

      <div className="flex-1 relative">
        {!hasData && !loading && (
          <div className="absolute inset-0 z-1000 flex items-center justify-center bg-gray-950/80">
            <div className="text-center space-y-2">
              <p className="text-gray-400">No geo-enriched events yet</p>
              <p className="text-xs text-gray-600">
                Place GeoLite2-City.mmdb in the data/ directory to enable GeoIP enrichment
              </p>
            </div>
          </div>
        )}

        {basemap ? (
          <MapContainer
            // react-leaflet reads these options once at construction, so a
            // different basemap (or the WebGL fallback) remounts the map.
            key={`${basemap.provider}:${basemap.style || basemap.url}`}
            center={[25, 0]}
            zoom={2}
            minZoom={2}
            maxZoom={Math.min(12, basemap.maxZoom || 12)}
            className="h-full w-full"
            style={{ background: basemap.dark ? '#0f172a' : '#dbe2ea' }}
            worldCopyJump={true}
          >
            {isVector ? (
              <MaplibreLayer style={basemap.style} attribution={basemap.attribution} onFail={onGlFail} />
            ) : (
              <TileLayer
                url={basemap.url}
                attribution={basemap.attribution}
                subdomains={basemap.subdomains || 'abc'}
              />
            )}

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
        ) : (
          <div className="absolute inset-0 flex items-center justify-center text-xs text-gray-500">
            Loading map…
          </div>
        )}

        <MapLegend />
        <StatsOverlay geoEvents={filteredEvents} recentEvents={recentEvents} />
      </div>
    </div>
  );
}
