// The only module that statically imports MapLibre GL, so Vite emits it as
// one lazy chunk that raster-only deployments never download. LiveMap pulls
// it in with a dynamic import() from MaplibreLayer.jsx.
import { setWorkerUrl } from 'maplibre-gl';
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url';
import { maplibreGL } from '@maplibre/maplibre-gl-leaflet';
import 'maplibre-gl/dist/maplibre-gl.css';

let workerConfigured = false;

/**
 * Create a Leaflet layer that renders a MapLibre style (vector tiles).
 * The bridge disables MapLibre's own attribution control and feeds the
 * `customAttribution` string to Leaflet's attribution control instead.
 */
export function createGlLayer({ style, attribution }) {
  if (!workerConfigured) {
    // MapLibre 6 can't locate its worker inside a bundler's module graph; a
    // same-origin worker URL also keeps the server's CSP at worker-src 'self'.
    setWorkerUrl(workerUrl);
    workerConfigured = true;
  }
  return maplibreGL({
    style,
    attributionControl: { customAttribution: attribution },
  });
}
