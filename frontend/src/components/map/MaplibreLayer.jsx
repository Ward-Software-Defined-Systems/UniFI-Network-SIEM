import { useEffect, useRef } from 'react';
import { useMap } from 'react-leaflet';

// MapLibre 6 needs WebGL2 and throws synchronously from its constructor when
// no context is available (VNC/RDP sessions, locked-down browsers). Probe
// first so those browsers never download the ~1 MB chunk.
function hasWebGL() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return false;
    const lose = gl.getExtension('WEBGL_lose_context');
    if (lose) lose.loseContext();
    return true;
  } catch {
    return false;
  }
}

/**
 * Vector basemap layer for react-leaflet. Lazily loads MapLibre + the
 * Leaflet bridge, adds the GL layer to the map and removes it on unmount or
 * when the style changes. Calls onFail(err) if the layer can't be created or
 * the style can't load, so LiveMap can swap in the raster fallback.
 */
export default function MaplibreLayer({ style, attribution, onFail }) {
  const map = useMap();
  const onFailRef = useRef(onFail);
  onFailRef.current = onFail;

  useEffect(() => {
    let cancelled = false;
    let layer = null;
    const fail = (err) => {
      if (cancelled) return;
      cancelled = true;
      const error = err instanceof Error ? err : new Error(String(err?.message || err || 'unknown error'));
      onFailRef.current?.(error);
    };

    if (!hasWebGL()) {
      fail(new Error('WebGL is not available in this browser'));
      return undefined;
    }

    import('./maplibre-bridge')
      .then(({ createGlLayer }) => {
        if (cancelled) return;
        try {
          layer = createGlLayer({ style, attribution });
          layer.addTo(map);
          const gl = layer.getMaplibreMap();
          let loaded = false;
          gl.once('load', () => { loaded = true; });
          gl.on('error', (e) => {
            // Before the first `load`, a resource error means the style
            // itself can't load (404, blocked fetch, GPU loss). Tile-level
            // errors carry a `tile`/`sourceId` and are never fatal.
            if (loaded || e?.tile || e?.sourceId) return;
            fail(e?.error || new Error('MapLibre could not load the map style'));
          });
        } catch (err) {
          fail(err);
        }
      })
      .catch(fail);

    return () => {
      cancelled = true;
      if (layer && map.hasLayer(layer)) map.removeLayer(layer);
      layer = null;
    };
  }, [map, style, attribution]);

  return null;
}
