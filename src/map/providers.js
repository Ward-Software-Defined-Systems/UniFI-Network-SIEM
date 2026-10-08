/**
 * Live Map basemap providers — registry, resolver, validators and the CSP
 * image sources derived from them.
 *
 * Pure module by design: no requires of config/storage/logger, because
 * src/config/schema.js imports the constants below (PROVIDER_IDS, the style
 * lists) to build its `options`, and server.js calls mapImgSources() on
 * every request.
 *
 * Only resolveMapConfig() ever touches the CARTO key, and it returns the key
 * substituted into the tile URL — a CARTO Basemaps key is a client-side key
 * by design (it rides on every tile request from the browser) — never the
 * raw field. GET /api/map/config is the single route that exposes the
 * result; /api/settings/v2 keeps masking the key like every private setting.
 */

const PROVIDER_IDS = ['openfreemap', 'carto', 'osm', 'custom-raster', 'custom-vector'];
const OPENFREEMAP_STYLES = ['dark', 'fiord', 'positron', 'liberty', 'bright'];
// Raster styles served from basemaps.cartocdn.com/rastertiles/ (verified 2026-10-08).
const CARTO_STYLES = [
  'dark_all', 'dark_nolabels', 'light_all', 'light_nolabels',
  'voyager', 'voyager_nolabels', 'voyager_labels_under',
];

const OSM_COPYRIGHT = '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors';
const ATTRIBUTION = {
  openfreemap: '<a href="https://openfreemap.org" target="_blank" rel="noopener">OpenFreeMap</a> '
    + '<a href="https://www.openmaptiles.org/" target="_blank" rel="noopener">&copy; OpenMapTiles</a> '
    + 'Data from <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a>',
  carto: `${OSM_COPYRIGHT} &copy; <a href="https://carto.com/attributions" target="_blank" rel="noopener">CARTO</a>`,
  osm: OSM_COPYRIGHT,
};

const OSM_TILE_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const CARTO_IMG_SOURCE = 'https://*.basemaps.cartocdn.com';
const OSM_IMG_SOURCE = 'https://tile.openstreetmap.org';
// Always allow-listed in img-src: a page's CSP is fixed when it loads, so
// switching between the built-in raster providers must not need a reload.
const BUILTIN_IMG_SOURCES = [CARTO_IMG_SOURCE, OSM_IMG_SOURCE];

const PROVIDERS = {
  openfreemap: {
    kind: 'vector', label: 'OpenFreeMap', styles: OPENFREEMAP_STYLES, defaultStyle: 'dark',
    styleUrl: (style) => `https://tiles.openfreemap.org/styles/${style}`,
    isDark: (style) => style === 'dark' || style === 'fiord',
    attribution: ATTRIBUTION.openfreemap, maxZoom: 19,
  },
  carto: {
    kind: 'raster', label: 'CARTO', styles: CARTO_STYLES, defaultStyle: 'dark_all', requiresKey: true,
    url: (style) => `https://{s}.basemaps.cartocdn.com/rastertiles/${style}/{z}/{x}/{y}{r}.png`,
    subdomains: 'abcd', cspSources: [CARTO_IMG_SOURCE],
    isDark: (style) => style.startsWith('dark'),
    attribution: ATTRIBUTION.carto, maxZoom: 20,
  },
  osm: {
    kind: 'raster', label: 'OpenStreetMap', url: OSM_TILE_URL, cspSources: [OSM_IMG_SOURCE],
    isDark: () => false, attribution: ATTRIBUTION.osm, maxZoom: 19,
  },
  'custom-raster': { kind: 'raster', label: 'Custom raster (XYZ)' },
  'custom-vector': { kind: 'vector', label: 'Custom vector (MapLibre style)' },
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Anything that could terminate or split a CSP directive, or break out of an
// HTML attribute, is rejected outright. Helmet throws on `;` / `,` inside a
// directive value, which would turn into a 500 on every request.
const FORBIDDEN_CHARS = /[\s;,<>"'`\\]/;
const PLACEHOLDER_RE = /\{([^{}]*)\}/g;
const HOSTNAME_RE = /^[a-z0-9.-]+$/i;
const CSP_SOURCE_RE = /^https:\/\/(\*\.)?[a-z0-9.-]+(:\d{1,5})?$/i;
const RASTER_PLACEHOLDERS = new Set(['z', 'x', 'y', '-y', 's', 'r']);

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseHttpsUrl(candidate) {
  let url;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, reason: 'is not a valid URL' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, reason: 'must use https:// (the dashboard is served over HTTPS, so http:// tiles are blocked as mixed content)' };
  }
  if (url.username || url.password) return { ok: false, reason: 'must not contain credentials' };
  if (!HOSTNAME_RE.test(url.hostname)) return { ok: false, reason: 'has an invalid hostname' };
  return { ok: true, url };
}

/**
 * Validate an XYZ raster tile template.
 * Returns { ok: true, url, cspSource } or { ok: false, reason }.
 */
function validateRasterTemplate(input) {
  if (typeof input !== 'string' || input.trim() === '') return { ok: false, reason: 'is empty' };
  const tpl = input.trim();
  if (FORBIDDEN_CHARS.test(tpl)) {
    return { ok: false, reason: 'contains whitespace or a forbidden character (; , < > quotes or backslash)' };
  }

  const names = [];
  for (const m of tpl.matchAll(PLACEHOLDER_RE)) names.push(m[1]);
  for (const n of names) {
    if (!RASTER_PLACEHOLDERS.has(n)) {
      return { ok: false, reason: `uses an unsupported placeholder {${n}} (allowed: {z} {x} {y} {-y} {s} {r})` };
    }
  }
  if (!names.includes('z') || !names.includes('x') || !(names.includes('y') || names.includes('-y'))) {
    return { ok: false, reason: 'must contain {z}, {x} and {y} placeholders' };
  }
  const sCount = names.filter((n) => n === 's').length;
  if (sCount > 1) return { ok: false, reason: 'may use {s} only once' };
  const hasSubdomain = sCount === 1;
  if (hasSubdomain && !/^https:\/\/\{s\}\./.test(tpl)) {
    return { ok: false, reason: '{s} must be the first host label (https://{s}.example.com/…) so the CSP wildcard can match it' };
  }

  // Substitute placeholders with a sentinel label so the URL parses; the
  // sentinel is stripped again when deriving the CSP wildcard host.
  const concrete = tpl
    .replace('{s}', 's0')
    .replace(/\{(z|x|y|-y)\}/g, '0')
    .replace('{r}', '');
  const parsed = parseHttpsUrl(concrete);
  if (!parsed.ok) return parsed;
  const { url } = parsed;
  const host = hasSubdomain ? url.hostname.replace(/^s0\./, '') : url.hostname;
  if (!host || !HOSTNAME_RE.test(host)) return { ok: false, reason: 'has an invalid hostname' };
  const cspSource = `https://${hasSubdomain ? '*.' : ''}${host}${url.port ? `:${url.port}` : ''}`;
  if (!CSP_SOURCE_RE.test(cspSource)) return { ok: false, reason: 'has a host that cannot be expressed as a CSP source' };
  return { ok: true, url: tpl, cspSource };
}

/** Validate a MapLibre style JSON URL. Returns { ok: true, url } or { ok: false, reason }. */
function validateStyleUrl(input) {
  if (typeof input !== 'string' || input.trim() === '') return { ok: false, reason: 'is empty' };
  const value = input.trim();
  if (FORBIDDEN_CHARS.test(value)) {
    return { ok: false, reason: 'contains whitespace or a forbidden character (; , < > quotes or backslash)' };
  }
  if (/[{}]/.test(value)) return { ok: false, reason: 'must be a plain URL (no {placeholders})' };
  const parsed = parseHttpsUrl(value);
  if (!parsed.ok) return parsed;
  return { ok: true, url: value };
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

function pickStyle(provider, requested, warnings) {
  const def = PROVIDERS[provider];
  if (typeof requested === 'string' && def.styles.includes(requested)) return requested;
  if (requested) warnings.push(`Unknown ${def.label} style "${requested}" — using "${def.defaultStyle}".`);
  return def.defaultStyle;
}

function resolveOpenFreeMap(m, warnings) {
  const def = PROVIDERS.openfreemap;
  const style = pickStyle('openfreemap', m.openfreemapStyle, warnings);
  return {
    provider: 'openfreemap', kind: 'vector', label: `OpenFreeMap (${style})`,
    style: def.styleUrl(style), attribution: def.attribution, maxZoom: def.maxZoom, dark: def.isDark(style),
  };
}

function resolveCarto(m, warnings) {
  const def = PROVIDERS.carto;
  const key = typeof m.cartoApiKey === 'string' ? m.cartoApiKey.trim() : '';
  if (!key) {
    warnings.push('CARTO is selected but no API key is set (map.cartoApiKey) — showing OpenFreeMap until a key is saved under Settings → Live Map.');
    return null;
  }
  const style = pickStyle('carto', m.cartoStyle, warnings);
  const base = def.url(style);
  const url = `${base}${base.includes('?') ? '&' : '?'}key=${encodeURIComponent(key)}`;
  return {
    provider: 'carto', kind: 'raster', label: `CARTO (${style})`,
    url, subdomains: def.subdomains, attribution: def.attribution, maxZoom: def.maxZoom, dark: def.isDark(style),
  };
}

function osmDescriptor() {
  const def = PROVIDERS.osm;
  return {
    provider: 'osm', kind: 'raster', label: def.label,
    url: def.url, attribution: def.attribution, maxZoom: def.maxZoom, dark: false,
  };
}

function customAttribution(m, fallback) {
  const text = typeof m.customAttribution === 'string' ? m.customAttribution.trim() : '';
  return text ? escapeHtml(text.slice(0, 300)) : fallback;
}

function resolveCustomRaster(m, warnings) {
  const v = validateRasterTemplate(m.customRasterUrl);
  if (!v.ok) {
    warnings.push(`Custom raster tile URL (map.customRasterUrl) ${v.reason} — showing OpenFreeMap.`);
    return null;
  }
  return {
    provider: 'custom-raster', kind: 'raster', label: 'Custom raster',
    url: v.url, attribution: customAttribution(m, 'Custom tiles'), maxZoom: 19, dark: true,
  };
}

function resolveCustomVector(m, warnings) {
  const v = validateStyleUrl(m.customVectorStyleUrl);
  if (!v.ok) {
    warnings.push(`Custom vector style URL (map.customVectorStyleUrl) ${v.reason} — showing OpenFreeMap.`);
    return null;
  }
  return {
    provider: 'custom-vector', kind: 'vector', label: 'Custom vector',
    style: v.url, attribution: customAttribution(m, 'Custom vector tiles'), maxZoom: 19, dark: true,
  };
}

/**
 * Resolve the operator's map settings into what the browser needs:
 *   { provider, requested, kind, label, style? | url? (+subdomains?),
 *     attribution, maxZoom, dark, warning, rasterFallback }
 * Never throws and never returns the raw key field. Falls back to
 * OpenFreeMap (with a `warning`) whenever the requested provider can't be
 * used. `rasterFallback` is the OSM descriptor the browser switches to when
 * WebGL is unavailable for a vector provider.
 */
function resolveMapConfig(config) {
  const m = (config && config.map) || {};
  const requested = typeof m.provider === 'string' ? m.provider : '';
  const warnings = [];
  let resolved = null;
  switch (requested) {
    case 'openfreemap': resolved = resolveOpenFreeMap(m, warnings); break;
    case 'carto': resolved = resolveCarto(m, warnings); break;
    case 'osm': resolved = osmDescriptor(); break;
    case 'custom-raster': resolved = resolveCustomRaster(m, warnings); break;
    case 'custom-vector': resolved = resolveCustomVector(m, warnings); break;
    default: warnings.push(`Unknown map provider "${requested}" — showing OpenFreeMap.`);
  }
  if (!resolved) resolved = resolveOpenFreeMap(m, warnings);
  return {
    ...resolved,
    requested,
    warning: warnings.length ? warnings.join(' ') : null,
    rasterFallback: osmDescriptor(),
  };
}

/** img-src sources the *active* raster provider needs ([] for vector providers). */
function cspSourcesFor(resolved) {
  if (!resolved) return [];
  if (resolved.provider === 'carto' || resolved.provider === 'osm') return PROVIDERS[resolved.provider].cspSources.slice();
  if (resolved.provider === 'custom-raster') {
    const v = validateRasterTemplate(resolved.url);
    return v.ok ? [v.cspSource] : [];
  }
  return [];
}

/**
 * img-src sources for Helmet: the built-in raster hosts always, plus a
 * validated custom-raster host when that provider is active. Every entry is
 * re-checked against CSP_SOURCE_RE as the last line of defence — Helmet
 * throws (→ 500 on every request) if a directive value contains `;` or `,`.
 */
function mapImgSources(config) {
  const sources = new Set(BUILTIN_IMG_SOURCES);
  const m = (config && config.map) || {};
  if (m.provider === 'custom-raster') {
    const v = validateRasterTemplate(m.customRasterUrl);
    if (v.ok) sources.add(v.cspSource);
  }
  return [...sources].filter((s) => CSP_SOURCE_RE.test(s));
}

module.exports = {
  PROVIDER_IDS, OPENFREEMAP_STYLES, CARTO_STYLES, PROVIDERS, BUILTIN_IMG_SOURCES,
  resolveMapConfig, validateRasterTemplate, validateStyleUrl, cspSourcesFor, mapImgSources, escapeHtml,
};
