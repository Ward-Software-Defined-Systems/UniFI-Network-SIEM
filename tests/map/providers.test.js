const {
  PROVIDER_IDS, OPENFREEMAP_STYLES, CARTO_STYLES, PROVIDERS, BUILTIN_IMG_SOURCES,
  resolveMapConfig, validateRasterTemplate, validateStyleUrl, cspSourcesFor, mapImgSources, escapeHtml,
} = require('../../src/map/providers');

const HOST_SOURCE = /^https:\/\/(\*\.)?[a-z0-9.-]+(:\d{1,5})?$/i;
const cfg = (over = {}) => ({
  map: {
    provider: 'openfreemap', openfreemapStyle: 'dark', cartoStyle: 'dark_all', cartoApiKey: '',
    customRasterUrl: '', customVectorStyleUrl: '', customAttribution: '', ...over,
  },
});

describe('provider registry', () => {
  it('has a definition for every provider id', () => {
    for (const id of PROVIDER_IDS) {
      expect(PROVIDERS[id]).toBeDefined();
      expect(['raster', 'vector']).toContain(PROVIDERS[id].kind);
    }
  });

  it('built-in raster providers have {z}{x}{y} URLs and well-formed CSP sources', () => {
    for (const id of ['carto', 'osm']) {
      const d = PROVIDERS[id];
      const url = typeof d.url === 'function' ? d.url(d.defaultStyle) : d.url;
      expect(url).toMatch(/\{z\}.*\{x\}.*\{y\}/);
      for (const s of d.cspSources) expect(s).toMatch(HOST_SOURCE);
    }
  });

  it('style lists contain their defaults', () => {
    expect(OPENFREEMAP_STYLES).toContain(PROVIDERS.openfreemap.defaultStyle);
    expect(CARTO_STYLES).toContain(PROVIDERS.carto.defaultStyle);
  });
});

describe('resolveMapConfig — OpenFreeMap (default)', () => {
  it('resolves the dark vector style with no warning', () => {
    const r = resolveMapConfig(cfg());
    expect(r.provider).toBe('openfreemap');
    expect(r.requested).toBe('openfreemap');
    expect(r.kind).toBe('vector');
    expect(r.style).toBe('https://tiles.openfreemap.org/styles/dark');
    expect(r.url).toBeUndefined();
    expect(r.dark).toBe(true);
    expect(r.warning).toBeNull();
    expect(r.attribution).toContain('OpenMapTiles');
    expect(r.attribution).toContain('openstreetmap.org/copyright');
  });

  it('positron is light; fiord is dark', () => {
    expect(resolveMapConfig(cfg({ openfreemapStyle: 'positron' })).dark).toBe(false);
    expect(resolveMapConfig(cfg({ openfreemapStyle: 'fiord' })).dark).toBe(true);
  });

  it('unknown style falls back to dark with a warning', () => {
    const r = resolveMapConfig(cfg({ openfreemapStyle: 'neon' }));
    expect(r.style).toMatch(/\/dark$/);
    expect(r.warning).toMatch(/neon/);
  });

  it('always carries the OSM raster fallback descriptor', () => {
    const r = resolveMapConfig(cfg());
    expect(r.rasterFallback).toMatchObject({
      provider: 'osm', kind: 'raster', url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', dark: false,
    });
    expect(r.rasterFallback.attribution).toContain('OpenStreetMap');
  });

  it('unknown provider falls back to OpenFreeMap with a warning', () => {
    const r = resolveMapConfig(cfg({ provider: 'bing' }));
    expect(r.provider).toBe('openfreemap');
    expect(r.requested).toBe('bing');
    expect(r.warning).toMatch(/Unknown map provider "bing"/);
  });

  it('tolerates a missing map section', () => {
    const r = resolveMapConfig({});
    expect(r.provider).toBe('openfreemap');
    expect(r.warning).toBeTruthy();
  });
});

describe('resolveMapConfig — CARTO', () => {
  it('puts the trimmed, encoded key after {r}.png and uses abcd subdomains', () => {
    const r = resolveMapConfig(cfg({ provider: 'carto', cartoApiKey: ' abc def ' }));
    expect(r.provider).toBe('carto');
    expect(r.kind).toBe('raster');
    expect(r.url).toBe('https://{s}.basemaps.cartocdn.com/rastertiles/dark_all/{z}/{x}/{y}{r}.png?key=abc%20def');
    expect(r.subdomains).toBe('abcd');
    expect(r.dark).toBe(true);
    expect(r.warning).toBeNull();
    expect(r.attribution).toContain('CARTO');
    expect(r.attribution).toContain('OpenStreetMap');
  });

  it('exposes the key only inside the tile URL', () => {
    const r = resolveMapConfig(cfg({ provider: 'carto', cartoApiKey: 'sekrit' }));
    expect(r.cartoApiKey).toBeUndefined();
    expect(JSON.stringify(r).split('sekrit').length - 1).toBe(1);
    expect(r.url).toContain('key=sekrit');
  });

  it('light styles are not dark', () => {
    expect(resolveMapConfig(cfg({ provider: 'carto', cartoApiKey: 'k', cartoStyle: 'voyager' })).dark).toBe(false);
  });

  it('unknown style falls back to dark_all with a warning', () => {
    const r = resolveMapConfig(cfg({ provider: 'carto', cartoApiKey: 'k', cartoStyle: 'sepia' }));
    expect(r.url).toContain('/rastertiles/dark_all/');
    expect(r.warning).toMatch(/sepia/);
  });

  it('without a key falls back to OpenFreeMap and names the setting', () => {
    const r = resolveMapConfig(cfg({ provider: 'carto' }));
    expect(r.provider).toBe('openfreemap');
    expect(r.requested).toBe('carto');
    expect(r.warning).toMatch(/map\.cartoApiKey/);
  });
});

describe('resolveMapConfig — OSM', () => {
  it('uses the bare tile host, a light backdrop and the OSM credit', () => {
    const r = resolveMapConfig(cfg({ provider: 'osm' }));
    expect(r.url).toBe('https://tile.openstreetmap.org/{z}/{x}/{y}.png');
    expect(r.subdomains).toBeUndefined();
    expect(r.dark).toBe(false);
    expect(r.attribution).toContain('OpenStreetMap');
    expect(r.warning).toBeNull();
  });
});

describe('resolveMapConfig — custom raster', () => {
  const tpl = 'https://{s}.tiles.example.com:8443/{z}/{x}/{y}{r}.png?key=k';

  it('accepts a valid template and escapes the attribution', () => {
    const r = resolveMapConfig(cfg({ provider: 'custom-raster', customRasterUrl: ` ${tpl} `, customAttribution: '<b>Me</b> & co' }));
    expect(r.provider).toBe('custom-raster');
    expect(r.url).toBe(tpl);
    expect(r.attribution).toBe('&lt;b&gt;Me&lt;/b&gt; &amp; co');
    expect(r.warning).toBeNull();
    expect(cspSourcesFor(r)).toEqual(['https://*.tiles.example.com:8443']);
  });

  it('defaults the attribution when empty', () => {
    const r = resolveMapConfig(cfg({ provider: 'custom-raster', customRasterUrl: 'https://t.example.com/{z}/{x}/{y}.png' }));
    expect(r.attribution).toBe('Custom tiles');
  });

  it('accepts {-y} (TMS) templates and bare hosts', () => {
    const v = validateRasterTemplate('https://tms.example.com/{z}/{x}/{-y}.png');
    expect(v.ok).toBe(true);
    expect(v.cspSource).toBe('https://tms.example.com');
  });

  it.each([
    ['', /is empty/],
    ['http://t.example.com/{z}/{x}/{y}.png', /https/],
    ['https://t.example.com/{x}/{y}.png', /\{z\}/],
    ['https://tiles{s}.example.com/{z}/{x}/{y}.png', /first host label/],
    ['https://{s}.{s}.example.com/{z}/{x}/{y}.png', /only once/],
    ['https://t.example.com/{z}/{x}/{y}.png?style={foo}', /unsupported placeholder/],
    ['https://t.example.com/{z}/{x}/{y}.png; img-src *', /forbidden/],
    ['https://t.example.com/{z}/{x}/{y}.png,https://evil', /forbidden/],
    ['https://t.example.com/{z}/{x}/{y}.png"onerror="x', /forbidden/],
    ['https://user:pw@t.example.com/{z}/{x}/{y}.png', /credentials/],
    ['javascript:alert({z}{x}{y})', /https/],
  ])('rejects %s and falls back with the reason', (url, reason) => {
    const v = validateRasterTemplate(url);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(reason);
    const r = resolveMapConfig(cfg({ provider: 'custom-raster', customRasterUrl: url }));
    expect(r.provider).toBe('openfreemap');
    expect(r.requested).toBe('custom-raster');
    expect(r.warning).toMatch(reason);
  });
});

describe('resolveMapConfig — custom vector', () => {
  it('accepts an https style URL', () => {
    const r = resolveMapConfig(cfg({ provider: 'custom-vector', customVectorStyleUrl: 'https://tiles.openfreemap.org/styles/liberty' }));
    expect(r.kind).toBe('vector');
    expect(r.style).toBe('https://tiles.openfreemap.org/styles/liberty');
    expect(r.attribution).toBe('Custom vector tiles');
    expect(r.warning).toBeNull();
    expect(cspSourcesFor(r)).toEqual([]);
  });

  it.each([
    ['', /is empty/],
    ['http://x.example.com/style.json', /https/],
    ['https://x.example.com/{z}.json', /placeholders/],
    ['https://x.example.com/a b.json', /forbidden/],
    ['not-a-url', /valid URL/],
  ])('rejects %s and falls back with the reason', (url, reason) => {
    expect(validateStyleUrl(url).ok).toBe(false);
    const r = resolveMapConfig(cfg({ provider: 'custom-vector', customVectorStyleUrl: url }));
    expect(r.provider).toBe('openfreemap');
    expect(r.warning).toMatch(reason);
  });
});

describe('CSP image sources', () => {
  it('cspSourcesFor: built-in raster hosts, nothing for vector', () => {
    expect(cspSourcesFor(resolveMapConfig(cfg({ provider: 'carto', cartoApiKey: 'k' })))).toEqual(['https://*.basemaps.cartocdn.com']);
    expect(cspSourcesFor(resolveMapConfig(cfg({ provider: 'osm' })))).toEqual(['https://tile.openstreetmap.org']);
    expect(cspSourcesFor(resolveMapConfig(cfg()))).toEqual([]);
    expect(cspSourcesFor(null)).toEqual([]);
  });

  it('mapImgSources always lists exactly the two built-in hosts for non-custom providers', () => {
    const variants = [
      {},
      { provider: 'carto', cartoApiKey: 'k' },
      { provider: 'osm' },
      { provider: 'custom-vector', customVectorStyleUrl: 'https://x.example.com/s.json' },
      { provider: 'osm', customRasterUrl: 'https://t.example.com/{z}/{x}/{y}.png' },
    ];
    for (const over of variants) {
      const s = mapImgSources(cfg(over));
      expect(s).toEqual(expect.arrayContaining(BUILTIN_IMG_SOURCES));
      expect(s).toHaveLength(2);
    }
  });

  it('adds the custom host only when custom-raster is active and valid', () => {
    expect(mapImgSources(cfg({ provider: 'custom-raster', customRasterUrl: 'https://{s}.t.example.com/{z}/{x}/{y}.png' })))
      .toContain('https://*.t.example.com');
    expect(mapImgSources(cfg({ provider: 'custom-raster', customRasterUrl: 'http://t.example.com/{z}/{x}/{y}.png' })))
      .toHaveLength(2);
  });

  it('never emits a source Helmet would reject', () => {
    const nasty = [
      'https://t.example.com/{z}/{x}/{y}.png;',
      'https://t.example.com/{z}/{x}/{y}.png,x',
      'https://t.exa mple.com/{z}/{x}/{y}.png',
      'https://{s}.t.example.com/{z}/{x}/{y}.png',
    ];
    for (const u of nasty) {
      for (const s of mapImgSources(cfg({ provider: 'custom-raster', customRasterUrl: u }))) {
        expect(s).toMatch(HOST_SOURCE);
        expect(s).not.toMatch(/[;,\s]/);
      }
    }
  });
});

describe('escapeHtml', () => {
  it.each([
    ['<b>', '&lt;b&gt;'],
    ['a & b', 'a &amp; b'],
    ['"q" \'s\'', '&quot;q&quot; &#39;s&#39;'],
    ['plain', 'plain'],
  ])('%s → %s', (input, output) => {
    expect(escapeHtml(input)).toBe(output);
  });
});
