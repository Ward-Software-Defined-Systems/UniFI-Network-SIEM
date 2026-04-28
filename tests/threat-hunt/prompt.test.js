const { buildInvestigationPrompt } = require('../../src/threat-hunt/prompt');

const emptyIntel = {
  cached: null,
  totalEvents: 0,
  byAction: [],
  byType: [],
  topPorts: [],
  topSrcPorts: [],
  timeline: [],
  firstSeen: null,
  lastSeen: null,
  relatedIPs: [],
  signatures: [],
  targetsHit: 0,
  topDestinations: [],
  topSources: [],
};

const emptyExternal = { rdns: null, whois: null };

describe('buildInvestigationPrompt', () => {
  it('always includes the target line', () => {
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, emptyExternal, null);
    expect(out).toContain('## Target: 1.2.3.4');
  });

  it('omits the investigation window when no period given', () => {
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, emptyExternal, null);
    expect(out).not.toContain('## Investigation Window');
  });

  it('includes the investigation window when a period is given', () => {
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, emptyExternal, '24h');
    expect(out).toContain('## Investigation Window: last 24h');
  });

  it('renders cached enrichment when present', () => {
    const intel = {
      ...emptyIntel,
      cached: {
        geo_country: 'US',
        geo_city: 'Ashburn',
        abuse_score: 73,
        hostname: 'evil.example.com',
      },
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('Country: US');
    expect(out).toContain('City: Ashburn');
    expect(out).toContain('AbuseIPDB Score: 73/100');
    expect(out).toContain('Hostname: evil.example.com');
  });

  it('shows "Not scored" when abuse_score is null', () => {
    const intel = {
      ...emptyIntel,
      cached: { geo_country: 'US', abuse_score: null },
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('AbuseIPDB Score: Not scored/100');
  });

  it('skips the cached section when no cached data', () => {
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, emptyExternal, null);
    expect(out).not.toContain('### Enrichment Data');
  });

  it('renders WHOIS when external whois is present', () => {
    const external = {
      rdns: null,
      whois: { org: 'AS15169 Google', city: 'Mountain View', region: 'CA', country: 'US', hostname: 'g.example' },
    };
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, external, null);
    expect(out).toContain('Organization: AS15169 Google');
    expect(out).toContain('Mountain View, CA, US');
    expect(out).toContain('Hostname: g.example');
  });

  it('uses rdns as hostname fallback', () => {
    const external = { rdns: 'fallback.example', whois: { org: 'X', city: '', region: '', country: '' } };
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, external, null);
    expect(out).toContain('Hostname: fallback.example');
  });

  it('formats large totals with locale separators', () => {
    const intel = { ...emptyIntel, totalEvents: 1234567 };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    // Locale is determined by Node's default, but commas are standard for en-US
    expect(out).toMatch(/Total events: 1[,.]?234[,.]?567/);
  });

  it('renders by-action breakdown', () => {
    const intel = {
      ...emptyIntel,
      byAction: [
        { action: 'block', count: 1500 },
        { action: 'allow', count: 30 },
      ],
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('### Actions');
    expect(out).toContain('- block: 1,500');
    expect(out).toContain('- allow: 30');
  });

  it('renders top ports with protocol', () => {
    const intel = {
      ...emptyIntel,
      topPorts: [
        { dst_port: 22, protocol: 'TCP', count: 500 },
        { dst_port: 3389, protocol: 'TCP', count: 200 },
      ],
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('### Top Destination Ports Targeted');
    expect(out).toContain('- TCP/22: 500 events');
    expect(out).toContain('- TCP/3389: 200 events');
  });

  it('renders IDS signatures with classification', () => {
    const intel = {
      ...emptyIntel,
      signatures: [
        { ids_signature: 'ET SCAN Nmap', ids_classification: 'recon', count: 42 },
      ],
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('- ET SCAN Nmap (recon): 42 events');
  });

  it('renders related IPs with abuse score and country', () => {
    const intel = {
      ...emptyIntel,
      relatedIPs: [
        { ip: '1.2.3.5', abuse_score: 90, geo_country: 'US', hostname: 'a.example' },
        { ip: '1.2.3.6', abuse_score: null, geo_country: null, hostname: null },
      ],
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('- 1.2.3.5 — Abuse: 90, Country: US, Host: a.example');
    expect(out).toContain('- 1.2.3.6 — Abuse: N/A, Country: ?, Host: N/A');
  });

  it('renders timeline buckets in order', () => {
    const intel = {
      ...emptyIntel,
      timeline: [
        { hour: '2026-04-27T10:00:00Z', count: 5 },
        { hour: '2026-04-27T11:00:00Z', count: 12 },
      ],
    };
    const out = buildInvestigationPrompt('1.2.3.4', intel, emptyExternal, null);
    expect(out).toContain('- 2026-04-27T10:00:00Z: 5 events');
    expect(out).toContain('- 2026-04-27T11:00:00Z: 12 events');
  });

  it('always includes the 8-section instruction footer', () => {
    const out = buildInvestigationPrompt('1.2.3.4', emptyIntel, emptyExternal, null);
    expect(out).toContain('1. **Threat Classification**');
    expect(out).toContain('2. **Confidence Level**');
    expect(out).toContain('3. **Actor Profile**');
    expect(out).toContain('8. **Related Threat Intelligence**');
    expect(out).toContain('Do not hallucinate');
  });
});
