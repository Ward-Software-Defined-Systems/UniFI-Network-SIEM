const express = require('express');
const { getDb } = require('../../db/database');
const config = require('../../config');
const logger = require('../../utils/logger');

const router = express.Router();

// In-memory settings for threat hunt (also persisted to DB)
let huntSettings = {
  provider: 'anthropic',  // anthropic | openai | gemini
  anthropicKey: '',
  openaiKey: '',
  geminiKey: '',
};

// Load settings from DB on first use
let settingsLoaded = false;
function loadSettings() {
  if (settingsLoaded) return;
  try {
    const db = getDb();
    const rows = db.prepare("SELECT key, value FROM settings WHERE key LIKE 'hunt_%'").all();
    for (const row of rows) {
      try {
        const val = JSON.parse(row.value);
        const field = row.key.replace('hunt_', '');
        if (field in huntSettings) huntSettings[field] = val;
      } catch {}
    }
    settingsLoaded = true;
  } catch {}
}

// GET /api/threat-hunt/settings
router.get('/settings', (req, res) => {
  loadSettings();
  res.json({
    provider: huntSettings.provider,
    anthropicKey: huntSettings.anthropicKey ? '••••••••' + huntSettings.anthropicKey.slice(-4) : '',
    openaiKey: huntSettings.openaiKey ? '••••••••' + huntSettings.openaiKey.slice(-4) : '',
    geminiKey: huntSettings.geminiKey ? '••••••••' + huntSettings.geminiKey.slice(-4) : '',
    hasAnthropicKey: !!huntSettings.anthropicKey,
    hasOpenaiKey: !!huntSettings.openaiKey,
    hasGeminiKey: !!huntSettings.geminiKey,
  });
});

// PUT /api/threat-hunt/settings
router.put('/settings', (req, res) => {
  try {
    const db = getDb();
    const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    const txn = db.transaction((entries) => {
      for (const [key, value] of entries) {
        if (key in huntSettings) {
          huntSettings[key] = value;
          upsert.run(`hunt_${key}`, JSON.stringify(value));
        }
      }
    });
    txn(Object.entries(req.body));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// POST /api/threat-hunt/investigate
router.post('/investigate', async (req, res) => {
  loadSettings();
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target IP or hostname required' });

  const key = getActiveKey();
  if (!key) return res.status(400).json({ error: `No API key configured for ${huntSettings.provider}` });

  try {
    // Gather local intelligence
    const intel = gatherLocalIntel(target);

    // Gather external intelligence
    const external = await gatherExternalIntel(target);

    // Build prompt and call AI
    const prompt = buildInvestigationPrompt(target, intel, external);
    const analysis = await callAI(prompt);

    res.json({
      target,
      provider: huntSettings.provider,
      intel,
      external,
      analysis,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    logger.warn({ err, target }, 'Threat hunt investigation failed');
    res.status(500).json({ error: err.message || 'Investigation failed' });
  }
});

function getActiveKey() {
  switch (huntSettings.provider) {
    case 'anthropic': return huntSettings.anthropicKey;
    case 'openai': return huntSettings.openaiKey;
    case 'gemini': return huntSettings.geminiKey;
    default: return null;
  }
}

function gatherLocalIntel(target) {
  const db = getDb();

  // Check enrichment cache
  const cached = db.prepare('SELECT * FROM ip_enrichment_cache WHERE ip = ?').get(target);

  // Event summary
  const totalEvents = db.prepare(
    'SELECT COUNT(*) as c FROM events WHERE src_ip = ? OR dst_ip = ?'
  ).get(target, target).c;

  // Events by action
  const byAction = db.prepare(`
    SELECT action, COUNT(*) as count FROM events
    WHERE (src_ip = ? OR dst_ip = ?) AND action IS NOT NULL
    GROUP BY action ORDER BY count DESC
  `).all(target, target);

  // Events by type
  const byType = db.prepare(`
    SELECT event_type, COUNT(*) as count FROM events
    WHERE src_ip = ? OR dst_ip = ?
    GROUP BY event_type ORDER BY count DESC
  `).all(target, target);

  // Top destination ports targeted
  const topPorts = db.prepare(`
    SELECT dst_port, protocol, COUNT(*) as count FROM events
    WHERE src_ip = ? AND dst_port IS NOT NULL
    GROUP BY dst_port, protocol ORDER BY count DESC LIMIT 20
  `).all(target);

  // Top source ports (if target is destination)
  const topSrcPorts = db.prepare(`
    SELECT src_port, protocol, COUNT(*) as count FROM events
    WHERE dst_ip = ? AND src_port IS NOT NULL
    GROUP BY src_port, protocol ORDER BY count DESC LIMIT 10
  `).all(target);

  // Activity timeline (hourly)
  const timeline = db.prepare(`
    SELECT strftime('%Y-%m-%dT%H:00:00Z', received_at) as hour, COUNT(*) as count
    FROM events WHERE src_ip = ? OR dst_ip = ?
    GROUP BY hour ORDER BY hour
  `).all(target, target);

  // First and last seen
  const firstSeen = db.prepare(
    'SELECT MIN(received_at) as t FROM events WHERE src_ip = ? OR dst_ip = ?'
  ).get(target, target).t;

  const lastSeen = db.prepare(
    'SELECT MAX(received_at) as t FROM events WHERE src_ip = ? OR dst_ip = ?'
  ).get(target, target).t;

  // Related IPs from same /24 subnet
  const subnet = target.split('.').slice(0, 3).join('.');
  const relatedIPs = db.prepare(`
    SELECT ip, abuse_score, geo_country, hostname FROM ip_enrichment_cache
    WHERE ip LIKE ? AND ip != ? AND is_private = 0
    ORDER BY abuse_score DESC LIMIT 10
  `).all(subnet + '.%', target);

  // IDS/IPS signatures triggered
  const signatures = db.prepare(`
    SELECT ids_signature, ids_classification, COUNT(*) as count
    FROM events WHERE (src_ip = ? OR dst_ip = ?) AND ids_signature IS NOT NULL
    GROUP BY ids_signature ORDER BY count DESC LIMIT 10
  `).all(target, target);

  // Unique destination IPs targeted by this source
  const targetsHit = db.prepare(`
    SELECT COUNT(DISTINCT dst_ip) as c FROM events WHERE src_ip = ?
  `).get(target).c;

  return {
    cached,
    totalEvents,
    byAction,
    byType,
    topPorts,
    topSrcPorts,
    timeline,
    firstSeen,
    lastSeen,
    relatedIPs,
    signatures,
    targetsHit,
  };
}

async function gatherExternalIntel(target) {
  const results = { rdns: null, whois: null };

  // Reverse DNS
  try {
    const dns = require('dns').promises;
    const hostnames = await dns.reverse(target);
    results.rdns = hostnames.length > 0 ? hostnames[0] : null;
  } catch {}

  // Basic whois via ipinfo.io (free, no key needed)
  try {
    const res = await fetch(`https://ipinfo.io/${encodeURIComponent(target)}/json`);
    if (res.ok) {
      const data = await res.json();
      results.whois = {
        hostname: data.hostname || null,
        org: data.org || null,
        city: data.city || null,
        region: data.region || null,
        country: data.country || null,
        timezone: data.timezone || null,
      };
    }
  } catch {}

  return results;
}

function buildInvestigationPrompt(target, intel, external) {
  const sections = [];

  sections.push(`You are a senior threat intelligence analyst. Investigate the following IP address and provide a comprehensive threat assessment based on the data provided from our SIEM.`);

  sections.push(`\n## Target: ${target}`);

  // Enrichment data
  if (intel.cached) {
    sections.push(`\n### Enrichment Data`);
    sections.push(`- Country: ${intel.cached.geo_country || 'Unknown'}`);
    sections.push(`- City: ${intel.cached.geo_city || 'Unknown'}`);
    sections.push(`- AbuseIPDB Score: ${intel.cached.abuse_score ?? 'Not scored'}/100`);
    sections.push(`- Hostname: ${intel.cached.hostname || 'None'}`);
  }

  // External data
  if (external.whois) {
    sections.push(`\n### Network Info (WHOIS)`);
    sections.push(`- Organization: ${external.whois.org || 'Unknown'}`);
    sections.push(`- Hostname: ${external.whois.hostname || external.rdns || 'None'}`);
    sections.push(`- Location: ${[external.whois.city, external.whois.region, external.whois.country].filter(Boolean).join(', ') || 'Unknown'}`);
  }

  // Activity summary
  sections.push(`\n### Activity Summary`);
  sections.push(`- Total events: ${intel.totalEvents.toLocaleString()}`);
  sections.push(`- First seen: ${intel.firstSeen || 'N/A'}`);
  sections.push(`- Last seen: ${intel.lastSeen || 'N/A'}`);
  sections.push(`- Unique targets hit: ${intel.targetsHit}`);

  if (intel.byAction.length > 0) {
    sections.push(`\n### Actions`);
    for (const a of intel.byAction) {
      sections.push(`- ${a.action}: ${a.count.toLocaleString()}`);
    }
  }

  if (intel.byType.length > 0) {
    sections.push(`\n### Event Types`);
    for (const t of intel.byType) {
      sections.push(`- ${t.event_type}: ${t.count.toLocaleString()}`);
    }
  }

  if (intel.topPorts.length > 0) {
    sections.push(`\n### Top Destination Ports Targeted`);
    for (const p of intel.topPorts) {
      sections.push(`- ${p.protocol}/${p.dst_port}: ${p.count} events`);
    }
  }

  if (intel.signatures.length > 0) {
    sections.push(`\n### IDS/IPS Signatures Triggered`);
    for (const s of intel.signatures) {
      sections.push(`- ${s.ids_signature} (${s.ids_classification}): ${s.count} events`);
    }
  }

  if (intel.relatedIPs.length > 0) {
    sections.push(`\n### Related IPs (Same /24 Subnet)`);
    for (const r of intel.relatedIPs) {
      sections.push(`- ${r.ip} — Abuse: ${r.abuse_score ?? 'N/A'}, Country: ${r.geo_country || '?'}, Host: ${r.hostname || 'N/A'}`);
    }
  }

  if (intel.timeline.length > 0) {
    sections.push(`\n### Activity Timeline (Hourly)`);
    for (const t of intel.timeline) {
      sections.push(`- ${t.hour}: ${t.count} events`);
    }
  }

  sections.push(`\n## Instructions`);
  sections.push(`Based on the above SIEM data, provide a structured threat assessment with the following sections:`);
  sections.push(`1. **Threat Classification** — What type of threat actor/activity is this? (scanner, brute-forcer, botnet, APT, benign, etc.)`);
  sections.push(`2. **Confidence Level** — How confident are you in this classification? (High/Medium/Low) and why.`);
  sections.push(`3. **Actor Profile** — Who is likely behind this? (automated scanner, hosting provider abuse, nation-state, cybercrime group, researcher, etc.)`);
  sections.push(`4. **Intent Analysis** — What are they likely trying to achieve based on the ports and patterns?`);
  sections.push(`5. **Risk Assessment** — What is the risk to our network? (Critical/High/Medium/Low) and why.`);
  sections.push(`6. **Indicators of Compromise (IOCs)** — List any IOCs from the data (IPs, ports, signatures, patterns).`);
  sections.push(`7. **Recommended Actions** — Specific, actionable recommendations for the network defender.`);
  sections.push(`8. **Related Threat Intelligence** — Any known threat groups, campaigns, or CVEs that match this pattern.`);
  sections.push(`\nBe specific and reference the actual data provided. Do not hallucinate or invent data not present in the evidence.`);

  return sections.join('\n');
}

async function callAI(prompt) {
  const provider = huntSettings.provider;
  const key = getActiveKey();

  switch (provider) {
    case 'anthropic': return callAnthropic(prompt, key);
    case 'openai': return callOpenAI(prompt, key);
    case 'gemini': return callGemini(prompt, key);
    default: throw new Error(`Unknown provider: ${provider}`);
  }
}

async function callAnthropic(prompt, key) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-opus-4-6',
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.content?.[0]?.text || 'No response from Anthropic';
}

async function callOpenAI(prompt, key) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: 'gpt-5.4',
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`OpenAI API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content || 'No response from OpenAI';
}

async function callGemini(prompt, key) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro:generateContent?key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 4096 },
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response from Gemini';
}

module.exports = router;
