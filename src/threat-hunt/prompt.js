/**
 * Build the investigation prompt sent to the AI provider.
 *
 * Pure function: takes the local intel + external intel + target + period,
 * returns a prompt string. No I/O. Phase 13 will wrap untrusted strings
 * in <untrusted>...</untrusted> tags as a prompt-injection defence.
 */
function buildInvestigationPrompt(target, intel, external, period) {
  const sections = [];

  sections.push(`You are a senior threat intelligence analyst. Investigate the following IP address and provide a comprehensive threat assessment based on the data provided from our SIEM.`);

  sections.push(`\n## Target: ${target}`);
  if (period) sections.push(`## Investigation Window: last ${period}`);

  if (intel.cached) {
    sections.push(`\n### Enrichment Data`);
    sections.push(`- Country: ${intel.cached.geo_country || 'Unknown'}`);
    sections.push(`- City: ${intel.cached.geo_city || 'Unknown'}`);
    sections.push(`- AbuseIPDB Score: ${intel.cached.abuse_score ?? 'Not scored'}/100`);
    sections.push(`- Hostname: ${intel.cached.hostname || 'None'}`);
  }

  if (external.whois) {
    sections.push(`\n### Network Info (WHOIS)`);
    sections.push(`- Organization: ${external.whois.org || 'Unknown'}`);
    sections.push(`- Hostname: ${external.whois.hostname || external.rdns || 'None'}`);
    sections.push(`- Location: ${[external.whois.city, external.whois.region, external.whois.country].filter(Boolean).join(', ') || 'Unknown'}`);
  }

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

module.exports = { buildInvestigationPrompt };
