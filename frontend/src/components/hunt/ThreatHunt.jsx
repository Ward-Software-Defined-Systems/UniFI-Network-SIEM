import { useState, useEffect, useRef } from 'react';
import { countryFlag, abuseScoreColor } from '../../lib/format';
import './ThreatHunt.css';

const API_PROVIDERS = [
  { id: 'anthropic', name: 'Anthropic (Opus 4.6)', icon: '🟣' },
  { id: 'openai', name: 'OpenAI (GPT-5.4)', icon: '🟢' },
  { id: 'gemini', name: 'Google (Gemini 3.1 Pro)', icon: '🔵' },
];

export default function ThreatHunt() {
  const [settings, setSettings] = useState({
    provider: 'anthropic',
    anthropicKey: '',
    openaiKey: '',
    geminiKey: '',
    hasAnthropicKey: false,
    hasOpenaiKey: false,
    hasGeminiKey: false,
  });
  const [showKeys, setShowKeys] = useState({
    anthropic: false,
    openai: false,
    gemini: false,
  });
  const [keyInputs, setKeyInputs] = useState({
    anthropicKey: '',
    openaiKey: '',
    geminiKey: '',
  });
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsSaved, setSettingsSaved] = useState(false);
  const [target, setTarget] = useState('');
  const [investigating, setInvestigating] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const resultRef = useRef(null);

  // Load settings on mount
  useEffect(() => {
    fetch('/api/threat-hunt/settings')
      .then(r => r.json())
      .then(data => {
        setSettings(data);
        // If no keys configured, open settings panel
        if (!data.hasAnthropicKey && !data.hasOpenaiKey && !data.hasGeminiKey) {
          setSettingsOpen(true);
        }
      })
      .catch(() => {});
  }, []);

  const saveSettings = async () => {
    const payload = { provider: settings.provider };
    // Only send key fields that have been edited (non-empty input)
    if (keyInputs.anthropicKey) payload.anthropicKey = keyInputs.anthropicKey;
    if (keyInputs.openaiKey) payload.openaiKey = keyInputs.openaiKey;
    if (keyInputs.geminiKey) payload.geminiKey = keyInputs.geminiKey;

    await fetch('/api/threat-hunt/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    // Reload settings
    const res = await fetch('/api/threat-hunt/settings');
    const data = await res.json();
    setSettings(data);
    setKeyInputs({ anthropicKey: '', openaiKey: '', geminiKey: '' });
    setSettingsSaved(true);
    setTimeout(() => setSettingsSaved(false), 2000);
  };

  const investigate = async () => {
    if (!target.trim()) return;
    setInvestigating(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/api/threat-hunt/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Investigation failed');

      setResult(data);
      setHistory(prev => [{ target: data.target, timestamp: data.timestamp, provider: data.provider }, ...prev.slice(0, 19)]);

      // Scroll to results
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    } catch (err) {
      setError(err.message);
    } finally {
      setInvestigating(false);
    }
  };

  const activeProvider = API_PROVIDERS.find(p => p.id === settings.provider);
  const hasActiveKey = settings[`has${settings.provider.charAt(0).toUpperCase() + settings.provider.slice(1)}Key`];

  return (
    <div className="threat-hunt">
      <div className="hunt-header">
        <div className="hunt-title">
          <h2>🎯 Threat Hunt <span className="beta-badge">BETA</span></h2>
          <p className="hunt-subtitle">AI-powered threat actor investigation and profiling</p>
        </div>
        <button
          className={`settings-toggle ${settingsOpen ? 'active' : ''}`}
          onClick={() => setSettingsOpen(!settingsOpen)}
        >
          ⚙️ Settings
        </button>
      </div>

      {/* Settings Panel */}
      {settingsOpen && (
        <div className="hunt-settings">
          <h3>AI Provider Configuration</h3>

          <div className="provider-selector">
            {API_PROVIDERS.map(p => (
              <button
                key={p.id}
                className={`provider-btn ${settings.provider === p.id ? 'active' : ''}`}
                onClick={() => setSettings(s => ({ ...s, provider: p.id }))}
              >
                <span className="provider-icon">{p.icon}</span>
                <span className="provider-name">{p.name}</span>
                {settings[`has${p.id.charAt(0).toUpperCase() + p.id.slice(1)}Key`] && (
                  <span className="key-status">✓</span>
                )}
              </button>
            ))}
          </div>

          <div className="key-fields">
            {API_PROVIDERS.map(p => (
              <div key={p.id} className="key-field">
                <label>{p.icon} {p.name} API Key</label>
                <div className="key-input-row">
                  <input
                    type={showKeys[p.id] ? 'text' : 'password'}
                    placeholder={settings[`${p.id}Key`] || `Enter ${p.name} API key`}
                    value={keyInputs[`${p.id}Key`]}
                    onChange={e => setKeyInputs(k => ({ ...k, [`${p.id}Key`]: e.target.value }))}
                  />
                  <button
                    className="key-toggle"
                    onClick={() => setShowKeys(s => ({ ...s, [p.id]: !s[p.id] }))}
                    title={showKeys[p.id] ? 'Hide' : 'Show'}
                  >
                    {showKeys[p.id] ? '🙈' : '👁️'}
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="settings-actions">
            <button className="save-btn" onClick={saveSettings}>
              {settingsSaved ? '✅ Saved!' : '💾 Save Settings'}
            </button>
          </div>
        </div>
      )}

      {/* Investigation Input */}
      <div className="hunt-input">
        <div className="input-row">
          <div className="target-input-wrap">
            <span className="input-icon">🔍</span>
            <input
              type="text"
              className="target-input"
              placeholder="Enter IP address or hostname to investigate..."
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && investigate()}
              disabled={investigating}
            />
          </div>
          <button
            className="investigate-btn"
            onClick={investigate}
            disabled={investigating || !target.trim() || !hasActiveKey}
          >
            {investigating ? (
              <>
                <span className="spinner"></span>
                Investigating...
              </>
            ) : (
              <>🎯 Investigate</>
            )}
          </button>
        </div>
        {!hasActiveKey && (
          <p className="input-hint warning">⚠️ No API key configured for {activeProvider?.name}. Open Settings to add one.</p>
        )}
        {activeProvider && hasActiveKey && (
          <p className="input-hint">Using {activeProvider.icon} {activeProvider.name}</p>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="hunt-error">
          <span>❌</span> {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="hunt-results" ref={resultRef}>
          {/* Intel Summary */}
          <div className="intel-summary">
            <h3>📊 Local Intelligence: {result.target}</h3>
            <div className="intel-cards">
              <div className="intel-card">
                <div className="intel-value">{result.intel.totalEvents?.toLocaleString() || 0}</div>
                <div className="intel-label">Total Events</div>
              </div>
              {result.intel.cached && (
                <>
                  <div className="intel-card">
                    <div className="intel-value">
                      {countryFlag(result.intel.cached.geo_country)} {result.intel.cached.geo_country || '—'}
                    </div>
                    <div className="intel-label">Country</div>
                  </div>
                  <div className="intel-card">
                    <div className="intel-value">
                      <span className="abuse-pill" style={{ background: abuseScoreColor(result.intel.cached.abuse_score) }}>
                        {result.intel.cached.abuse_score ?? 'N/A'}
                      </span>
                    </div>
                    <div className="intel-label">Abuse Score</div>
                  </div>
                </>
              )}
              <div className="intel-card">
                <div className="intel-value">{result.intel.targetsHit || 0}</div>
                <div className="intel-label">Targets Hit</div>
              </div>
              {result.external?.whois?.org && (
                <div className="intel-card wide">
                  <div className="intel-value small">{result.external.whois.org}</div>
                  <div className="intel-label">Organization / ASN</div>
                </div>
              )}
            </div>

            {/* Activity breakdown */}
            <div className="intel-details">
              {result.intel.byAction?.length > 0 && (
                <div className="detail-section">
                  <h4>Actions</h4>
                  <div className="detail-chips">
                    {result.intel.byAction.map(a => (
                      <span key={a.action} className={`chip ${a.action}`}>
                        {a.action}: {a.count.toLocaleString()}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {result.intel.topPorts?.length > 0 && (
                <div className="detail-section">
                  <h4>Top Ports Targeted</h4>
                  <div className="port-grid">
                    {result.intel.topPorts.slice(0, 10).map((p, i) => (
                      <span key={i} className="port-tag">
                        {p.protocol}/{p.dst_port} <small>×{p.count}</small>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {result.intel.signatures?.length > 0 && (
                <div className="detail-section">
                  <h4>🚨 IDS Signatures</h4>
                  {result.intel.signatures.map((s, i) => (
                    <div key={i} className="signature-row">
                      <span className="sig-name">{s.ids_signature}</span>
                      <span className="sig-class">{s.ids_classification}</span>
                      <span className="sig-count">×{s.count}</span>
                    </div>
                  ))}
                </div>
              )}

              {result.intel.relatedIPs?.length > 0 && (
                <div className="detail-section">
                  <h4>🔗 Related IPs (Same /24)</h4>
                  <div className="related-ips">
                    {result.intel.relatedIPs.map(r => (
                      <span
                        key={r.ip}
                        className="related-ip"
                        onClick={() => { setTarget(r.ip); }}
                        title="Click to investigate"
                      >
                        {countryFlag(r.geo_country)} {r.ip}
                        {r.abuse_score != null && (
                          <span className="abuse-pill small" style={{ background: abuseScoreColor(r.abuse_score) }}>
                            {r.abuse_score}
                          </span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {result.intel.firstSeen && (
                <div className="detail-section">
                  <h4>⏱️ Activity Window</h4>
                  <p className="time-range">
                    {new Date(result.intel.firstSeen).toLocaleString()} → {new Date(result.intel.lastSeen).toLocaleString()}
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* AI Analysis */}
          <div className="ai-analysis">
            <h3>
              🤖 AI Threat Assessment
              <span className="provider-tag">{API_PROVIDERS.find(p => p.id === result.provider)?.icon} {result.provider}</span>
            </h3>
            <div className="analysis-content" dangerouslySetInnerHTML={{ __html: markdownToHtml(result.analysis) }} />
            <div className="analysis-meta">
              <span>Generated: {new Date(result.timestamp).toLocaleString()}</span>
            </div>
          </div>
        </div>
      )}

      {/* Investigation History */}
      {history.length > 0 && (
        <div className="hunt-history">
          <h3>📜 Recent Investigations</h3>
          <div className="history-list">
            {history.map((h, i) => (
              <button
                key={i}
                className="history-item"
                onClick={() => setTarget(h.target)}
              >
                <span className="history-target">{h.target}</span>
                <span className="history-provider">{API_PROVIDERS.find(p => p.id === h.provider)?.icon}</span>
                <span className="history-time">{new Date(h.timestamp).toLocaleTimeString()}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Simple markdown → HTML converter for the AI response
function markdownToHtml(md) {
  if (!md) return '';
  return md
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^## (.+)$/gm, '<h3>$1</h3>')
    .replace(/^# (.+)$/gm, '<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`(.+?)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>')
    .replace(/<\/ul>\s*<ul>/g, '')
    .replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>')
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>');
}
