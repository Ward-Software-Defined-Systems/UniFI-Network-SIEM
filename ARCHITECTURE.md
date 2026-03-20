# UniFi Network SIEM — Architecture

## Overview
A self-hosted Security Information and Event Management (SIEM) system for UniFi network infrastructure. Ingests syslog events from UniFi gateways, enriches them with GeoIP, rDNS, and threat intelligence, and provides a real-time web dashboard with live map, event stream, and analytics.

## Data Flow
```
UniFi Gateway (UDM/USG)
    │ (syslog UDP :5514)
    ▼
Syslog Collector
    ├── Header parser (RFC 3164/5424)
    └── Event parsers (firewall, IDS, DNS, DHCP, WiFi, system, CEF)
         │
         ▼
    Enrichment Queue
    ├── GeoIP lookup (MaxMind GeoLite2-City)
    ├── Reverse DNS
    └── AbuseIPDB threat scoring
         │
         ▼
    SQLite (WAL mode)
    ├── events table (full event data)
    ├── enrichment_cache (IP → geo/rDNS/abuse)
    └── retention policy (configurable auto-purge)
         │
         ▼
    Express API + WebSocket
    ├── REST endpoints (events, stats, settings, health)
    └── Real-time push (new events → connected clients)
         │
         ▼
    React Dashboard (Vite + Tailwind)
    ├── Live Stream — real-time event feed with filters
    ├── Dashboard — stats cards, timeline, top talkers/ports/threats
    ├── Live Map — Leaflet world map of external IP locations
    ├── Threat Intel — AbuseIPDB-enriched threat view
    ├── Threat Hunt (Beta) — AI-powered investigation w/ PDF export
    └── Settings — retention, API keys, syslog config
```

## Stack

### Backend
- **Runtime:** Node.js
- **Syslog:** Custom UDP server (port 5514)
- **API:** Express + HTTPS (self-signed TLS, port 3000)
- **WebSocket:** ws library (real-time event push)
- **Database:** better-sqlite3, WAL mode
- **GeoIP:** MaxMind GeoLite2-City (.mmdb)
- **Threat Intel:** AbuseIPDB API (optional, rate-limited)

### Frontend
- **Framework:** React 18 + Vite
- **Styling:** Tailwind CSS
- **Mapping:** Leaflet + OpenStreetMap
- **Charts:** Recharts
- **State:** React hooks + WebSocket subscription

## Source Structure
```
src/
├── index.js                    # Entry point — starts syslog, API, enrichment
├── config.js                   # Environment-based configuration
├── collector/
│   ├── syslog-server.js        # UDP syslog listener
│   └── parsers/
│       ├── index.js            # Parser router (dispatches by event type)
│       ├── syslog-header.js    # RFC 3164/5424 header extraction
│       ├── firewall.js         # iptables/netfilter log parsing
│       ├── ids.js              # Suricata IDS/IPS alerts
│       ├── dns.js              # DNS query/response logs
│       ├── coredns.js          # CoreDNS ad-block logs
│       ├── dhcp.js             # DHCP lease events
│       ├── dhcp-relay.js       # DHCP relay events
│       ├── wifi.js             # Wireless association/disassociation
│       ├── system.js           # System/kernel messages
│       └── cef.js              # Common Event Format
├── db/
│   ├── database.js             # SQLite init, schema, migrations (legacy direct access)
│   ├── events.js               # Event CRUD (batched inserts, legacy direct access)
│   ├── cache.js                # Enrichment cache layer (legacy direct access)
│   ├── retention.js            # Auto-purge by age/count
│   └── backends/
│       ├── interface.js        # StorageBackend base class (contract for all backends)
│       ├── index.js            # Backend registry & factory
│       ├── sqlite.js           # SQLite backend — full implementation (default)
│       ├── wardsondb.js        # WardSONDB backend — full implementation (Beta)
│       └── opensearch.js       # OpenSearch backend — stub (Beta — Coming Soon)
├── enrichment/
│   ├── enrichment-queue.js     # Enrichment coordinator (delegates UPDATEs to worker)
│   ├── enrichment-worker.js    # Worker thread — runs UPDATE operations off main event loop
│   ├── geoip.js                # MaxMind GeoLite2 lookups
│   ├── rdns.js                 # Reverse DNS resolution
│   └── abuseipdb.js            # AbuseIPDB threat score API
├── api/
│   ├── server.js               # Express HTTPS server
│   ├── websocket.js            # WebSocket server (event push)
│   └── routes/
│       ├── events.js           # GET /api/events (filtered, paginated)
│       ├── stats.js            # GET /api/stats (aggregations)
│       ├── settings.js         # GET/POST /api/settings
│       ├── health.js           # GET /api/health
│       └── threat-hunt.js      # Threat Hunt AI investigation API
└── utils/
    ├── logger.js               # Structured logging
    ├── ip-utils.js             # RFC1918/private IP detection
    ├── event-types.js          # Event type constants
    └── port-names.js           # Well-known port → name mapping

frontend/
├── src/
│   ├── main.jsx                # React entry
│   ├── App.jsx                 # Router (Dashboard, Live, Map, Intel, Hunt, Settings)
│   ├── components/
│   │   ├── Layout.jsx          # Shell, nav, theme
│   │   ├── Settings.jsx        # Settings panel
│   │   ├── dashboard/          # Dashboard view (stats, timeline, top-N)
│   │   ├── live/               # Live stream (event table, detail, filters)
│   │   ├── map/                # Leaflet world map
│   │   ├── intel/              # Threat intel view
│   │   ├── hunt/               # Threat Hunt (Beta) — AI investigation + PDF export
│   │   └── shared/             # Badges, selectors, reusable UI
│   ├── hooks/
│   │   ├── useWebSocket.js     # WebSocket subscription hook
│   │   └── useEventQuery.js    # API query hook with polling
│   └── lib/
│       ├── api.js              # Fetch wrapper
│       ├── constants.js        # Shared constants
│       └── format.js           # Display formatters
└── dist/                       # Built frontend (served by Express)
```

## Data Storage
- **Events DB:** `./data/events.db` (SQLite, WAL mode for concurrent reads)
- **GeoIP DB:** `./data/GeoLite2-City.mmdb` (download from MaxMind)
- **TLS Certs:** `./certs/` (auto-generated self-signed on first run)
- **Enrichment cache:** In-DB table, keyed by IP, with TTL

## Ports
| Port | Protocol | Purpose |
|------|----------|---------|
| 3000 | HTTPS | Web dashboard + API |
| 5514 | UDP | Syslog receiver |

## Environment Configuration
See `.env.example` for all options. Key settings:
- `SYSLOG_PORT` — UDP port for syslog ingestion (default: 5514)
- `WEB_PORT` — HTTPS dashboard port (default: 3000)
- `ABUSEIPDB_API_KEY` — Optional threat intel API key
- `MAXMIND_DB_PATH` — Path to GeoLite2-City.mmdb
- `RETENTION_DAYS` — Event retention period

## Key Design Decisions

### Storage Backend Abstraction
The SIEM supports pluggable storage backends via a `StorageBackend` interface (`src/db/backends/interface.js`). All backends implement the same contract covering writes, reads, stats/aggregation, enrichment cache, settings, and maintenance.

**Available backends:**
| Backend | Status | Description |
|---------|--------|-------------|
| SQLite | **Stable (Default)** | Zero-dependency embedded database via `better-sqlite3`. Best for single-node deployments. |
| WardSONDB | **Beta** | High-performance Rust-based JSON document database with selective indexing. Requires a separate WardSONDB instance. |
| OpenSearch | Beta — Coming Soon | Enterprise search/analytics engine with native SIEM capabilities, dashboards, and horizontal scaling. |

**Selection:** Users choose their backend from Settings > Database Engine. The selection is persisted in the SQLite `settings` table (always — regardless of active backend). Non-SQLite backends require a restart to take effect.

> **⚠️ Important:** Settings and configuration are always stored in the local SQLite database (`data/events.db`), even when using an external backend. Do not delete this file.

**Migration path:** The existing code paths (`db/database.js`, `db/events.js`, `db/cache.js`) still operate directly for the SQLite backend. Once external backends are implemented, the codebase will route through the `StorageBackend` interface. The `SqliteBackend` class (`src/db/backends/sqlite.js`) already wraps all existing SQLite logic behind the interface, ready for the switch.

### WardSONDB Integration

The WardSONDB backend (`src/db/backends/wardsondb.js`) communicates with WardSONDB over HTTPS with TLS and optional API key authentication.

**Deferred index creation:** Indexes are not created during `initialize()`. Instead, a background task monitors the ingest rate via `/_stats`. Once the rate stabilizes (< 500 docs per 10-second interval for 3 consecutive checks), indexes are created one at a time with 5-second pauses between each. Before creating each index, the SIEM checks WardSONDB's `write_pressure` field — if `"high"`, it waits an additional 30 seconds. This prevents compaction storms that can make WardSONDB unresponsive during bulk ingest.

**Write pressure detection:** The health endpoint (`/api/health`) runs sequentially for WardSONDB: `healthCheck()` first (calls `/_health` + `/_stats` only), then conditionally fetches `getEventCountToday()` and `getEventTypeCounts()` only if the DB is non-empty and reachable. If any call times out, the response includes `rebuilding: true` and `writePressure: "high"`. The frontend Layout component detects this and replaces the dashboard with a "Database Under Heavy Load" banner, suppressing all dashboard queries until WardSONDB recovers. This also activates during the 60-second grace period after a database reset. Empty databases (0 documents) never trigger the rebuilding banner.

**Empty database short-circuit:** On startup, the backend caches the document count from `/_stats`. When `docCount === 0`, all expensive stats methods (`getOverviewStats`, `getTimeline`, `getTopTalkers`, `getTopBlocked`, `getTopPorts`, `getTopClients`, `getTopThreats`, `getThreatIntel`, `getGeoEvents`, `getRecentGeoEvents`, `getEventTypeCounts`) return empty results immediately without making any WardSONDB requests. The cache is updated whenever `healthCheck()` succeeds or `insertEvents()` inserts documents.

**Known WardSONDB bug — `/{collection}/storage` endpoint hang (workaround in place):** WardSONDB's per-collection `/storage` endpoint can hang indefinitely on empty or freshly-indexed collections, even when `/_health` and `/_stats` respond normally. This caused a cascading failure: the SIEM's `healthCheck()` called `/events/storage`, which timed out, triggering fallback queries that also timed out, piling up connections faster than WardSONDB could drain them, eventually making all endpoints unresponsive. **Workaround:** The SIEM no longer calls `/{collection}/storage` at runtime. Doc counts come from `/_stats.total_documents` (which works reliably), and per-collection metadata (oldest/newest doc, index count) is unavailable until this WardSONDB bug is fixed. All WardSONDB requests use `AbortSignal.timeout(6s)` and health check calls use 0 retries (the 10s poll interval is its own retry). See: `src/db/backends/wardsondb.js`, `src/api/routes/health.js`.

**9 required indexes:** `idx_event_type`, `idx_received_at`, `idx_network_action`, `idx_src_ip`, `idx_dst_ip`, `idx_dst_port`, `idx_type_time` (compound), `idx_action_time` (compound), `idx_type_action` (compound).

**Bitmap scan acceleration:** When WardSONDB is launched with `--bitmap-fields`, the SIEM's dashboard queries (overview stats, event type counts) use bitmap-accelerated paths that return in sub-millisecond times at any scale — no code changes needed on the SIEM side. The bitmap accelerator is transparent to API consumers.

**Compound range scans:** The compound indexes `idx_type_time` and `idx_action_time` enable fast time-windowed queries (e.g., `event_type = "firewall" AND received_at >= X`). WardSONDB's query planner automatically selects compound range scans when an equality prefix + range suffix matches a compound index, reducing queries that previously scanned millions of documents to narrow index range scans.

### Time Period Filtering
- All datetime comparisons use `strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)` to match stored ISO 8601 timestamps. SQLite's `datetime()` returns space-separated format which breaks string comparisons against T-separated timestamps.
- Period state is lifted to `App.jsx` and shared across Dashboard, Live Map, and Threat Intel views so selections persist when switching views.

### Enrichment Pipeline
- GeoIP (sync, local) and AbuseIPDB (async, rate-limited) run in the same enrichment pass per IP on the main thread.
- All `UPDATE` operations (backfill + inline enrichment) are delegated to a **dedicated worker thread** (`enrichment-worker.js`) via `worker_threads`. The worker opens its own `better-sqlite3` connection to the same WAL-mode database, keeping the main event loop free for syslog ingest and API serving.
- Cached IPs missing abuse scores are re-queued when AbuseIPDB becomes available (handles rate limit recovery).
- Re-enrichment merges with existing cache data to avoid overwriting GeoIP when only updating abuse scores.
- Private IPs (RFC1918, CGNAT, loopback, link-local) are filtered at queue entry — no API calls wasted.
- AbuseIPDB field: `abuseConfidenceScore` (not `abuseConfidencePercentage`).

### Database Reset
- Uses `DROP TABLE` + schema recreate instead of `DELETE` + `VACUUM` — instant regardless of database size.

### Frontend Data Fetching
- All polling views use a `cancelled` flag pattern to discard stale in-flight API responses when the period changes or the component unmounts, preventing UI flicker.
- Dashboard fetches all 9 stat endpoints atomically via `Promise.all` before updating state.

### Suricata Event Classification
- Only Suricata messages matching the IDS alert regex (with signature, IPs, ports) are classified as `threat`.
- Suricata system messages (e.g., `acquire lock`) are classified as `system`.

## UI Features
- **Country flags:** Emoji flags + 2-letter codes on all external IPs (via Unicode regional indicators)
- **Abuse score badges:** Color-coded pills (green/yellow/orange/red) based on AbuseIPDB confidence score
- **Threat Intel summary:** Two rows of cards — all-time totals from enrichment cache + period-filtered stats from events

## Threat Hunt (Beta)
AI-powered threat actor investigation view. Standalone — no wiring to other views.

### Architecture
- **Backend:** `src/api/routes/threat-hunt.js` — settings persistence + investigation endpoint
- **Frontend:** `frontend/src/components/hunt/ThreatHunt.jsx` + `.css`
- **Settings:** Stored in SQLite `settings` table with `hunt_` prefix (survives DB reset)

### Investigation Flow
1. User enters target IP/hostname
2. Backend gathers **local intelligence** from SIEM DB:
   - Total events, events by action/type
   - Top 20 destination ports targeted, top 10 source ports
   - IDS/IPS signatures triggered
   - Activity timeline (hourly buckets)
   - First/last seen timestamps
   - Unique targets hit
   - Related IPs from same /24 subnet (from enrichment cache)
3. Backend gathers **external intelligence**:
   - Reverse DNS (Node.js `dns.promises.reverse`)
   - WHOIS/ASN via ipinfo.io (free, no key required)
4. Builds structured prompt with all data → sends to selected AI provider
5. AI returns structured threat assessment (8 sections)
6. Frontend renders: intel summary cards, detail breakdown, full AI analysis
7. PDF export opens print-formatted report in new window

### AI Providers
| Provider | Model | Endpoint |
|----------|-------|----------|
| Anthropic | Claude Opus 4.6 | `api.anthropic.com/v1/messages` |
| OpenAI | GPT-5.4 | `api.openai.com/v1/chat/completions` |
| Google | Gemini 3.1 Pro | `generativelanguage.googleapis.com/v1beta` |

*Currently tested with Anthropic only.*

### AI Prompt Structure
The prompt provides the AI with all gathered data and requests 8 structured sections:
1. Threat Classification
2. Confidence Level
3. Actor Profile
4. Intent Analysis
5. Risk Assessment
6. Indicators of Compromise (IOCs)
7. Recommended Actions
8. Related Threat Intelligence

### Security
- API keys stored in DB, redacted in GET responses (last 4 chars only)
- Keys never sent to frontend — investigation calls are server-side only
- No key = no investigation (frontend blocks the button)

## Enrichment Backfill (Worker Thread)
When enrichment completes for an IP, existing events need updating with geo/abuse data. All UPDATE operations run in a dedicated worker thread to avoid blocking the main event loop.

### Architecture
- **Worker thread:** `src/enrichment/enrichment-worker.js` runs in a `worker_threads` Worker with its own `better-sqlite3` connection
- **Communication:** Main thread sends `{ type: 'update', ip, data }` or `{ type: 'backfill' }` messages via `postMessage()`
- **Worker reports:** Progress updates (`backfill-progress`), completion (`backfill-done`), and per-IP results (`update-done`) back to main thread for logging
- **Lifecycle:** Worker is initialized on first use, auto-restarts on unexpected exit, and shuts down gracefully with the main process

### Performance Characteristics
- **Deferred startup:** 30-second delay before backfill begins (server starts responsive)
- **Chunked processing:** 10 IPs per chunk with 100ms `setTimeout` yield between chunks (more aggressive than previous main-thread approach since worker doesn't block the event loop)
- **Row limits:** 1,000 rows per IP per direction (most recent first via `ORDER BY rowid DESC`)
- **Partial indexes:** `idx_events_src_unenriched` and `idx_events_dst_unenriched` for fast lookup of unenriched rows
- **Observed:** 6,623 IPs backfilled (70,825 row updates) in ~1.5 minutes with 0% main thread CPU. Previously took 4+ hours at 99% CPU when running on the main thread.

## Important Notes
- **Syslog logging must be enabled per-rule** on the UniFi gateway. WAN/Internet firewall rules need "Enable Logging" checked individually — there is no global toggle.
- Only external (non-RFC1918) IPs are enriched with GeoIP and threat intel.
- The enrichment queue is async and non-blocking — events are stored immediately, enriched in the background.
- Frontend is pre-built in `frontend/dist/` and served statically by Express.
