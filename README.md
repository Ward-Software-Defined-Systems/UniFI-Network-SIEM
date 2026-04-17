# UniFi Network SIEM

![AI Powered](https://img.shields.io/badge/AI-Powered_Threat_Hunting-blueviolet?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiPjxwYXRoIGQ9Ik0xMiAyYTEwIDEwIDAgMSAwIDAgMjAgMTAgMTAgMCAwIDAgMC0yMHoiLz48cGF0aCBkPSJNMTIgOHY0bDMgMyIvPjwvc3ZnPg==)
![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)
![Node.js](https://img.shields.io/badge/Node.js-22_LTS+-green?style=flat-square)

A self-contained, **AI-powered** Node.js application that collects syslog from UniFi consoles and gateways, parses all event types, stores them in SQLite (or OpenSearch/WardSONDB), and serves a real-time security dashboard with built-in AI threat hunting.

> **📊 Backend Recommendation for Scale:** Both **OpenSearch** and **SQLite** are production-ready at scale. OpenSearch uses native aggregations (`date_histogram`, `terms`, `cardinality`) for sub-second dashboard queries. SQLite uses five materialized rollup tables updated atomically on insert plus a dedicated stats worker thread, tested stable at 8M+ events. **WardSONDB** mirrors SQLite's rollup pattern (daily event partitions + five rollup collections) and is running live at 12M+ events — optimizations are still being iterated on and tested, so treat it as Beta for now. See [Using OpenSearch Backend](#using-opensearch-backend-optional) below to get started.

## Features

- **Syslog collector** — UDP listener for UniFi Traffic Logging and Activity Logging (CEF)
- **11 event type parsers** — firewall, threat, DHCP, DNS, DNS filter (CoreDNS ad-block), Wi-Fi, admin, device, client, VPN, system
- **Real-time live stream** — WebSocket-powered event table with type/action badges, search, and pause
- **Dashboard** — stats cards, event timeline chart, top blocked, top threats, top ports, top clients, top sources, top destinations; progressive loading with progress bar
- **Live Map** — Leaflet-based world map showing geo-enriched traffic with color-coded markers (normal/blocked/threat), flow lines, and stats overlay
- **Refresh controls** — Dashboard, Live Map, and Threat Intel all include manual refresh, pause/resume, and selectable auto-refresh rates (1m, 2m, 5m). Defaults to paused to reduce load on large datasets — especially useful with remote database backends (e.g., WardSONDB over VPN) where concurrent queries can be expensive
- **GeoIP & threat enrichment** — MaxMind GeoLite2 for geolocation, AbuseIPDB for threat scoring, reverse DNS — all async with caching
- **Country flags & abuse badges** — 🇺🇸 emoji flags with country codes on external IPs; color-coded abuse score badges across all views
- **Threat Intel** — sortable/filterable table of enriched IPs with abuse scores, event counts, and locations; period-filtered summary cards alongside all-time totals
- **Threat Hunt (Beta)** — AI-powered threat actor investigation with SSE streaming. Enter any IP and choose a time window (`1h / 6h / 24h / 7d / 30d`) — the same period selector used by Dashboard / Live Map / Threat Intel — and every local-intel query is scoped to that window. Returns a full profile: local SIEM activity (events, ports, timeline, IDS signatures, related /24 IPs), external intel (rDNS, WHOIS/ASN), and a structured AI threat assessment streamed token-by-token with PDF export. Supports Anthropic (Opus 4.6 with adaptive thinking, 128K output), OpenAI (GPT-5.4, 128K output), and Google (Gemini 3.1 Pro, 65K output) with on-page API key management. *Currently tested with Anthropic only — OpenAI and Google integrations are implemented but untested.*
- **HTTPS by default** — auto-generated self-signed TLS certificate
- **Pluggable storage backends** — SQLite (built-in default), WardSONDB (Beta), OpenSearch (Beta). OpenSearch runs via Docker with native aggregations (no rollup tables), batched enrichment backfill with `update_by_query`, and full Threat Hunt support. WardSONDB runs remotely over HTTPS with a per-client undici dispatcher for connect-timeout tuning
- **SQLite storage** — WAL mode, batched inserts, automatic retention cleanup, worker thread enrichment. Materialized rollup tables (event_stats_5m, ip/port/sig/client_stats_hourly) are updated atomically on insert for sub-second dashboard stats at scale (tested to 8M+ events). A dedicated stats worker thread keeps the event loop responsive during queries. Existing databases self-heal on restart: legacy indexes are automatically dropped and replaced with optimized compound indexes, and rollup tables are backfilled from existing events on first upgrade
- **WardSONDB storage** — daily event partitions (`events-YYYY-MM-DD`) with partition-drop retention (no `_delete_by_query` on event data), five pre-aggregated rollup collections matching SQLite's schemas exactly (`rollups-5m`, `rollups-ip-hourly`, `rollups-port-hourly`, `rollups-sig-hourly`, `rollups-client-hourly`) flushed every 5 seconds via read-then-increment. Dashboard stats, Live Map, and Threat Intel all query rollups exclusively; Threat Hunt fans out across the partitions overlapping the selected period with per-partition result merging. Running live at 12M+ events — still iterating on optimizations
- **Zero external services** — everything runs in one process

## Screenshots

### Dashboard
![Dashboard](screenshots/Dashboard.png)

### Live Map
![Live Map](screenshots/LiveMap.png)

### Threat Intel
![Threat Intel](screenshots/ThreatIntel.png)

### Threat Hunt (Beta)
![Threat Hunt Beta](screenshots/ThreatHuntBeta.png)

### Live Stream
![Live Stream](screenshots/LiveStream.png)

### Settings
![Settings](screenshots/Settings.png)

## Quick Start

### Prerequisites

- **Node.js v22 LTS** — pinned via `.nvmrc`, so `nvm use` (or `fnm use` / `nodenv local`) will pick the right version automatically
- **C++ build toolchain** for `better-sqlite3`'s native build:
  - macOS: `xcode-select --install`
  - Debian / Ubuntu: `sudo apt-get install build-essential python3`
  - Windows: Visual Studio 2022 Build Tools with the "Desktop development with C++" workload
- macOS, Linux, or Windows

### Install

```bash
# Backend
npm install

# Frontend
cd frontend && npm install && cd ..

# Configure
cp .env.example .env
# Edit .env if needed (defaults work for most setups)

# Optional but recommended: download MaxMind GeoLite2-City.mmdb to ./data/
# Live Map and Threat Intel need this to populate geo data — see "Enrichment Setup" below
```

### Run

```bash
# Production (serves built frontend)
cd frontend && npm run build && cd ..
npm start

# Development (two terminals)
npm run dev          # Backend with auto-reload (port 3000)
cd frontend && npm run dev   # Vite HMR (port 5173)
```

Open https://localhost:3000 in your browser. Accept the self-signed certificate warning on first visit.

### Using OpenSearch Backend (Optional)

```bash
# Start OpenSearch via Docker (HTTPS + self-signed cert, 4GB heap)
./docker/opensearch/start.sh

# Start SIEM with OpenSearch env vars
OPENSEARCH_HOST=localhost OPENSEARCH_PORT=9200 \
OPENSEARCH_USERNAME=admin OPENSEARCH_PASSWORD='S!em_Secure9200' \
OPENSEARCH_USE_TLS=true OPENSEARCH_VERIFY_CERTS=false \
npm run dev
```

Or select OpenSearch from Settings > Database Engine in the web UI and restart. Configuration is persisted — env vars are only needed for initial setup.

### Test with fake syslog

```bash
node scripts/test-syslog.js
# Sends 10 msgs/sec by default. Set RATE=100 for more volume.
```

## UniFi Console Configuration

For full functionality, three logging sources on the UniFi Console should be configured. All share the same UDP port — the parser auto-detects the format.

### Source 1: Traffic Logging / Syslog (firewall, IDS, DHCP, Wi-Fi)

1. **Settings > Policy Engine** — for each firewall rule, Edit > Advanced > **Enable Syslog Logging**

> ⚠️ **Important**: This must be enabled on **every firewall rule** you want to monitor — including WAN IN/OUT and inter-VLAN rules. Rules without syslog enabled will pass/drop traffic silently with no log sent. This is the most commonly missed step and will result in missing events (especially external IP traffic needed for the Live Map and Threat Intel).

2. **Settings > CyberSecure > Traffic Logging**:
   - Flow Logging: **All Traffic** (or Blocked Only for less volume)
   - Activity Logging (Syslog): Enable **SIEM Server**
   - Server Address: `<your-machine-ip>`
   - Port: `5514`
   - Categories: Enable all desired (Firewall Default Policy, Security Detections, etc.)

### Source 2: Activity Logging / CEF (admin, device, client events)

1. **Settings > Control Plane > Integrations > Activity Logging**:
   - Enable **SIEM Server**
   - Server Address: `<your-machine-ip>`
   - Port: `5514`
   - Categories: Enable Clients, Devices, Security Detections, Triggers, VPN, Critical

### Source 3: Debug Logs (detailed DHCP, system processes)

1. **Settings > CyberSecure > Traffic Logging**:
   - Enable **Debug Logs**
   - This enables detailed `dnsmasq-dhcp` lease events, `ubios-udapi-server` messages, and other system process logs from the gateway
   - Without this, DHCP events and many system-level messages won't be forwarded

### Source 4: Netconsole (kernel-level logging)

1. **Settings > CyberSecure > Traffic Logging**:
   - Enable **Netconsole**
   - Server Address: `<your-machine-ip>`
   - Port: `5514`
   - Provides kernel-level messages including firewall rule hits and low-level network events

> **Note**: All four sources can point to the same IP and port. The parser auto-detects CEF, iptables, CoreDNS JSON, hostapd, dnsmasq, and other formats automatically.

## Event Types

| Type | Source | Description |
|---|---|---|
| `firewall` | Traffic Logging | Firewall allow/block decisions (iptables) |
| `threat` | Traffic Logging / CEF | IDS/IPS alerts (Suricata) and CEF threat detections |
| `dhcp` | Traffic Logging | DHCP lease events (dnsmasq + switch relay) |
| `dns` | Traffic Logging | DNS queries/replies (if logging enabled) |
| `dns_filter` | Traffic Logging | CoreDNS ad-block and content filtering blocks |
| `wifi` | Traffic Logging | Wi-Fi client associate/disassociate (hostapd) |
| `admin` | CEF | Admin login, config changes |
| `device` | CEF | Device adoption, restart, firmware |
| `client` | CEF | Client connect/disconnect, roaming |
| `vpn` | CEF / Traffic Logging | VPN tunnel up/down events |
| `system` | Either | Catch-all for unclassified messages |

## API

| Endpoint | Description |
|---|---|
| `GET /api/events` | Query events with filters (type, action, IP, port, search, pagination) |
| `GET /api/events/:id` | Single event detail |
| `GET /api/stats/overview` | Summary counts by type and action |
| `GET /api/stats/timeline` | Time-bucketed event counts for charts |
| `GET /api/stats/top-talkers` | Top source or destination IPs |
| `GET /api/stats/top-blocked` | Top blocked IPs (src or dst direction, exclude_private) |
| `GET /api/stats/top-ports` | Top destination ports |
| `GET /api/stats/top-clients` | Top clients by MAC across event types |
| `GET /api/stats/top-threats` | Top IDS/IPS signatures |
| `GET /api/stats/threat-intel` | Enriched IPs with abuse scores and event counts |
| `GET /api/stats/geo-events` | Aggregated IPs with geo coordinates for map |
| `GET /api/stats/recent-geo-events` | Recent events with geo data for flow lines |
| `GET /api/health` | System health, event counts, DB size |
| `GET /api/settings` | App settings (sensitive values redacted) |
| `PUT /api/settings` | Update settings (AbuseIPDB key, etc.) |
| `POST /api/settings/reset-db` | Clear all events and enrichment cache |
| `GET /api/threat-hunt/settings` | Threat Hunt AI provider settings |
| `PUT /api/threat-hunt/settings` | Update AI provider/keys |
| `POST /api/threat-hunt/investigate` | Run AI-powered threat investigation on an IP (non-streaming) |
| `POST /api/threat-hunt/investigate-stream` | SSE streaming AI investigation (primary endpoint) |
| `WSS /ws/events` | Live event stream with filtering |

## Configuration (.env)

| Variable | Default | Description |
|---|---|---|
| `SYSLOG_PORT` | 5514 | UDP port for syslog listener |
| `HTTP_PORT` | 3000 | Web dashboard port |
| `DB_PATH` | ./data/events.db | SQLite database path |
| `RETENTION_DAYS` | 60 | Auto-delete events older than this |
| `LOG_LEVEL` | info | Logging level (trace/debug/info/warn/error) |
| `GEOIP_DB_PATH` | ./data/GeoLite2-City.mmdb | Path to MaxMind GeoLite2 database |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB API key (free tier: 1000/day) |
| `ABUSEIPDB_CACHE_HOURS` | 24 | Cache duration for abuse scores |
| `RDNS_ENABLED` | false | Enable reverse DNS lookups |
| `LOG_RAW_MESSAGES` | false | Store raw syslog text in DB |
| `INSERT_BATCH_SIZE` | 50 | Batch insert threshold |
| `INSERT_BATCH_INTERVAL_MS` | 500 | Batch insert flush interval |
| `ENRICHMENT_CONCURRENCY` | 5 | Max parallel enrichment lookups |
| `RDNS_TIMEOUT_MS` | 2000 | Reverse DNS lookup timeout (ms) |
| `WS_BROADCAST_THROTTLE_MS` | 100 | WebSocket broadcast throttle interval (ms) |
| `WARDSONDB_HEALTH_TIMEOUT_MS` | 5000 | WardSONDB health check timeout (ms) |
| `WARDSONDB_CONNECT_TIMEOUT_MS` | 60000 | TCP connect timeout for the per-client undici Agent. Default is higher than undici's 10s stock timeout because saturated WardSONDB instances under heavy flush/backfill take longer to accept new connections |
| `WARDSONDB_QUERY_TIMEOUT_MS` | 0 | Client-side headers/body timeout. `0` = no client-side limit (server-side `--query-timeout` governs). Operator escape hatch |
| `WARDSONDB_FLUSH_CONCURRENCY` | 4 | Rollup flush worker-pool size. Lower values reduce accept-loop pressure on saturated WardSONDB instances |
| `HEALTH_REBUILDING_DEBOUNCE_POLLS` | 2 | Consecutive `write_pressure: "high"` polls required before the Rebuilding banner fires. At the 10s poll cadence, `2` ≈ 20s. Eliminates single-poll flickers from volatile write-pressure signals |
| `OPENSEARCH_HOST` | localhost | OpenSearch host |
| `OPENSEARCH_PORT` | 9200 | OpenSearch port |
| `OPENSEARCH_USERNAME` | *(empty)* | Basic auth username (empty = no auth) |
| `OPENSEARCH_PASSWORD` | *(empty)* | Basic auth password |
| `OPENSEARCH_USE_TLS` | false | Enable HTTPS connection |
| `OPENSEARCH_VERIFY_CERTS` | true | Verify TLS certificates (set false for self-signed) |
| `OPENSEARCH_INDEX_PREFIX` | siem- | Prefix for OpenSearch index names |
| `OPENSEARCH_BULK_SIZE` | 50 | Bulk insert batch size |

> **⚠️ Important:** Settings and configuration are always stored in the local SQLite database (`data/events.db`), regardless of which storage backend is active. Do not delete this file even when using WardSONDB or OpenSearch — it contains your backend configuration, API keys, and other settings needed to boot the application. Changing the storage backend requires a SIEM restart to take effect.

> **WardSONDB query timeouts:** Query duration is controlled by WardSONDB's server-side `--query-timeout` flag (default 30s). For large datasets or Threat Hunt queries, launch WardSONDB with `--query-timeout 120` or higher. By default the SIEM has no client-side query timeout — this is intentional. If you need to override per-request (e.g. unreliable network, long-running server-side queries you want to cap), set `WARDSONDB_QUERY_TIMEOUT_MS` in `.env` as an escape hatch.

## Project Structure

```
docker/
  opensearch/
    docker-compose.yml         # OpenSearch single-node + security plugin
    start.sh                   # Boot helper (waits for HTTPS readiness)

src/
  index.js                    # Entry point
  config.js                   # Environment config
  collector/
    syslog-server.js           # UDP listener
    parsers/
      index.js                 # Format detection & routing
      syslog-header.js         # Header parser (4 formats)
      firewall.js              # iptables parser
      ids.js                   # Suricata IDS parser
      dhcp.js                  # dnsmasq-dhcp parser
      dhcp-relay.js            # Switch DHCP relay parser
      dns.js                   # dnsmasq DNS parser
      coredns.js               # CoreDNS ad-block/content filter
      wifi.js                  # hostapd parser
      cef.js                   # CEF (Activity Logging) parser
      system.js                # Catch-all parser
  db/
    database.js                # SQLite connection & schema
    events.js                  # Event CRUD & batch insert
    cache.js                   # IP enrichment cache
    retention.js               # Periodic cleanup
    storage.js                 # Active backend manager (singleton)
    stats-worker.js            # Read-only stats worker thread
    backends/
      interface.js             # StorageBackend base class
      index.js                 # Backend registry & factory
      sqlite.js                # SQLite backend (default)
      wardsondb.js             # WardSONDB backend (Beta)
      opensearch.js            # OpenSearch backend (Beta)
  api/
    server.js                  # Express + static serving
    websocket.js               # WebSocket live stream
    routes/                    # REST API routes
  enrichment/
    geoip.js                   # MaxMind GeoLite2 lookup
    abuseipdb.js               # AbuseIPDB API client
    rdns.js                    # Reverse DNS lookup
    enrichment-queue.js        # Async enrichment coordinator
    enrichment-worker.js       # Worker thread for SQLite UPDATEs
  utils/                       # IP utils, port names, constants

frontend/                      # React + Vite + Tailwind
  src/
    components/
      Layout.jsx               # App shell + navigation
      Settings.jsx              # Settings view
      live/                    # Live stream view
      dashboard/               # Analytics dashboard
      map/                     # Live Map (Leaflet)
      intel/                   # Threat Intel view
      hunt/                    # Threat Hunt (Beta) — AI investigation
      shared/                  # Badges, selectors
    hooks/                     # WebSocket & query hooks
    lib/                       # API client, formatters

scripts/
  test-syslog.js               # Test message generator
```

## Enrichment Setup (Optional)

### GeoIP (enables Live Map)

1. Sign up at [MaxMind](https://www.maxmind.com/en/geolite2/signup) (free)
2. Download `GeoLite2-City.mmdb`
3. Place in `./data/GeoLite2-City.mmdb`

### AbuseIPDB (threat scoring)

1. Get a free API key at [abuseipdb.com](https://www.abuseipdb.com) (1000 lookups/day)
2. Set `ABUSEIPDB_API_KEY` in `.env`, or save via the Settings page (no restart needed)
3. If the daily limit is reached, lookups automatically back off for 1 hour

## Security

The app runs HTTPS by default with an auto-generated self-signed certificate. Below are remaining security considerations.

| Concern | Severity | Description |
|---|---|---|
| No authentication | **Medium** | The web UI, API, and database reset are accessible to anyone who can reach port 3000. On a trusted home network this is acceptable. If exposed beyond your LAN, put it behind a reverse proxy with auth (nginx/Caddy with basic auth or mTLS). |
| Syslog spoofing | **Low** | The UDP syslog listener accepts messages from any source on the network. A device on your LAN could send crafted syslog to inject fake events. UDP has no authentication by design — this is inherent to syslog. |
| Database reset without auth | **Low** | The `POST /api/settings/reset-db` endpoint requires no credentials. Mitigated by the network-only access constraint and the two-click confirmation in the UI. |
| TLS certificate trust | **Info** | The self-signed certificate will trigger browser warnings. For production, replace `data/server.key` and `data/server.cert` with certs from a trusted CA or your own internal CA. |

**Known advisories:**
- **esbuild ≤ 0.24.2 (moderate)** — allows any website to send requests to the Vite dev server and read responses ([GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99)). This is a dev-only dependency used during frontend development — it does not affect production builds or the deployed SIEM. Fix requires upgrading Vite to 7.x (breaking change).

**Already mitigated:**
- **SQL injection** — all queries use parameterized prepared statements. The `getTimeline()` strftime format string is derived from a fixed internal lookup (not from caller input), eliminating the previous injection surface
- **XSS** — React auto-escapes all rendered content including untrusted syslog data
- **API key exposure** — AbuseIPDB key is redacted in API responses (last 4 chars only)
- **Transport security** — HTTPS/WSS enabled by default with auto-generated TLS certificate
- **Parser crashes** — all parsers wrapped in try/catch with fallback to system parser
- **AbuseIPDB rate limits** — automatic 1-hour backoff when daily limit is reached

## Known Issues

| Issue | Status | Description |
|---|---|---|
| AbuseIPDB scores not populating | **Fixed** | AbuseIPDB API field name was `abuseConfidenceScore` but code referenced `abuseConfidencePercentage` — scores were always `null`. Fixed in commit `11607e4`. Also added re-queue logic for cached IPs missing abuse scores. |
| Database reset pegs CPU on large datasets | **Fixed** | Using "Initialize Database" previously ran `DELETE` + `VACUUM` on millions of rows, pegging CPU at 100% for 10+ minutes. Fixed by switching to `DROP TABLE` + schema recreate, which is instant regardless of database size. Fixed in commit `11607e4`. |
| Enrichment backfill pegs CPU at 100% | **Fixed** | Backfill UPDATE queries blocked the main Node.js event loop via synchronous `better-sqlite3` calls, sustaining 99% CPU for 4+ hours. Fixed by moving all enrichment UPDATEs to a dedicated `worker_threads` Worker with its own DB connection. Backfill of 6,600+ IPs now completes in ~1.5 minutes with 0% main thread CPU. Fixed in commit `ca0f8ea`. |

## Roadmap

- [x] Abuse score badges on IPs in tables
- [x] Country flags on external IPs
- [x] Threat Hunting view — AI-powered investigation with SSE streaming, adaptive thinking (Anthropic), 128K token output, and structured threat assessments with PDF export
- [ ] CSV export
- [ ] Dark/light mode toggle
- [x] Performance optimization — enrichment backfill moved to worker thread for non-blocking operation
- [x] Storage backend abstraction — pluggable database engine (SQLite, WardSONDB, OpenSearch) selectable from Settings
- [x] WardSONDB integration — high-performance Rust-based JSON document database with deferred index creation and write pressure detection
- [x] OpenSearch integration — distributed search/analytics engine via Docker with native aggregations, batched enrichment backfill, and full Threat Hunt support
- [x] Query performance optimization — bitmap scan acceleration and compound range scans via WardSONDB, running live at 12M+ events
- [x] WardSONDB scale optimization — daily event partitioning with partition-drop retention and five pre-aggregated rollup collections mirroring SQLite's schema, flushed every 5 seconds. Threat Hunt queries fan out across the partitions overlapping the selected period
- [ ] launchd plist for macOS auto-start
