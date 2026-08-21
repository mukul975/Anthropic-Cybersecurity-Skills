# InfraGuard — Config Schema & API Reference

## Full config.yaml Schema

```yaml
# ─── LISTENERS ───────────────────────────────────────────────────────────────
listeners:
  - bind: "0.0.0.0"           # bind address
    port: 443                   # port
    tls:
      cert: "/path/fullchain.pem"
      key: "/path/privkey.pem"
    domains:
      - "cdn.example.com"
    # protocol: http|https|dns|mqtt|wss (default: https if tls present, else http)

# ─── DOMAINS ─────────────────────────────────────────────────────────────────
domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"
    upstream_ssl_verify: false           # skip SSL verification for teamserver
    profile_path: "path/to/c2.profile"  # C2 profile file
    profile_type: "cobalt_strike"        # see profile types

    whitelist_cidrs:                     # bypass all filters for these CIDRs
      - "10.0.0.0/8"

    drop_action:
      type: "redirect"                   # redirect|reset|proxy|tarpit|decoy
      target: "https://jquery.com"       # URL for redirect/proxy, dir name for decoy

    circuit_breaker:
      enabled: true
      failure_threshold: 5
      reset_timeout_seconds: 60

    content_routes:
      - path: "/update.js"               # exact path or prefix
        backend:
          type: "filesystem"             # filesystem|pwndrop|mythic_file|http_proxy
          target: "/app/payloads/x.js"  # path/URL/file_id depending on type
          ssl_verify: false             # for mythic_file/http_proxy
          headers:                      # inject response headers
            Content-Disposition: "attachment; filename=\"update.js\""
        guard:
          require_beacon_ip: true        # only allow IPs that previously beaconed
          allowed_user_agents:
            - "^Mozilla/5\\.0 \\(Windows NT"
          forbidden_headers:
            - "Via"
            - "X-Forwarded-For"
          required_headers:
            - "X-Custom-Header"
        require_token: true              # require payload_token
        rate_limit:
          enabled: true
          max_downloads: 1
          window_seconds: 3600
        conditional:
          score_threshold: 0.5          # below threshold = serve payload
          scanner_backend:              # above threshold = proxy to decoy backend
            type: "http_proxy"
            target: "https://cdn.jquery.com"
        track: true                     # record in DB

# ─── INTEL ───────────────────────────────────────────────────────────────────
intel:
  auto_block_scanners: true
  dynamic_whitelist_threshold: 3
  geoip_db: "/app/geoip/GeoLite2-City.mmdb"
  geoip_asn_db: "/app/geoip/GeoLite2-ASN.mmdb"
  geoip_country_db: "/app/geoip/GeoLite2-Country.mmdb"
  banned_ip_file: "/app/rules/banned_ips.txt"
  rules_dir: "/app/rules"
  dns_enum_nxdomain_threshold: 15
  dns_enum_window_seconds: 30
  feeds:
    enabled: true
    update_interval_hours: 24
  ct_monitor:
    enabled: false
    domains: []                         # domains to watch in CT logs
  reputation_monitor:
    enabled: false
  burn_detect:
    enabled: true

# ─── TRACKING ────────────────────────────────────────────────────────────────
tracking:
  db_path: "/app/data/infraguard.db"

# ─── PIPELINE ────────────────────────────────────────────────────────────────
pipeline:
  filter_mode: "scoring"                # scoring|hard
  block_score_threshold: 0.7
  replay_window_seconds: 86400
  replay_persist: true
  enable_enumeration_filter: true
  enumeration_unique_path_threshold: 20
  enumeration_unique_path_suspect_threshold: 8
  enumeration_window_seconds: 60
  enable_sandbox_filter: true
  enable_ja3_filter: true
  ja3_filter:
    log_ja3: true
    block_unknown: false
    ja3_header: "x-ja3"

# ─── API ─────────────────────────────────────────────────────────────────────
api:
  bind: "0.0.0.0"
  port: 8080
  auth_token: "${INFRAGUARD_API_TOKEN}"
  health_path: "/health"

# ─── PAYLOAD TOKENS ──────────────────────────────────────────────────────────
payload_tokens:
  enabled: false
  default_ttl_seconds: 3600
  default_max_uses: 1
  token_header: "X-DL-Token"
  token_param: "_t"
  issuance_header: "X-Payload-Token"

# ─── DECOY PAGES ─────────────────────────────────────────────────────────────
decoy_pages_dir: "/app/pages"

# ─── LOGGING ─────────────────────────────────────────────────────────────────
logging:
  level: "INFO"                         # DEBUG|INFO|WARNING|ERROR
  format: "json"                        # json|text

# ─── PLUGINS ─────────────────────────────────────────────────────────────────
plugins:
  elasticsearch:
    enabled: false
    url: "https://elastic:9200"
    api_key: ""
    index: "infraguard-requests"

  wazuh:
    enabled: false
    api_url: "https://wazuh:55000"
    indexer_url: "https://wazuh-indexer:9200"
    password: ""

  syslog:
    enabled: false
    host: "siem.internal"
    port: 514
    protocol: "udp"

  discord:
    enabled: false
    webhook_url: ""
    events:
      - blocked_request
      - burn_alert
      - payload_download

  slack:
    enabled: false
    webhook_url: ""

  webhook:
    enabled: false
    url: ""
    token: ""
```

## REST API Endpoints

Base: `https://infraguard:8080`
Auth: `Authorization: Bearer <INFRAGUARD_API_TOKEN>`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` (configurable) | Health check — no auth required |
| GET | `/api/stats` | Aggregated request stats |
| GET | `/api/requests` | Recent request log (paginated) |
| GET | `/api/requests?ip=1.2.3.4` | Filter by IP |
| GET | `/api/blocked` | Blocked IPs/CIDRs list |
| POST | `/api/blocked` | Add IP/CIDR to blocklist |
| DELETE | `/api/blocked/{ip}` | Remove from blocklist |
| GET | `/api/tokens` | List active payload tokens |
| POST | `/api/tokens` | Issue new payload token |
| DELETE | `/api/tokens/{id}` | Revoke token |
| GET | `/api/nodes` | List proxy nodes (Command Post) |
| GET | `/api/config` | Current config (sanitized) |
| POST | `/api/reload` | Trigger config hot-reload (SIGHUP) |
| GET | `/ws/events` | WebSocket stream of request events |

## banned_ips.txt Format

```
# Comments with #
# CIDR ranges
8.8.8.0/24
35.0.0.0/8

# Single IPs
1.2.3.4

# User-Agent patterns (suffix with UA: prefix)
# UA: curl
# UA: Python-urllib
# UA: Zoom
```

## Ingest Formats

`infraguard ingest <files>` accepts:
- **Apache .htaccess** — extracts `RewriteCond %{REMOTE_ADDR}` and `RewriteCond %{HTTP_USER_AGENT}` rules
- **robots.txt** — extracts disallowed paths for reference

Output formats:
- `--format blocklist` → banned_ips.txt (CIDRs + UA patterns)
- `--format summary` → human-readable summary table
- `--format json` → structured JSON array

## Profile File Formats

### Cobalt Strike
Accepts: `.profile` (malleable C2 text) or `.json` (converted via `profile convert`)

```bash
infraguard profile parse cs-jquery.profile --type cobalt_strike
infraguard profile convert cs-jquery.profile -o cs-jquery.json
```

### Mythic
Accepts: `.json` (C2 profile exported from Mythic UI)

### Others (Havoc, Sliver, BRC4, Nighthawk, PoshC2)
Each has a parser in `infraguard/profiles/<name>.py`. Pass the framework's native profile format.

## Docker Compose Profiles

| Profile flag | Services enabled |
|-------------|-----------------|
| _(none)_ | `proxy`, `dashboard` |
| `--profile letsencrypt` | + `certbot`, `certbot-renew` |
| `--profile geoip` | + `geoip-update` |
| `--profile pwndrop` | + `pwndrop` (payload delivery on :8443) |
| `--profile command-post` | + `command-post` (aggregator on :9090) |

Scale proxy instances:
```bash
docker compose up -d --scale proxy-node=3
```

## Environment Variable Substitution

All `config.yaml` values support `${VAR_NAME}` substitution from environment or `.env` file:

```yaml
upstream: "${INFRAGUARD_CS_UPSTREAM}"   # resolved at startup
api:
  auth_token: "${INFRAGUARD_API_TOKEN}"
```

## Supported C2 Upstream Variables

| Variable | C2 |
|----------|----|
| `INFRAGUARD_CS_UPSTREAM` | Cobalt Strike |
| `INFRAGUARD_MYTHIC_UPSTREAM` | Mythic |
| `INFRAGUARD_BRC4_UPSTREAM` | Brute Ratel C4 |
| `INFRAGUARD_SLIVER_UPSTREAM` | Sliver |
| `INFRAGUARD_HAVOC_UPSTREAM` | Havoc |
| `INFRAGUARD_NIGHTHAWK_UPSTREAM` | Nighthawk |
| `INFRAGUARD_POSHC2_UPSTREAM` | PoshC2 |
