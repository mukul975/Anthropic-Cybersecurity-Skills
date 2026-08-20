---
name: deploying-infraguard-redirector
description: Install, configure, and operate InfraGuard as a C2 redirector and red team infrastructure tracker — covering Docker/pip install, YAML config, 10-filter pipeline, multi-C2 support (CS/Mythic/Sliver/Havoc/BRC4/Nighthawk/PoshC2), phishing redirectors, edge workers, and the web dashboard.
domain: cybersecurity
subdomain: red-team-infrastructure
tags:
- red-team
- c2-infrastructure
- redirector
- cobalt-strike
- mythic
- sliver
- havoc
- brute-ratel
- phishing
- opsec
version: '1.0'
author: dn9uy3n
license: Apache-2.0
mitre_attack:
- T1090.002
- T1071.001
- T1566
---

# Deploying InfraGuard Redirector

> **Legal Notice:** This skill is for authorized red-team engagements, security assessments, and educational purposes only. Always operate within a signed rules-of-engagement document.

## Overview

InfraGuard (v0.4.3) is an open-source C2 redirector and red team infrastructure tracker. It sits between beacon callbacks and your C2 teamserver, applying a 10-stage filter pipeline to block analysis/sandbox/security-vendor traffic while passing legitimate callbacks through.

Key capabilities:
- **Multi-C2 support**: Cobalt Strike, Mythic, Brute Ratel C4, Sliver, Havoc, Nighthawk, PoshC2
- **Multi-phishing support**: GoPhish, Evilginx2, CuddlePhish, Phishing.club, passthrough
- **10-filter pipeline**: IP, bot, header, geo, DNS, C2 profile validation, replay, enumeration, sandbox, JA3/TLS
- **Payload delivery**: one-time tokens, rate limiting, PwnDrop integration, Mythic file staging
- **Intel**: GeoIP, threat feeds, CT log monitoring, burn detection, DNS enum detection
- **SIEM/webhook**: Elasticsearch, Wazuh, Syslog, Discord, Slack
- **Edge workers**: Cloudflare Worker + AWS Lambda for domain fronting
- **Decoy pages**: served to blocked visitors instead of reset/redirect

## When to Use

- Standing up a C2 redirector that filters out security vendors and sandboxes before proxying to teamserver
- Replacing a static Apache/.htaccess redirector with dynamic, profiled filtering
- Setting up a phishing landing page redirector with token-based payload delivery
- Needing burn detection + engagement reporting across multiple C2 instances
- Deploying domain-fronted C2 via Cloudflare Worker or AWS Lambda

## Prerequisites

- Linux server (VPS) with public IP, ports 443/80 open
- Domain(s) pointed at the server
- C2 teamserver on internal/separate IP (not exposed publicly)
- Python 3.12+ OR Docker + Docker Compose
- (Optional) MaxMind GeoLite2 license key for GeoIP filtering
- Signed authorization / rules of engagement

## Installation

### Option A: pip (development/testing)

```bash
# Full install with all features
pip install "infraguard[all]"

# Minimal (proxy only, no web UI or TUI)
pip install infraguard

# Verify
infraguard --version
```

### Option B: Docker (recommended for production)

```bash
git clone <infraguard-repo>
cd infraguard

# Copy and edit environment
cp .env.example .env
$EDITOR .env

# Start proxy + dashboard
docker compose up -d proxy dashboard

# With Let's Encrypt TLS
docker compose --profile letsencrypt up -d

# With GeoIP databases
docker compose --profile geoip up -d

# Full stack (LE + GeoIP + PwnDrop + Command Post)
docker compose --profile letsencrypt --profile geoip --profile pwndrop --profile command-post up -d

# Check logs
docker compose logs -f proxy
```

### Environment variables (.env)

Critical vars to set before first run:

```bash
# Your redirector domain
INFRAGUARD_DOMAIN=cdn.example.com
INFRAGUARD_DOMAIN_EMAIL=operator@example.com

# TLS (use LE profile or provide manually)
INFRAGUARD_LETSENCRYPT=false
INFRAGUARD_TLS_CERT=/app/certs/live/cdn.example.com/fullchain.pem
INFRAGUARD_TLS_KEY=/app/certs/live/cdn.example.com/privkey.pem

# API auth token (generate with: python -c "import secrets; print(secrets.token_urlsafe(32))")
INFRAGUARD_API_TOKEN=<token>

# Upstream teamserver (internal IP)
INFRAGUARD_CS_UPSTREAM=https://10.0.0.5:8443
INFRAGUARD_MYTHIC_UPSTREAM=https://10.0.0.6:443

# Filter mode (scoring = soft block; hard = strict block)
INFRAGUARD_FILTER_MODE=scoring
```

## Quick Start

### Generate starter config

```bash
# Interactive config generator
infraguard config init -o config.yaml

# Full config bundle for a domain (CS example)
infraguard config generate \
  --domain cdn.example.com \
  --c2-profile examples/jquery-c2.3.14.profile \
  --upstream https://10.0.0.5:8443 \
  --profile-type cobalt_strike \
  --drop-target https://jquery.com \
  -o ./config/

# Validate before running
infraguard config validate -c config/config.yaml
```

### Start the proxy

```bash
# Direct
infraguard run -c config/config.yaml

# Docker
docker compose up -d proxy

# With dashboard on separate port
infraguard dashboard -c config/config.yaml --port 8080

# TUI (terminal UI)
infraguard tui -c config/config.yaml
# or connect to running instance
infraguard tui --url https://localhost:8080 --token $INFRAGUARD_API_TOKEN
```

## Configuration Reference

The main config (`config.yaml`) has these top-level keys:

### `listeners`

Bind addresses and TLS config:

```yaml
listeners:
  - bind: "0.0.0.0"
    port: 443
    tls:
      cert: "/app/certs/fullchain.pem"
      key: "/app/certs/privkey.pem"
    domains:
      - "cdn.example.com"
  - bind: "0.0.0.0"
    port: 80
    domains:
      - "cdn.example.com"
```

Additional listener protocols: `dns`, `mqtt`, `wss` (WebSocket).

### `domains`

Per-domain routing — the core config block:

```yaml
domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"        # teamserver/phishing server
    profile_path: "path/to/c2.profile"        # C2 profile for validation
    profile_type: "cobalt_strike"              # see Profile Types below

    whitelist_cidrs:                           # always-allow ranges
      - "10.0.0.0/8"
      - "192.168.1.100/32"

    drop_action:                               # what to do with blocked requests
      type: "redirect"                         # redirect | reset | proxy | tarpit | decoy
      target: "https://jquery.com"

    circuit_breaker:                           # protect teamserver if it goes down
      enabled: true
      failure_threshold: 5
      reset_timeout_seconds: 60

    content_routes:                            # optional per-path payload delivery
      - path: "/update.js"
        backend:
          type: "filesystem"                   # filesystem | pwndrop | mythic_file | http_proxy
          target: "/app/payloads/update.js"
        guard:
          require_beacon_ip: true
          allowed_user_agents:
            - "^Mozilla/5\\.0 \\(Windows NT"
          forbidden_headers:
            - "Via"
            - "X-Forwarded-For"
        require_token: true
        rate_limit:
          enabled: true
          max_downloads: 1
          window_seconds: 3600
        track: true
```

#### Profile Types

| `profile_type` value | C2 / Tool |
|---------------------|-----------|
| `cobalt_strike` | Cobalt Strike (.profile files) |
| `mythic` | Mythic (HTTP C2 profile JSON) |
| `mythic_http` | Mythic HTTP C2 variant |
| `brute_ratel` | Brute Ratel C4 |
| `sliver` | Sliver |
| `havoc` | Havoc |
| `nighthawk` | Nighthawk |
| `poshc2` | PoshC2 |
| `gophish` | GoPhish phishing |
| `evilginx` | Evilginx2 |
| `cuddlephish` | CuddlePhish |
| `phishing_club` | Phishing.club |
| `passthrough` | No profile validation (raw proxy) |
| `ligolo` | Ligolo-ng tunnel |
| `chisel` | Chisel tunnel |

#### Drop Action Types

| `type` | Behavior |
|--------|----------|
| `redirect` | HTTP 302 to `target` URL |
| `reset` | TCP RST — connection dropped silently |
| `proxy` | Proxy to a decoy site (e.g., real CDN) |
| `tarpit` | Slow-drip response to waste scanner time |
| `decoy` | Serve local HTML decoy page from `decoy_pages_dir` |

### `pipeline`

10-filter request pipeline:

```yaml
pipeline:
  filter_mode: "scoring"          # scoring (soft) or hard (strict block)
  block_score_threshold: 0.7      # combined score above this = block

  replay_window_seconds: 86400    # block replay of exact requests
  replay_persist: true            # persist replay cache across restarts

  enable_enumeration_filter: true
  enumeration_unique_path_threshold: 20       # total unique paths = block
  enumeration_unique_path_suspect_threshold: 8 # suspect threshold
  enumeration_window_seconds: 60

  enable_sandbox_filter: true     # behavioral sandbox fingerprint detection

  enable_ja3_filter: true
  ja3_filter:
    log_ja3: true                 # log JA3 fingerprints for analysis
    block_unknown: false          # block if JA3 not in known-good list
    ja3_header: "x-ja3"          # header where upstream CDN/nginx injects JA3
```

Filter pipeline order (applied sequentially):

1. **IP filter** — banned IPs/CIDRs from `banned_ip_file` + auto-blocked scanners
2. **Bot filter** — User-Agent pattern matching (curl, Python, scanners)
3. **Header filter** — forbidden/suspicious headers (Via, X-Forwarded-For, scanner headers)
4. **Geo filter** — GeoIP country/ASN blocking
5. **DNS filter** — reverse DNS lookup; block if resolves to known vendor ranges
6. **Profile filter** — validate request matches C2 malleable profile
7. **Replay filter** — block exact request replays (anti-detonation)
8. **Enumeration filter** — detect path enumeration bursts
9. **Sandbox filter** — behavioral fingerprinting (timing, header patterns)
10. **JA3/TLS filter** — TLS fingerprint validation

### `intel`

Threat intelligence feeds and blocking:

```yaml
intel:
  auto_block_scanners: true           # auto-ban IPs hitting non-existent paths
  dynamic_whitelist_threshold: 3      # requests from same IP before auto-allow

  geoip_db: "/app/geoip/GeoLite2-City.mmdb"
  geoip_asn_db: "/app/geoip/GeoLite2-ASN.mmdb"
  geoip_country_db: "/app/geoip/GeoLite2-Country.mmdb"
  banned_ip_file: "/app/rules/banned_ips.txt"
  rules_dir: "/app/rules"

  dns_enum_nxdomain_threshold: 15     # NXDOMAIN count triggering DNS enum block
  dns_enum_window_seconds: 30

  feeds:
    enabled: true                     # pull threat intel feed updates

  ct_monitor:
    enabled: false                    # Certificate Transparency log monitoring
                                      # (detect certs issued for your domain = burn alert)
  reputation_monitor:
    enabled: false                    # external IP reputation checks
```

### `payload_tokens`

One-time download tokens for staged payloads:

```yaml
payload_tokens:
  enabled: true
  default_ttl_seconds: 3600         # token expires after 1h
  default_max_uses: 1               # single-use by default
  token_header: "X-DL-Token"       # header for token auth
  token_param: "_t"                 # URL param alternative
  issuance_header: "X-Payload-Token" # header where issued token is returned
```

Issue a token via API: `POST /api/tokens` → returns token string.
Include in payload URL: `https://cdn.example.com/update.js?_t=<token>`

### `api`

REST API + WebSocket server:

```yaml
api:
  bind: "0.0.0.0"
  port: 8080
  auth_token: "${INFRAGUARD_API_TOKEN}"
  health_path: "/health"            # customize to avoid scanning
```

### `plugins`

SIEM and notification integrations:

```yaml
plugins:
  elasticsearch:
    enabled: true
    url: "${ELASTICSEARCH_URL}"
    api_key: "${ELASTICSEARCH_API_KEY}"
    index: "infraguard-requests"

  wazuh:
    enabled: false
    api_url: "${WAZUH_API_URL}"
    indexer_url: "${WAZUH_INDEXER_URL}"
    password: "${WAZUH_PASSWORD}"

  syslog:
    enabled: false
    host: "siem.internal"
    port: 514
    protocol: "udp"

  discord:
    enabled: true
    webhook_url: "${DISCORD_WEBHOOK_URL}"
    events:
      - blocked_request
      - burn_alert
      - payload_download

  slack:
    enabled: false
    webhook_url: "${SLACK_WEBHOOK_URL}"

  webhook:
    enabled: false
    url: "${WEBHOOK_URL}"
    token: "${WEBHOOK_TOKEN}"
```

### `decoy_pages_dir`

Directory of decoy HTML sites served when `drop_action.type: decoy`:

```yaml
decoy_pages_dir: "/app/pages"
# Set IG_DECOY_SITE=BankingBlog to pick a specific subdirectory
```

Built-in decoy sites: `BankingBlog`, `FinancialBlog`, `HealthcareBlog`, `HospitalBlog`, `InfraShieldBlog`.

## Workflows

### Cobalt Strike Redirector

```bash
# 1. Parse and convert CS malleable profile
infraguard profile parse examples/jquery-c2.3.14.profile --type cobalt_strike
infraguard profile convert examples/jquery-c2.3.14.profile -o config/jquery-c2.json

# 2. Generate config bundle
infraguard config generate \
  --domain cdn.example.com \
  --c2-profile config/jquery-c2.json \
  --upstream https://10.0.0.5:8443 \
  --profile-type cobalt_strike \
  --drop-target https://jquery.com \
  -o config/
```

Minimal `config.yaml` for CS:

```yaml
listeners:
  - bind: "0.0.0.0"
    port: 443
    tls:
      cert: "/app/certs/fullchain.pem"
      key: "/app/certs/privkey.pem"
    domains: ["cdn.example.com"]

domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"
    profile_path: "config/jquery-c2.json"
    profile_type: "cobalt_strike"
    drop_action:
      type: "redirect"
      target: "https://jquery.com"
```

### Mythic Redirector with Staged Payload

```yaml
domains:
  cdn.example.com:
    upstream: "https://10.0.0.6:443"
    profile_path: "config/mythic-http.json"
    profile_type: "mythic"
    drop_action:
      type: "decoy"
      target: "InfraShieldBlog"

    content_routes:
      - path: "/assets/bootstrap.min.js"
        backend:
          type: "mythic_file"
          target: "https://10.0.0.6:7443"    # Mythic API URL
          file_id: "${MYTHIC_STAGE2_FILE_ID}"
          ssl_verify: false
        guard:
          require_beacon_ip: true
          allowed_user_agents:
            - "^Mozilla/5\\.0 \\(Windows NT"
        require_token: true
        rate_limit:
          enabled: true
          max_downloads: 1
          window_seconds: 3600
        track: true
```

### Phishing Redirector (GoPhish)

```yaml
domains:
  phish.example.com:
    upstream: "https://10.0.0.7:3333"       # GoPhish landing page server
    profile_type: "gophish"
    drop_action:
      type: "redirect"
      target: "https://microsoft.com"
    whitelist_cidrs:
      - "10.0.0.0/8"
```

### Phishing Redirector (Evilginx2)

```yaml
domains:
  login.example.com:
    upstream: "https://10.0.0.8:443"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://login.microsoft.com"
```

### Ingest .htaccess Blocklist

Convert an existing Apache .htaccess blocklist:

```bash
# Parse and convert to infraguard banned_ips.txt format
infraguard ingest rules/.htaccess --format blocklist -o rules/banned_ips.txt

# View summary of ingested rules
infraguard ingest rules/.htaccess --format summary

# Multiple input files
infraguard ingest rules/.htaccess rules/robots.txt --format blocklist -o rules/banned_ips.txt
```

### Test Request Pipeline (Dry-Run)

Simulate a request through the filter pipeline without sending real traffic:

```bash
# Basic test
infraguard test-request \
  -c config/config.yaml \
  --domain cdn.example.com \
  --path /jquery-3.7.1.min.js \
  --method GET \
  --ip 1.2.3.4 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# With custom headers
infraguard test-request \
  -c config/config.yaml \
  --domain cdn.example.com \
  --header "X-Forwarded-For: 8.8.8.8" \
  --header "Via: 1.1 proxy.corp.internal"

# Output shows per-filter verdict + final action + score
```

### Generate Engagement Report

```bash
infraguard report \
  --db /app/data/infraguard.db \
  -o report.html \
  --title "Q1 2026 Red Team — Acme Corp"
```

### Backend Config Generation

Generate an nginx/caddy/apache config to use as CDN/TLS-terminator upstream:

```bash
# nginx
infraguard generate nginx \
  -c config/config.yaml \
  --listen-port 443 \
  --ssl-cert /etc/ssl/certs/cert.pem \
  --ssl-key /etc/ssl/private/key.pem \
  --redirect-url https://jquery.com

# caddy
infraguard generate caddy -c config/config.yaml

# apache
infraguard generate apache -c config/config.yaml
```

## Edge Workers

### Cloudflare Worker (Domain Fronting)

Traffic path: `Target → Cloudflare CDN → CF Worker → InfraGuard → Teamserver`

Configure `workers/infraguard-edge/wrangler.toml`:

```toml
[vars]
INFRAGUARD_BACKEND = "https://your-infraguard-server.com"
ALLOWED_HOSTS = "cdn.example.com,assets.example.com"
BLOCKED_COUNTRIES = "RU,CN,KP"
HOST_MAP = "cdn.example.com:cdn.example.com"
```

Deploy:

```bash
cd workers/infraguard-edge
wrangler deploy
```

Worker strips Cloudflare-specific headers (CF-*) for OPSEC and injects `X-Real-IP` / `X-Forwarded-For`.

### AWS Lambda Edge Proxy

Traffic path: `Target → CloudFront → Lambda@Edge → InfraGuard → Teamserver`

Three deployment modes:
1. **Lambda Function URL** — simplest, direct HTTPS URL
2. **CloudFront + Lambda@Edge** — full CDN, 400+ edge locations
3. **API Gateway + Lambda** — RESTful gateway

```bash
cd workers/infraguard-lambda

# Deploy with SAM
sam build
sam deploy --guided

# Environment vars (set in Lambda console or template.yaml)
INFRAGUARD_BACKEND=https://infraguard.internal:443
ALLOWED_HOSTS=cdn.example.com
BLOCKED_COUNTRIES=RU,CN
```

Zero external dependencies — stdlib only. Lambda@Edge provides AWS-owned TLS certs (hard to attribute).

## Multi-Instance (Command Post)

Aggregate multiple InfraGuard proxy instances into single dashboard:

```yaml
# command-post.yaml
instances:
  - name: "proxy-us-east"
    url: "https://cdn-us.example.com:8080"
    token: "${INFRAGUARD_API_TOKEN}"
  - name: "proxy-eu-west"
    url: "https://cdn-eu.example.com:8080"
    token: "${INFRAGUARD_API_TOKEN_EU}"

bind: "0.0.0.0"
port: 9090
auth_token: "${COMMAND_POST_TOKEN}"
```

```bash
infraguard command-post -c command-post.yaml
# Docker: docker compose --profile command-post up -d command-post
```

## CLI Reference

| Command | Purpose |
|---------|---------|
| `infraguard run -c config.yaml` | Start proxy/redirector |
| `infraguard dashboard -c config.yaml [--port 8080]` | Web dashboard only |
| `infraguard tui [-c config] [--url URL --token TOKEN]` | Terminal UI |
| `infraguard command-post -c cmd-post.yaml` | Multi-instance aggregator |
| `infraguard profile parse <file> [--type cobalt_strike]` | Parse C2 profile |
| `infraguard profile convert <file> -o out.json` | Convert profile to JSON |
| `infraguard ingest <files...> [--format blocklist\|summary\|json] [-o out]` | Ingest .htaccess/robots.txt |
| `infraguard generate nginx\|caddy\|apache -c config` | Generate upstream webserver config |
| `infraguard config init [-o config.yaml]` | Interactive config generator |
| `infraguard config generate --domain D --c2-profile P --upstream U` | Quick config bundle |
| `infraguard config validate -c config.yaml` | Validate config |
| `infraguard report --db data.db [-o report.html]` | HTML engagement report |
| `infraguard test-request -c config --domain D [--path] [--ip] [--header]` | Dry-run request through pipeline |
| `infraguard deploy` | Deployment subcommands (cloud providers) |

## OPSEC Considerations

| Risk | Mitigation |
|------|-----------|
| Teamserver IP exposed | InfraGuard sits in front; teamserver binds only to internal IP or wireguard |
| JA3 fingerprint of tooling | Enable JA3 filter; use beacon over raw sessions |
| Burn via CT logs | Enable `ct_monitor: true` to alert when certs issued for your domain |
| Scanner enumeration | Enable enumeration filter + auto_block_scanners |
| Replay detonation | Enable replay filter + `replay_persist: true` |
| DNS reverse lookup | Enable DNS filter — blocks AWS/Azure/GCP IP ranges by reverse lookup |
| Cloudflare headers leaking infra | CF Worker strips CF-* headers before forwarding |
| Health endpoint discovery | Set `health_path` to a non-obvious path (e.g., `/status-8e3f`) |
| Payload reuse | One-time tokens + rate limiting on `content_routes` |
| Profile mismatch detection | Profile filter rejects requests not matching malleable profile |

## Validation Criteria

- [ ] `infraguard config validate -c config.yaml` passes with no errors
- [ ] Proxy starts and `GET /<health_path>` returns 200
- [ ] `infraguard test-request` for known-good CS/Mythic UA returns ALLOW
- [ ] `infraguard test-request` with curl UA returns BLOCK (bot filter)
- [ ] `infraguard test-request` with `Via:` header returns BLOCK (header filter)
- [ ] Beacon from teamserver reaches target through redirector
- [ ] Blocked IP receives drop action (redirect/decoy) — not teamserver 404
- [ ] Dashboard accessible on configured port with API token auth
- [ ] Discord/Slack webhook fires on first blocked request (if configured)
- [ ] Engagement report generates successfully from SQLite DB

## References

| Resource | Link |
|----------|------|
| InfraGuard source | [Whispergate/InfraGuard](https://github.com/Whispergate/InfraGuard) |
| InfraGuard docs | [infraguard.whispergate.org](https://infraguard.whispergate.org/) |
| Config examples | [InfraGuard/config/examples/](https://github.com/Whispergate/InfraGuard/tree/main/config/examples) |
| Decoy pages | [InfraGuard/pages/](https://github.com/Whispergate/InfraGuard/tree/main/pages) |
| Rules / IP blocklist | [InfraGuard/rules/](https://github.com/Whispergate/InfraGuard/tree/main/rules) |
| Edge workers | [InfraGuard/workers/](https://github.com/Whispergate/InfraGuard/tree/main/workers) |
| MITRE T1090.002 | External Proxy technique |
| MITRE T1071.001 | Application Layer Protocol: Web |
| MITRE T1566 | Phishing |
