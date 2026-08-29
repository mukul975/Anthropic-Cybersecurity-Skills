---
name: building-c2-redirector-infrastructure
description: Build dumb-pipe and traffic-filtering C2 redirectors with nginx (proxy_pass) and Apache (mod_rewrite), deriving filter rules from a Malleable C2 profile, layering Let's Encrypt TLS, and applying OPSEC controls like domain fronting and UA/geo filtering. Use when standing up red-team C2 that must survive blue-team triage or ensuring only profile-matching implant traffic reaches the hidden team server. Do not use for standing up a full Sliver C2 team server and generating implants - use building-c2-infrastructure-with-sliver-framework.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- c2-infrastructure
- redirector
- nginx
- apache-mod-rewrite
- malleable-c2
- opsec
- traffic-filtering
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1090.002
---
# Building C2 Redirector Infrastructure

> **Authorized Use Only:** This skill is for authorized red-team engagements, adversary-emulation exercises, and defensive research only. Command-and-control infrastructure is dual-use; deploying redirectors to control malware on systems you are not explicitly authorized to test is illegal. Operate only inside an agreed scope with a signed rules-of-engagement document, and decommission infrastructure when the engagement ends.

## Overview

A C2 redirector is an intermediary host that sits between victim implants and the real team server. Beacons connect to the redirector's public domain/IP; the redirector inspects each request and either proxies legitimate C2 traffic back to the hidden team server or diverts everything else (scanners, blue-team analysts, sandboxes) to a benign decoy site. This protects the team server from discovery, takedown, and attribution, and lets operators rotate the public edge without rebuilding the backend. The technique maps to MITRE ATT&CK **T1090.002 (Proxy: External Proxy)** — adversaries route C2 through an intermediary node to obscure the true origin.

Redirectors come in two flavors. **Dumb pipes** (socat, iptables NAT) blindly forward a port and provide separation but no filtering. **Smart/filtering redirectors** (nginx `proxy_pass`, Apache `mod_rewrite` with `[P]`, or purpose-built tools like RedWarden) parse HTTP requests and only forward traffic that matches the implant's Malleable C2 profile — correct URI, User-Agent, headers — while sending everything else a `302` to a real website. The filtering logic is derived directly from the C2 framework's traffic profile, so the two must stay in lock-step. Tools such as `cs2modrewrite` automate generating Apache/nginx rules from a Cobalt Strike Malleable C2 profile.

This skill covers building both dumb and filtering redirectors with nginx and Apache, deriving filter rules from a malleable profile, layering TLS with Let's Encrypt, and applying OPSEC controls (categorized domains, domain fronting/CDN fronting, header validation, geo/UA filtering) for resilient, low-attribution infrastructure.

## When to Use

- Standing up red-team C2 that must survive blue-team triage and domain takedown requests.
- Separating a hidden team server from any internet-facing host during an engagement.
- Filtering implant traffic so only profile-matching requests reach the backend, diverting scanners.
- Adding TLS termination, domain categorization, and CDN/domain fronting to an HTTP(S) listener.
- Teaching defenders how external-proxy C2 (T1090.002) is constructed so they can detect it.

## Prerequisites

- One or more disposable cloud VPS instances (the redirector edge) and a separate, firewalled team-server host.
- A registered domain with controllable DNS, ideally aged/categorized.
- Root on the redirector host. Install the web server and TLS tooling:
  ```bash
  # Debian/Ubuntu redirector
  sudo apt update
  sudo apt install -y nginx apache2 socat certbot python3-certbot-nginx git
  # Enable Apache proxy modules if using mod_rewrite redirector
  sudo a2enmod rewrite proxy proxy_http ssl headers
  ```
- The C2 framework's Malleable C2 profile (Cobalt Strike `.profile`, Sliver/Havoc HTTP profile) defining URIs, User-Agent, and headers.
- `cs2modrewrite` to auto-generate rules from a Cobalt Strike profile:
  ```bash
  git clone https://github.com/threatexpress/cs2modrewrite
  ```
- Firewall the team server so it only accepts the redirector's source IP on the C2 port.

## Objectives

- Deploy a dumb-pipe redirector (socat/iptables) for fast port separation.
- Deploy a filtering nginx reverse-proxy redirector keyed to a malleable profile.
- Deploy an Apache `mod_rewrite` redirector with `[P]` proxying and `302` decoy fallback.
- Auto-generate redirector rules from a Cobalt Strike profile with `cs2modrewrite`.
- Terminate TLS with Let's Encrypt and harden the public edge.
- Apply OPSEC: header/UA validation, geo filtering, decoy diversion, and infra rotation.

## MITRE ATT&CK Mapping

| Technique ID | Official Name | Relevance |
|--------------|---------------|-----------|
| T1090.002 | Proxy: External Proxy | The redirector is an external intermediary that proxies C2 to hide the team server |
| T1090.004 | Proxy: Domain Fronting | CDN fronting routes beacon traffic through a trusted high-reputation domain |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 is tunneled over HTTP/HTTPS shaped by the malleable profile |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | TLS termination at the redirector encrypts the beacon channel |
| T1583.006 | Acquire Infrastructure: Web Services | Disposable VPS/CDN edges are acquired for resilient C2 |

## Workflow

### 1. Lab and firewall the team server
Place the team server on a private host. Restrict its C2 port to the redirector's IP only.
```bash
# On the team server: only the redirector (203.0.113.10) may reach 443/tcp
sudo ufw default deny incoming
sudo ufw allow from 203.0.113.10 to any port 443 proto tcp
sudo ufw allow OpenSSH
sudo ufw enable
```

### 2. Dumb-pipe redirector (socat / iptables)
For quick separation with no filtering, forward the C2 port to the team server.
```bash
# socat foreground forward of 443 -> team server
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:10.0.0.2:443

# Or iptables DNAT (persistent)
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.0.0.2:443
iptables -t nat -A POSTROUTING -p tcp -d 10.0.0.2 --dport 443 -j MASQUERADE
```

### 3. Filtering nginx reverse-proxy redirector
Only proxy requests whose URI matches the malleable profile; send everything else a `302` to a decoy. Replace the location regex and User-Agent with values from your profile.
```nginx
# /etc/nginx/sites-available/redirector.conf
server {
    listen 443 ssl;
    server_name cdn.example.com;

    ssl_certificate     /etc/letsencrypt/live/cdn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example.com/privkey.pem;

    # Proxy ONLY profile-matching C2 URIs to the hidden team server
    location ~ ^/(api/v2/jobs|cm/[a-z0-9]+|push) {
        # Require the implant's exact User-Agent
        if ($http_user_agent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") {
            return 302 https://www.legitimate-decoy.com/;
        }
        proxy_pass https://10.0.0.2;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Everything else -> benign decoy
    location / {
        return 302 https://www.legitimate-decoy.com/;
    }
}
```
```bash
sudo ln -s /etc/nginx/sites-available/redirector.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 4. Apache mod_rewrite redirector
Apache's `[P]` flag proxies matching requests to the team server; non-matches get a `302` redirect. This is the format `cs2modrewrite` produces.
```apache
# /etc/apache2/sites-available/redirector.conf  (inside <VirtualHost *:443>)
RewriteEngine On
SSLProxyEngine On
# Require the implant User-Agent
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" [NC]
# Match valid C2 URIs (GET/POST/stager) from the malleable profile
RewriteCond %{REQUEST_URI} ^/(api/v2/jobs|cm/[a-z0-9]+|push)/?$
# Proxy to the hidden team server, preserving the URI
RewriteRule ^.*$ https://10.0.0.2%{REQUEST_URI} [P,L]
# Everything else -> decoy site
RewriteRule ^.*$ https://www.legitimate-decoy.com/ [R=302,L]
```
```bash
sudo a2ensite redirector && sudo apache2ctl configtest && sudo systemctl reload apache2
```

### 5. Generate rules from a malleable profile
Let `cs2modrewrite` build the Apache or nginx rules directly from your Cobalt Strike profile so the filter exactly matches beacon traffic.
```bash
cd cs2modrewrite
# Apache mod_rewrite rules
python3 cs2modrewrite.py -i havex.profile -c https://10.0.0.2 \
  -r https://www.legitimate-decoy.com -o /etc/apache2/redirect.rules
# nginx config
python3 cs2nginx.py -i havex.profile -c https://10.0.0.2 \
  -r https://www.legitimate-decoy.com -H cdn.example.com > /etc/nginx/sites-available/c2.conf
```

### 6. Terminate TLS with Let's Encrypt
Issue a valid certificate so beacon HTTPS does not throw TLS warnings and the edge looks legitimate.
```bash
sudo certbot --nginx -d cdn.example.com --agree-tos -m ops@example.com --redirect
# Verify auto-renewal
sudo certbot renew --dry-run
```

### 7. Apply OPSEC controls
Layer defenses against blue-team analysis: validate headers, geofence to the target country, divert sandboxes, and rotate edges. Consider CDN/domain fronting (T1090.004) where supported.
```bash
# Example: drop non-target geographies at the firewall with ipset/GeoIP,
# require a custom auth header in the profile, and rotate the redirector
# domain/IP on a schedule. Check the redirector only forwards matched traffic:
curl -k https://cdn.example.com/                       # expect 302 to decoy
curl -k -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  https://cdn.example.com/api/v2/jobs                  # expect proxied response
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| nginx | Filtering reverse-proxy redirector | https://nginx.org/ |
| Apache mod_rewrite | `[P]` proxy + `302` decoy redirector | https://httpd.apache.org/docs/current/mod/mod_rewrite.html |
| cs2modrewrite | Generate Apache/nginx rules from CS profile | https://github.com/threatexpress/cs2modrewrite |
| RedWarden | Malleable-aware filtering C2 reverse proxy | https://github.com/mgeeky/RedWarden |
| redi | Automated nginx + Let's Encrypt CS redirector | https://github.com/taherio/redi |
| socat | Dumb-pipe TCP forwarder | http://www.dest-unreach.org/socat/ |
| Let's Encrypt / certbot | Free TLS certificates | https://certbot.eff.org/ |
| ired.team | Red-team infrastructure reference | https://www.ired.team/offensive-security/red-team-infrastructure |

## Validation Criteria

- [ ] Team server firewalled to accept only the redirector source IP on the C2 port.
- [ ] Redirector deployed (dumb pipe and/or filtering reverse proxy).
- [ ] Filter rules derived from the actual malleable C2 profile (URI + User-Agent + headers).
- [ ] Non-matching requests return a `302` to a benign decoy site (verified with curl).
- [ ] Matching beacon requests are proxied to the hidden team server (verified with curl).
- [ ] Valid TLS certificate issued and auto-renewal confirmed.
- [ ] OPSEC controls applied (UA/header validation, geofencing, decoy diversion).
- [ ] Domain categorization / CDN fronting considered where applicable.
- [ ] Infrastructure rotation and decommissioning plan documented.
- [ ] All activity confined to the authorized engagement scope.
