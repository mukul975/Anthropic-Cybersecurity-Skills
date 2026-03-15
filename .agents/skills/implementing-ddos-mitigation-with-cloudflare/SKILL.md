---
name: implementing-ddos-mitigation-with-cloudflare
description: Configure Cloudflare DDoS protection with managed rulesets, rate limiting, WAF rules, Bot Management, and origin protection to mitigate volumetric, protocol, and application-layer attacks.
domain: cybersecurity
subdomain: network-security
tags: [ddos, cloudflare, ddos-mitigation, rate-limiting, waf, bot-management, layer-7, volumetric-attack, network-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing DDoS Mitigation with Cloudflare

## Overview

Cloudflare provides multi-layer DDoS protection across its global network of over 300 data centers with 477+ Tbps of capacity. The platform protects against L3/4 volumetric attacks (SYN floods, UDP amplification, DNS reflection), protocol attacks (Ping of Death, Smurf), and L7 application-layer attacks (HTTP floods, Slowloris, cache-busting). Cloudflare's autonomous detection systems identify and mitigate attacks within approximately 3 seconds using traffic profiling, machine learning, and adaptive rulesets. This skill covers configuring Cloudflare's DDoS protection stack including managed rulesets, WAF rules, rate limiting, Bot Management, and origin server hardening.

## Prerequisites

- Cloudflare account (Pro plan minimum for WAF, Enterprise for Advanced DDoS)
- Domain with DNS delegated to Cloudflare nameservers
- Origin server IP address(es)
- Understanding of normal traffic patterns and peak volumes
- Cloudflare API token for automation

## Core Concepts

### DDoS Attack Categories

| Layer | Attack Type | Examples | Cloudflare Protection |
|-------|------------|----------|----------------------|
| L3/4 | Volumetric | SYN flood, UDP flood, DNS amplification | Network-layer DDoS managed rules |
| L3/4 | Protocol | Ping of Death, Smurf, IP fragmentation | Advanced TCP Protection |
| L7 | Application | HTTP flood, Slowloris, cache busting | HTTP DDoS managed rules, WAF, Rate Limiting |
| DNS | DNS-specific | DNS query flood, NXDOMAIN attack | Advanced DNS Protection |

### Cloudflare Protection Stack

```
Internet Traffic
     │
     ▼
┌─────────────────────────┐
│  Cloudflare Edge (PoP)  │
│  ┌───────────────────┐  │
│  │ L3/4 DDoS Mgd Rules│  │  ← Volumetric/Protocol mitigation
│  └───────────────────┘  │
│  ┌───────────────────┐  │
│  │ IP Access Rules    │  │  ← Country/ASN/IP blocks
│  └───────────────────┘  │
│  ┌───────────────────┐  │
│  │ Bot Management     │  │  ← Bot score, JS challenge
│  └───────────────────┘  │
│  ┌───────────────────┐  │
│  │ WAF Managed Rules  │  │  ← OWASP, Cloudflare, Custom
│  └───────────────────┘  │
│  ┌───────────────────┐  │
│  │ Rate Limiting      │  │  ← Request rate enforcement
│  └───────────────────┘  │
│  ┌───────────────────┐  │
│  │ HTTP DDoS Mgd Rules│  │  ← L7 flood detection
│  └───────────────────┘  │
└─────────────────────────┘
     │
     ▼
  Origin Server
```

## Implementation Steps

### Step 1: Onboard Domain to Cloudflare

```bash
# Add domain via API
curl -X POST "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "example.com",
    "type": "full",
    "plan": {"id": "enterprise"}
  }'

# Update DNS records (proxy enabled for DDoS protection)
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "type": "A",
    "name": "example.com",
    "content": "203.0.113.50",
    "proxied": true,
    "ttl": 1
  }'
```

### Step 2: Configure DDoS Managed Rulesets

**HTTP DDoS Attack Protection override:**

```bash
# List HTTP DDoS managed ruleset
curl -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/ddos_l7/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN"

# Override HTTP DDoS sensitivity and action
curl -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/ddos_l7/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "rules": [{
      "action": "execute",
      "action_parameters": {
        "id": "4d21379b4f9f4bb088e0729962c8b3cf",
        "overrides": {
          "rules": [{
            "id": "fdfdac75430c4c47a422bdc024aab531",
            "sensitivity_level": "medium",
            "action": "block"
          }],
          "sensitivity_level": "high"
        }
      },
      "expression": "true"
    }]
  }'
```

**Network-layer DDoS Protection override:**

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/rulesets/phases/ddos_l4/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "rules": [{
      "action": "execute",
      "action_parameters": {
        "id": "3b64149bfa6e4220bbbc2bd6db7c867e",
        "overrides": {
          "sensitivity_level": "high"
        }
      },
      "expression": "true"
    }]
  }'
```

### Step 3: Configure Rate Limiting Rules

```bash
# Create rate limiting rule for login endpoint
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "rules": [
      {
        "description": "Rate limit login attempts",
        "expression": "(http.request.uri.path eq \"/api/login\")",
        "action": "block",
        "ratelimit": {
          "characteristics": ["cf.colo.id", "ip.src"],
          "period": 60,
          "requests_per_period": 10,
          "mitigation_timeout": 600
        }
      },
      {
        "description": "Rate limit API endpoints",
        "expression": "(http.request.uri.path matches \"^/api/\")",
        "action": "managed_challenge",
        "ratelimit": {
          "characteristics": ["cf.colo.id", "ip.src"],
          "period": 60,
          "requests_per_period": 100,
          "mitigation_timeout": 300
        }
      },
      {
        "description": "Global rate limit per IP",
        "expression": "true",
        "action": "managed_challenge",
        "ratelimit": {
          "characteristics": ["ip.src"],
          "period": 10,
          "requests_per_period": 50,
          "mitigation_timeout": 60
        }
      }
    ]
  }'
```

### Step 4: Configure WAF Custom Rules

```bash
# Block known attack patterns
curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "rules": [
      {
        "description": "Block requests from known bad ASNs",
        "expression": "(ip.geoip.asnum in {12345 67890})",
        "action": "block"
      },
      {
        "description": "Challenge requests without User-Agent",
        "expression": "(not http.user_agent ne \"\")",
        "action": "managed_challenge"
      },
      {
        "description": "Block high-risk countries for admin paths",
        "expression": "(http.request.uri.path contains \"/admin\" and not ip.geoip.country in {\"US\" \"CA\" \"GB\"})",
        "action": "block"
      },
      {
        "description": "Block oversized request bodies",
        "expression": "(http.request.body.size gt 10000000)",
        "action": "block"
      }
    ]
  }'
```

### Step 5: Configure Origin Protection

Ensure the origin server only accepts traffic from Cloudflare:

```bash
# Get Cloudflare IP ranges
curl https://api.cloudflare.com/client/v4/ips

# Configure origin server firewall (iptables)
# Allow only Cloudflare IPs
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    iptables -A INPUT -p tcp --dport 443 -s $ip -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -s $ip -j ACCEPT
done

# Drop all other HTTP/HTTPS traffic
iptables -A INPUT -p tcp --dport 443 -j DROP
iptables -A INPUT -p tcp --dport 80 -j DROP

# Enable Authenticated Origin Pulls (mutual TLS)
# Download Cloudflare origin CA certificate
curl -o /etc/ssl/cloudflare-origin-pull.pem \
  https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem

# Nginx configuration for authenticated origin pulls
# ssl_client_certificate /etc/ssl/cloudflare-origin-pull.pem;
# ssl_verify_client on;
```

### Step 6: Enable Under Attack Mode Automation

```python
#!/usr/bin/env python3
"""Auto-enable Cloudflare Under Attack Mode based on traffic anomalies."""

import requests
import time
import sys

CF_API_TOKEN = "your-api-token"
ZONE_ID = "your-zone-id"
HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}
BASE_URL = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}"

NORMAL_RPS_THRESHOLD = 5000  # Requests per second threshold
CHECK_INTERVAL = 30  # Seconds between checks


def get_current_security_level():
    """Get current security level setting."""
    resp = requests.get(
        f"{BASE_URL}/settings/security_level",
        headers=HEADERS
    )
    return resp.json()["result"]["value"]


def set_security_level(level: str):
    """Set security level (off, essentially_off, low, medium, high, under_attack)."""
    resp = requests.patch(
        f"{BASE_URL}/settings/security_level",
        headers=HEADERS,
        json={"value": level}
    )
    result = resp.json()
    if result["success"]:
        print(f"[+] Security level set to: {level}")
    else:
        print(f"[-] Failed to set security level: {result['errors']}")
    return result["success"]


def get_traffic_analytics():
    """Get recent traffic data from Cloudflare analytics."""
    query = """
    query {
      viewer {
        zones(filter: {zoneTag: "%s"}) {
          httpRequests1mGroups(limit: 1, orderBy: [datetime_DESC]) {
            sum {
              requests
              threats
            }
            dimensions {
              datetime
            }
          }
        }
      }
    }
    """ % ZONE_ID

    resp = requests.post(
        "https://api.cloudflare.com/client/v4/graphql",
        headers=HEADERS,
        json={"query": query}
    )
    return resp.json()


def monitor_and_respond():
    """Monitor traffic and auto-enable under attack mode."""
    current_level = get_current_security_level()
    print(f"[*] Current security level: {current_level}")
    print(f"[*] Monitoring traffic (threshold: {NORMAL_RPS_THRESHOLD} RPS)...")

    attack_mode_active = False
    consecutive_normal = 0

    while True:
        try:
            analytics = get_traffic_analytics()
            zones = analytics.get("data", {}).get("viewer", {}).get("zones", [])

            if zones and zones[0].get("httpRequests1mGroups"):
                data = zones[0]["httpRequests1mGroups"][0]["sum"]
                rps = data["requests"] / 60
                threats = data["threats"]

                print(f"[*] Current RPS: {rps:.0f}, Threats: {threats}")

                if rps > NORMAL_RPS_THRESHOLD and not attack_mode_active:
                    print(f"[!] Traffic spike detected: {rps:.0f} RPS")
                    set_security_level("under_attack")
                    attack_mode_active = True
                    consecutive_normal = 0

                elif rps <= NORMAL_RPS_THRESHOLD and attack_mode_active:
                    consecutive_normal += 1
                    if consecutive_normal >= 5:
                        print("[+] Traffic normalized, disabling under attack mode")
                        set_security_level("high")
                        attack_mode_active = False
                        consecutive_normal = 0

        except Exception as e:
            print(f"[-] Error: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    monitor_and_respond()
```

## Monitoring and Alerting

### Cloudflare Dashboard Metrics

- **Firewall Events** - View blocked requests, challenged requests, rate-limited requests
- **DDoS Analytics** - Attack size, duration, type, and mitigation status
- **Traffic Analytics** - Request volume, bandwidth, error rates by time
- **Bot Analytics** - Bot score distribution, verified bots vs automated threats

### Alert Configuration

```bash
# Create notification policy for DDoS attacks
curl -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/alerting/v3/policies" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "DDoS Attack Alert",
    "alert_type": "dos_attack_l7",
    "enabled": true,
    "mechanisms": {
      "email": [{"id": "soc@example.com"}],
      "webhooks": [{"id": "webhook-id"}]
    },
    "filters": {
      "zones": ["'$ZONE_ID'"]
    }
  }'
```

## Best Practices

- **Proxy All DNS Records** - Ensure all A/AAAA/CNAME records pointing to origin are proxied (orange cloud)
- **Hide Origin IP** - Never expose origin server IP; use Cloudflare Tunnel or restrict to Cloudflare IPs only
- **Start in Log Mode** - Test DDoS rule overrides with "Log" action before switching to "Block"
- **Layer Defense** - Combine managed rulesets, rate limiting, WAF rules, and Bot Management
- **Tune Sensitivity** - Adjust DDoS rule sensitivity based on false positive rates in your traffic
- **Cache Strategy** - Maximize cache hit ratio to reduce origin load during attacks
- **Waiting Room** - Configure Cloudflare Waiting Room for critical pages during traffic surges
- **Authenticated Origin** - Enable Authenticated Origin Pulls to prevent direct-to-origin attacks

## References

- [Cloudflare DDoS Protection Documentation](https://developers.cloudflare.com/ddos-protection/)
- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [Cloudflare Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)
- [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)
