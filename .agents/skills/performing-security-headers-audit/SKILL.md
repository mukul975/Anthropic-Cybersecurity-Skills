---
name: performing-security-headers-audit
description: Auditing HTTP security headers including CSP, HSTS, X-Frame-Options, and cookie attributes to identify missing or misconfigured browser-level protections.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, security-headers, csp, hsts, owasp, web-security, hardening]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Security Headers Audit

## When to Use

- During authorized web application security assessments as a standard configuration review
- When evaluating browser-level protections against XSS, clickjacking, and data leakage
- For compliance assessments requiring security header implementation (PCI DSS, SOC 2)
- When performing initial reconnaissance to identify easy-win security improvements
- During CI/CD pipeline security gate checks for new deployments

## Prerequisites

- **Authorization**: Written scope for the target application (header review is low-risk)
- **curl**: For fetching response headers from target endpoints
- **SecurityHeaders.com**: Online scanner for quick header assessment
- **Mozilla Observatory**: Mozilla's web security testing tool
- **Burp Suite**: For comprehensive header analysis across multiple pages
- **Browser DevTools**: For examining headers and CSP violations in real-time

## Workflow

### Step 1: Collect Security Headers from Target

Retrieve and catalog all security-related response headers.

```bash
# Fetch all response headers
curl -s -I "https://target.example.com/" | grep -iE \
  "(strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy|feature-policy|x-permitted|cross-origin|set-cookie|server|x-powered-by|cache-control)"

# Check headers across multiple pages
PAGES=("/" "/login" "/api/health" "/admin" "/account/settings" "/static/app.js")

for page in "${PAGES[@]}"; do
  echo "=== $page ==="
  curl -s -I "https://target.example.com$page" 2>/dev/null | grep -iE \
    "(strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy|set-cookie|server|x-powered)"
  echo
done

# Check both HTTP and HTTPS responses
echo "=== HTTP Response ==="
curl -s -I "http://target.example.com/" | head -20
echo "=== HTTPS Response ==="
curl -s -I "https://target.example.com/" | head -20
```

### Step 2: Assess Transport Security (HSTS)

Evaluate HTTP Strict Transport Security configuration.

```bash
# Check HSTS header
curl -s -I "https://target.example.com/" | grep -i "strict-transport-security"

# Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Verify HSTS attributes:
# max-age: Should be >= 31536000 (1 year) for preload eligibility
# includeSubDomains: Protects all subdomains
# preload: Eligible for browser HSTS preload list

# Check if HTTP redirects to HTTPS
curl -s -I "http://target.example.com/" | head -5
# Should be 301/302 redirect to https://

# Check if HSTS is on the preload list
# Visit: https://hstspreload.org/?domain=target.example.com

# Test for HTTPS-only cookies
curl -s -I "https://target.example.com/login" | grep -i "set-cookie"
# All session cookies should have Secure flag

# Check for mixed content
curl -s "https://target.example.com/" | grep -oP "http://[^\"']+" | head -20
# HTTP resources loaded on HTTPS pages create mixed content vulnerabilities
```

### Step 3: Audit Content Security Policy (CSP)

Analyze CSP headers for effectiveness and potential bypasses.

```bash
# Extract CSP header
CSP=$(curl -s -I "https://target.example.com/" | grep -i "content-security-policy" | cut -d: -f2-)
echo "$CSP"

# Check for dangerous directives:
# 'unsafe-inline' in script-src: Allows inline scripts (XSS risk)
# 'unsafe-eval' in script-src: Allows eval() (XSS risk)
# * in any directive: Allows loading from any origin
# data: in script-src: Allows data: URI scripts
# Missing default-src: No fallback policy

echo "$CSP" | tr ';' '\n' | while read directive; do
  echo "  $directive"
  if echo "$directive" | grep -q "unsafe-inline"; then
    echo "    WARNING: unsafe-inline allows inline script execution"
  fi
  if echo "$directive" | grep -q "unsafe-eval"; then
    echo "    WARNING: unsafe-eval allows eval() calls"
  fi
  if echo "$directive" | grep -q " \* "; then
    echo "    WARNING: wildcard allows loading from any origin"
  fi
done

# Check for CSP report-only (not enforcing)
curl -s -I "https://target.example.com/" | grep -i "content-security-policy-report-only"
# Report-only does NOT block violations, only logs them

# Test CSP with Google's evaluator
# https://csp-evaluator.withgoogle.com/
# Paste the CSP header for automated analysis

# Check for CSP bypass via whitelisted domains
# If CDN domains are whitelisted, check for JSONP endpoints or angular libraries
```

### Step 4: Check Frame Protection and Click Defense Headers

Verify anti-clickjacking and iframe embedding controls.

```bash
# X-Frame-Options
curl -s -I "https://target.example.com/" | grep -i "x-frame-options"
# Expected: DENY or SAMEORIGIN
# ALLOW-FROM is deprecated and not supported in modern browsers

# CSP frame-ancestors (supersedes X-Frame-Options)
curl -s -I "https://target.example.com/" | grep -i "content-security-policy" | grep -o "frame-ancestors[^;]*"
# Expected: frame-ancestors 'none' or frame-ancestors 'self'

# X-Content-Type-Options
curl -s -I "https://target.example.com/" | grep -i "x-content-type-options"
# Expected: nosniff (prevents MIME type sniffing)

# X-XSS-Protection (legacy, but still useful for older browsers)
curl -s -I "https://target.example.com/" | grep -i "x-xss-protection"
# Expected: 1; mode=block (or 0 if CSP is comprehensive)
# Note: Modern recommendation is 0 (disable) when CSP is present

# Referrer-Policy
curl -s -I "https://target.example.com/" | grep -i "referrer-policy"
# Expected: strict-origin-when-cross-origin or no-referrer
# Prevents sensitive URL data from leaking via Referer header
```

### Step 5: Audit Cookie Security Attributes

Examine session and authentication cookies for security flags.

```bash
# Fetch all Set-Cookie headers
curl -s -I -L "https://target.example.com/login" | grep -i "set-cookie"

# Check each cookie for required attributes:
# Secure: Only sent over HTTPS
# HttpOnly: Not accessible via JavaScript (prevents XSS cookie theft)
# SameSite: Controls cross-site cookie sending (Strict, Lax, None)
# Path: Restricts cookie scope
# Domain: Controls which domains receive the cookie
# Max-Age/Expires: Cookie lifetime

# Automated cookie check
curl -s -I "https://target.example.com/login" | grep -i "set-cookie" | while read line; do
  echo "Cookie: $(echo "$line" | grep -oP '[^:]+=[^;]+')"
  missing=""
  echo "$line" | grep -qi "secure" || missing="$missing Secure"
  echo "$line" | grep -qi "httponly" || missing="$missing HttpOnly"
  echo "$line" | grep -qi "samesite" || missing="$missing SameSite"
  if [ -n "$missing" ]; then
    echo "  MISSING:$missing"
  else
    echo "  All flags present"
  fi
done

# Check for __Host- and __Secure- cookie prefixes
# __Host- cookies must have Secure, Path=/, no Domain
# __Secure- cookies must have Secure flag
```

### Step 6: Check Permissions Policy and Information Disclosure

Review browser feature controls and information leakage headers.

```bash
# Permissions-Policy (formerly Feature-Policy)
curl -s -I "https://target.example.com/" | grep -i "permissions-policy"
# Controls browser features: camera, microphone, geolocation, etc.
# Expected: Restrict unused features
# Example: permissions-policy: camera=(), microphone=(), geolocation=()

# Cross-Origin headers
curl -s -I "https://target.example.com/" | grep -iE "(cross-origin-embedder|cross-origin-opener|cross-origin-resource)"
# COEP: Cross-Origin-Embedder-Policy: require-corp
# COOP: Cross-Origin-Opener-Policy: same-origin
# CORP: Cross-Origin-Resource-Policy: same-origin

# Information disclosure headers to flag
curl -s -I "https://target.example.com/" | grep -iE "(server|x-powered-by|x-aspnet|x-generator)"
# Server: Apache/2.4.52 (should be removed or generic)
# X-Powered-By: PHP/8.1.2 (should be removed)
# These headers reveal technology stack to attackers

# Cache-Control for sensitive pages
curl -s -I "https://target.example.com/account/settings" | grep -i "cache-control"
# Sensitive pages should have: Cache-Control: no-store, no-cache, must-revalidate
# Prevents browser caching of sensitive data

# Generate comprehensive report using online tools
echo "Scan with SecurityHeaders.com: https://securityheaders.com/?q=target.example.com"
echo "Scan with Mozilla Observatory: https://observatory.mozilla.org/analyze/target.example.com"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **HSTS** | Forces browsers to only use HTTPS for the domain, preventing protocol downgrade attacks |
| **CSP** | Restricts which resources (scripts, styles, images) can load on the page |
| **X-Frame-Options** | Controls whether the page can be embedded in iframes (clickjacking defense) |
| **X-Content-Type-Options** | Prevents MIME type sniffing; forces browser to respect declared Content-Type |
| **Referrer-Policy** | Controls how much referrer information is sent with cross-origin requests |
| **Permissions-Policy** | Restricts browser features (camera, microphone, geolocation) available to the page |
| **SameSite Cookie** | Controls when cookies are sent in cross-site contexts (Strict, Lax, None) |
| **HSTS Preloading** | Hardcoding HSTS policy in browser source code for first-visit protection |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **SecurityHeaders.com** | Online scanner providing letter-grade security header assessment |
| **Mozilla Observatory** | Comprehensive web security scanner with scoring and recommendations |
| **CSP Evaluator (Google)** | Analyzes Content Security Policy for weaknesses and bypasses |
| **Burp Suite Professional** | Inspecting response headers across all application pages |
| **securityheaders (CLI)** | Command-line security header scanner |
| **Hardenize** | TLS and security header monitoring service |

## Common Scenarios

### Scenario 1: Complete Header Absence
A legacy application returns no security headers at all. No HSTS, CSP, X-Frame-Options, or cookie security flags. Every page is vulnerable to clickjacking, XSS has no browser-level mitigation, and cookies are sent over HTTP.

### Scenario 2: Weak CSP with unsafe-inline
The CSP header includes `script-src 'self' 'unsafe-inline'`. While it restricts external script loading, the `unsafe-inline` directive allows any inline script to execute, rendering the CSP ineffective against XSS.

### Scenario 3: Session Cookie Without Secure Flag
The session cookie is set without the `Secure` flag. On mixed HTTP/HTTPS sites, the session token can be intercepted by a network attacker via a plain HTTP request.

### Scenario 4: Missing HSTS Enabling SSL Stripping
No HSTS header is present. An attacker on the network can perform an SSL stripping attack, downgrading the victim's HTTPS connection to HTTP and intercepting all traffic.

## Output Format

```
## Security Headers Audit Report

**Target**: target.example.com
**Grade**: D (SecurityHeaders.com)
**Assessment Date**: 2024-01-15

### Headers Assessment
| Header | Status | Current Value | Recommended |
|--------|--------|---------------|-------------|
| Strict-Transport-Security | MISSING | - | max-age=31536000; includeSubDomains; preload |
| Content-Security-Policy | WEAK | script-src 'self' 'unsafe-inline' | script-src 'self' 'nonce-{random}' |
| X-Frame-Options | MISSING | - | DENY |
| X-Content-Type-Options | PRESENT | nosniff | nosniff (OK) |
| Referrer-Policy | MISSING | - | strict-origin-when-cross-origin |
| Permissions-Policy | MISSING | - | camera=(), microphone=(), geolocation=() |
| X-XSS-Protection | MISSING | - | 0 (with strong CSP) |

### Cookie Security
| Cookie | Secure | HttpOnly | SameSite | Path |
|--------|--------|----------|----------|------|
| session | NO | YES | Not set | / |
| user_pref | NO | NO | Not set | / |
| csrf_token | YES | NO | Strict | / |

### Information Disclosure
| Header | Value | Risk |
|--------|-------|------|
| Server | Apache/2.4.52 | Technology fingerprinting |
| X-Powered-By | PHP/8.1.2 | Version-specific exploit targeting |

### Recommendation Priority
1. **Critical**: Add Secure and SameSite flags to session cookie
2. **High**: Implement HSTS with min 1-year max-age
3. **High**: Replace 'unsafe-inline' in CSP with nonce-based policy
4. **Medium**: Add X-Frame-Options: DENY
5. **Medium**: Add Referrer-Policy: strict-origin-when-cross-origin
6. **Low**: Remove Server and X-Powered-By version information
7. **Low**: Add Permissions-Policy to restrict unused browser features
```
