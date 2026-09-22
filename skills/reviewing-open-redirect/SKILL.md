---
name: reviewing-open-redirect
description: >-
  Detect Open Redirect vulnerabilities where user-controlled parameters dictate 
  redirection targets (e.g., URL parameters, OAuth callbacks). Covers HTTP Location headers, 
  meta refreshes, and DOM-based JavaScript redirects.
domain: cybersecurity
subdomain: web-application-security
tags: [open-redirect, phishing, oauth, penetration-testing]
mitre_attack: [T1566.002, T1189, T1190]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Open Redirect Flaws

## When to Use

- When an endpoint processes URLs or paths intended for redirection (e.g., `?url=`, `?next=`, `?redirect=`, `?returnTo=`).
- When evaluating Post-Login redirects, Logout redirects, or 404/401 error handlers.
- When assessing OAuth or SSO callbacks (`redirect_uri`).
- When encountering URL shorteners, exit pages, or "Click here to continue" interstitial pages.

## Prerequisites

- An interception proxy (Burp Suite, ZAP).
- Access to an attacker-controlled domain (e.g., `evil.com`, Burp Collaborator, or a local server) to serve as a verifiable external destination.

## Workflow

### Step 1: Parameter and Sink Identification
Identify parameters controlling redirection. Observe how the application handles the redirection:
- **HTTP `Location` Header**: The server responds with a 3xx status code and a `Location: <url>` header.
- **HTML Meta Refresh**: The server responds with `<meta http-equiv="refresh" content="0;url=...">`.
- **DOM-Based (JavaScript)**: The server responds with a 200 OK, and frontend JS reads the URL parameter to execute `window.location.href = ...`.

### Step 2: Direct External URL Testing
Replace the parameter value with an absolute external URL (e.g., `https://evil.com` or `http://evil.com`).
Submit the request and observe the sink. Does the `Location` header or JS variable echo your input?

### Step 3: Whitelist Bypass Techniques
If the server rejects `https://evil.com`, attempt to bypass its validation logic:
- **Protocol Relative URLs**: `//evil.com` (Bypasses checks looking for `http://`).
- **Backslash Variations**: `\/\/evil.com` or `/\evil.com`.
- **Subdomain Prefixing**: `https://evil.com.target.com` (Bypasses weak suffix checks).
- **Subdomain Suffixing**: `https://target.com.evil.com` (Bypasses weak prefix checks).
- **URL Authentication Format**: `https://target.com@evil.com` (Browser interprets `target.com` as the username, navigating to `evil.com`).
- **Null Byte Injection**: `https://target.com%00.evil.com`
- **Data/JavaScript URIs (For DOM Sinks)**: `javascript:alert(1)` or `data:text/html,<script>location='http://evil.com'</script>`.

### Step 4: Browser Verification
**Crucial**: An Open Redirect is only confirmed if a modern web browser actually follows the redirect to the external domain.
Copy the crafted URL (e.g., `https://target.com/login?next=//evil.com`), paste it into a browser address bar, and execute it. Check if the address bar ultimately lands on `evil.com`.

### Verification and Validation Phase
1. Establish target environment baseline and identify endpoint parameters.
2. Execute realistic detection payload to evaluate vulnerability exposure:

```bash
curl -i -s -X GET "https://target.example.com/login?next=https://evil.attacker.com"
```

3. Analyze HTTP response status, reflected headers, and execution timing to confirm finding.

## Key Concepts

| Term | Definition |
|------|------------|
| **Open Redirect** | A vulnerability that allows an attacker to construct a URL within an application that causes a redirection to an arbitrary external domain. Often used to facilitate convincing phishing attacks. |
| **DOM-based Redirect** | An open redirect that occurs entirely on the client-side via JavaScript manipulating `window.location`, making it invisible to standard HTTP response analysis. |
| **OAuth Token Leakage** | A high-impact variation where an Open Redirect in an OAuth `redirect_uri` causes the OAuth Provider to send the victim's authorization code or access token directly to the attacker's domain. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - URL Encoding in Location Header
**Context**: You inject `next=https://evil.com`. The server responds with `Location: https%3A%2F%2Fevil.com`.
**Analysis**: The server safely URL-encoded the parameter before placing it in the header.
**Action**: Test it in the browser. Modern browsers will usually treat the URL-encoded string as a relative file path (looking for a file literally named `https%3A...` on the target server) rather than a protocol, neutralizing the redirect.

### Scenario: DOM-Based Blind Spot
**Context**: You inject `?redirect=https://evil.com`. The HTTP response is just 200 OK with normal HTML.
**Analysis**: Automated scanners that only look for 3xx `Location` headers will mark this as safe.
**Action**: Inspect the JavaScript. If you see `let dest = new URLSearchParams(window.location.search).get('redirect'); window.location.replace(dest);`, it is a vulnerable DOM-based redirect.

## Output Format

Document confirmed vulnerabilities with the payload and proof of browser execution:

```json
{
  "id": "redir-001",
  "title": "Open Redirect via Flawed Prefix Whitelisting",
  "severity": "medium",
  "cwe": "CWE-601",
  "endpoint": "GET /auth/logout?returnTo=",
  "status": "confirmed",
  "evidence": {
    "payload": "GET /auth/logout?returnTo=https://target.com.attacker.net",
    "execution_proof": "When the payload URL was accessed in Chrome, the browser successfully redirected to attacker.net. The server's validation logic only verified that the URL began with 'https://target.com', failing to restrict the top-level domain."
  },
  "description": "The logout endpoint is vulnerable to Open Redirect. An attacker can craft a link that appears to originate from the trusted target application but ultimately redirects the user to a malicious phishing site."
}
```
