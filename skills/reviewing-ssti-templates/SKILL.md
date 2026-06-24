---
name: reviewing-ssti-templates
description: >-
  Detect Server-Side Template Injection (SSTI) vulnerabilities. Identifies instances where 
  user input is unsafely embedded into template engines (Jinja2, Twig, Freemarker, Velocity) 
  leading to mathematical evaluation, object enumeration, or Remote Code Execution (RCE).
domain: cybersecurity
subdomain: web-application-security
tags: [ssti, template-injection, rce, penetration-testing]
mitre_attack: [T1190]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Analyzing Server-Side Template Injection (SSTI)

## When to Use

- When user input is reflected in the HTTP response, particularly within customized content (e.g., welcome messages, customizable email templates, invoice generation).
- When a 404/Error page reflects the requested URL path.
- When you observe template syntax (`{{ }}`, `${ }`, `<% %>`) being stripped from your input, indicating the presence of a template engine processing the payload.

## Prerequisites

- An interception proxy (Burp Suite, ZAP).
- Knowledge of common template engine syntax (Jinja2, Twig, Smarty, Freemarker, Velocity).
- **Critical Rule**: Limit initial testing to harmless mathematical evaluations (`{{7*7}}`). Do not attempt OS command execution (`id`, `whoami`) until the engine is confirmed and authorized.

## Workflow

1. Initialize and execute the testing sequence.

```bash
# Verification block
echo test
```




### Step 1: Baseline and Injection Sinks
Identify parameters, headers, or URL paths that are reflected in the response. Observe the reflection behavior to ensure the input is not simply URL-encoded or HTML-escaped before reaching the template engine.

### Step 2: Multi-Engine Expression Probing
Inject basic mathematical expressions designed to trigger evaluation across different engines.
- **Jinja2 / Twig / Pebble / Handlebars**: `{{7*7}}`
- **Smarty**: `{7*7}`
- **Freemarker / Thymeleaf**: `${7*7}`
- **Velocity**: `#set($x=7*7)$x`
- **ERB / EJS**: `<%=7*7%>`
- **Thymeleaf (Inline)**: `[[${7*7}]]`

**Crucial Check**: If `{{7*7}}` results in `49`, also test `{{8*8}}` to ensure the server isn't just hardcoding the string "49" for a specific payload.

### Step 3: Engine Fingerprinting
If mathematical evaluation succeeds, determine the specific template engine by observing behavioral differences:
- **String Multiplication**: Inject `{{7*'7'}}`. 
  - If the output is `7777777`, the backend is using Python (Jinja2 / Mako).
  - If the output is `49`, the backend is performing numeric coercion (Twig).
- **Error Messages**: Purposefully inject invalid syntax like `${{"}` to trigger an error. Look for stack traces mentioning `jinja2.exceptions`, `TwigError`, `freemarker.core`, or `velocity.runtime`.

### Step 4: Assessing the Impact (Sandbox vs. RCE)
Once the engine is identified, probe the execution context:
1. **Object Enumeration**: Try to dump configuration objects (e.g., `{{config}}` in Jinja2 or `{{_self.env}}` in Twig).
2. **Sandbox Detection**: If `{{7*7}}` evaluates to `49`, but `{{config}}` returns empty or throws a security exception, the engine is likely sandboxed (e.g., Jinja2 `SandboxedEnvironment`). A sandboxed SSTI is still a confirmed vulnerability, but achieving RCE requires sandbox escape techniques (like traversing Python's `__mro__` subclass tree).

## Key Concepts

| Term | Definition |
|------|------------|
| **SSTI (Server-Side Template Injection)** | A vulnerability occurring when user input is concatenated directly into a template string rather than being passed in as contextual data, allowing the attacker to execute arbitrary template directives. |
| **Sandbox Escape** | Techniques used to bypass restrictions placed on template engines, usually by navigating the object hierarchy to find unrestricted classes (like Python's `os.popen` or Java's `java.lang.Runtime`). |
| **XSS vs. SSTI** | XSS executes in the user's browser (Client-Side). SSTI executes on the backend server. A payload like `{{7*7}}` evaluates to `49` on the server before the browser ever sees it. |


## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Client-Side Template Injection (CSTI)
**Context**: You inject `{{7*7}}` into a username field. You view the page, and it renders as `49`.
**Analysis**: You check the raw HTTP response in Burp Suite, and it says `{{7*7}}`. It only becomes `49` after the browser renders the page.
**Action**: This is Client-Side Template Injection (e.g., AngularJS, Vue.js), which leads to XSS, not server-side RCE. Validate SSTI by checking the raw HTTP response from the server.

### Scenario: Second-Order SSTI
**Context**: You inject `{{7*7}}` into a "Nickname" field during registration. The profile page safely displays `{{7*7}}`.
**Analysis**: The user-facing application passes the nickname as data. However, the Admin dashboard uses a vulnerable reporting script that concatenates nicknames into an email template.
**Action**: The SSTI triggers when the Admin generates the report, making it a Second-Order vulnerability. Test inputs that might be parsed by secondary backend systems.

## Output Format

Document confirmed vulnerabilities with proof of evaluation or object enumeration:

```json
{
  "id": "ssti-001",
  "title": "Jinja2 SSTI in User Profile Signature",
  "severity": "critical",
  "cwe": "CWE-1336",
  "endpoint": "POST /api/v1/profile/update",
  "status": "confirmed",
  "evidence": {
    "payload": "{\\"signature\\": \\"Hello {{7*'7'}}\\"}",
    "execution_proof": "The server responded with the updated profile showing the signature as 'Hello 7777777'. Further probing with {{config.items()}} successfully dumped the Flask application's secret keys and database connection strings."
  },
  "description": "The application is vulnerable to Server-Side Template Injection. User input supplied to the 'signature' field is concatenated directly into a Jinja2 template string prior to rendering. This allows attackers to evaluate arbitrary Python expressions and exfiltrate sensitive environment variables."
}
```
