---
name: reviewing-ssrf
description: >-
  Detect and exploit Server-Side Request Forgery (SSRF) vulnerabilities. Triggered when 
  an application fetches external resources (webhooks, link previews, image imports) 
  without strict protocol or IP validation, allowing internal network scanning or metadata theft.
domain: cybersecurity
subdomain: web-application-security
tags: [ssrf, cloud-security, penetration-testing, network-scanning]
mitre_attack: [T1190, T1552.005]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Server-Side Request Forgery

## When to Use

- When the application accepts a URL as input for webhooks, callbacks, avatar imports, or link preview generation.
- When the application acts as a proxy or fetches resources on behalf of the user (e.g., RSS feed readers, PDF generators, JSONP proxies).
- When a parameter value (even if not explicitly named `url`, e.g., `host`, `target`, `path`) dictates where the backend sends an outbound HTTP/TCP request.

**Do not use** to perform destructive actions against the target's internal network or cloud environment. Extracting sensitive data (like AWS credentials) should only be done to prove the vulnerability if required, and then immediately reported.

## Prerequisites

- An Out-of-Band (OOB) testing server you control (e.g., Burp Collaborator, interactsh, or a custom VPS) to receive callbacks.
- Ability to intercept and modify HTTP traffic.
- Understanding of cloud metadata IP addresses (e.g., `169.254.169.254` for AWS/GCP).

## Workflow

### Step 1: Out-of-Band (OOB) Confirmation
Before attempting internal network scanning, confirm the SSRF by making the server ping an external domain you control.
1. Provide your OOB URL (e.g., `http://your-collaborator.net`) as the payload.
2. Submit the request and monitor your OOB server logs.
3. If a request arrives, analyze the `User-Agent` and Source IP to infer the backend technology (e.g., `python-requests`, `Go-http-client`).

### Step 2: Internal Network Probing
Once external SSRF is confirmed, attempt to target internal network boundaries:
- **Localhost**: `http://127.0.0.1`, `http://localhost`, `http://0.0.0.0`
- **Cloud Metadata**: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/computeMetadata/v1/` (GCP)
- **Private IP Ranges**: `http://10.0.0.1`, `http://192.168.1.1`
- **Container Infrastructure**: `http://kubernetes.default.svc`

### Step 3: Protocol Smuggling & Alternative Schemes
Test if the backend supports protocols other than HTTP/HTTPS:
- **Local File Inclusion**: `file:///etc/passwd`
- **Gopher Protocol** (for Redis/Memcached exploitation): `gopher://127.0.0.1:6379/_...`
- **Dict Protocol** (for port scanning/banner grabbing): `dict://127.0.0.1:22`

### Step 4: Filter Bypasses
If direct requests to `127.0.0.1` are blocked, attempt to bypass the blocklist:
- **IP Obfuscation**: Decimal (`http://2130706433`), Octal (`http://0177.0.0.1`), IPv6 (`http://[::1]`).
- **DNS Rebinding**: Use a domain you control that initially resolves to a safe IP to pass the validation check, but then resolves to `127.0.0.1` when the backend actually fetches it (using tools like `rbndr.us`).
- **Open Redirects**: Provide a URL on a trusted domain that redirects (`302`) to the internal target. If the backend HTTP client follows redirects blindly, the SSRF triggers.
- **URL Parsing Inconsistencies**: `http://expected-domain.com@127.0.0.1`

### Verification and Validation Phase
1. Establish target environment baseline and identify endpoint parameters.
2. Execute realistic detection payload to evaluate vulnerability exposure:

```bash
curl -i -s -X POST "https://target.example.com/api/v1/webhook/register" \
     -H "Content-Type: application/json" \
     -d '{"callback_url": "http://169.254.169.254/latest/meta-data/"}'
```

3. Analyze HTTP response status, reflected headers, and execution timing to confirm finding.

## Key Concepts

| Term | Definition |
|------|------------|
| **SSRF** | Server-Side Request Forgery. A vulnerability where an attacker forces a backend server to make HTTP/TCP requests to an arbitrary domain of the attacker's choosing. |
| **Cloud Metadata Service** | A local REST API provided by cloud providers (AWS, Azure, GCP) accessible only from within the cloud instance (usually at `169.254.169.254`), often containing sensitive IAM tokens. |
| **Blind SSRF** | An SSRF where the response from the targeted internal service is not returned to the attacker. Detection relies entirely on time delays or OOB pingbacks. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Parameter Naming
**Context**: A parameter is named `target_url`, but placing a Collaborator payload does not trigger a pingback.
**Analysis**: The backend might simply store this URL in a database as a string and never actually execute an HTTP fetch.
**Action**: This is not an SSRF. However, trace where this URL is rendered later. It might be a Stored XSS if reflected in an `href` attribute.

### Scenario: False Negative - DNS Rebinding Missed
**Context**: `http://127.0.0.1` is blocked with a "Private IPs not allowed" error. You assume it is secure.
**Analysis**: The validation might happen asynchronously or the DNS resolution TTL is not respected by the HTTP client. 
**Action**: Always attempt a DNS rebinding attack before declaring a URL fetcher completely safe.

### Scenario: Blind SSRF
**Context**: You provide `http://127.0.0.1:22`, and the application returns a generic `500 Server Error` instead of the SSH banner.
**Analysis**: The application does not reflect the body of the response, but the difference in response time (or the specific error code) when hitting an open port vs a closed port can still be used to scan the internal network.

## Output Format

Document confirmed SSRF vulnerabilities with OOB interaction logs or internal network responses:

```json
{
  "id": "ssrf-001",
  "title": "Unauthenticated SSRF in Webhook Configuration",
  "severity": "critical",
  "cwe": "CWE-918",
  "parameter": "callback_url (JSON Body)",
  "status": "confirmed",
  "evidence": {
    "payload": "{\"callback_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
    "response_snippet": "IAMRole-EC2-Admin"
  },
  "description": "The webhook configuration endpoint blindly fetches the provided URL and reflects the response, allowing access to the AWS EC2 metadata service."
}
```
