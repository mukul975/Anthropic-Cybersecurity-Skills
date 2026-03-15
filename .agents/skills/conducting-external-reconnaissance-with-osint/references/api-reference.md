# API Reference: External Reconnaissance OSINT Agent

## Overview

Maps an organization's external attack surface using passive OSINT: certificate transparency, DNS records, Shodan, email security checks, web technology fingerprinting, and GitHub leak detection. For authorized assessments only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| shodan | >=1.28 | Shodan API for host discovery |
| requests | >=2.28 | HTTP API calls |

## CLI Usage

```bash
python agent.py --domain example.com --org "Example Corp" --shodan-key <key> \
  --github-token <token> --output recon.json
```

## Key Functions

### `enumerate_subdomains_crtsh(domain)`
Discovers subdomains from certificate transparency logs via crt.sh JSON API.

### `enumerate_dns_records(domain)`
Queries A, AAAA, MX, NS, TXT, CNAME, SOA records using Google DNS-over-HTTPS API.

### `shodan_org_search(api_key, org_name, max_results)`
Searches Shodan for hosts belonging to a named organization.

### `check_email_security(domain)`
Checks for SPF and DMARC DNS records to assess email security posture.

### `check_web_technologies(domain)`
Identifies web server technologies from HTTP response headers (Server, X-Powered-By).

### `search_github_leaks(domain, github_token)`
Searches GitHub code for leaked passwords, API keys, and secrets related to the target.

### `generate_recon_report(...)`
Consolidates all OSINT findings into a structured JSON report.

## External APIs Used

| API | Endpoint | Auth | Purpose |
|-----|----------|------|---------|
| crt.sh | `https://crt.sh/?q=...&output=json` | None | Certificate transparency |
| Google DNS | `https://dns.google/resolve` | None | DNS record lookup |
| Shodan | `api.shodan.io` | API key | Host/service discovery |
| GitHub | `https://api.github.com/search/code` | Token | Code leak search |
