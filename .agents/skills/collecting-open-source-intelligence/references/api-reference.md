# API Reference: OSINT Collection Agent

## Overview

Gathers open-source intelligence on target domains using Shodan, certificate transparency logs (crt.sh), RDAP WHOIS, SecurityTrails, and GitHub code search. For authorized assessments only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| shodan | >=1.28 | Shodan API for internet-wide device search |
| requests | >=2.28 | HTTP API calls |

## CLI Usage

```bash
python agent.py --domain example.com --shodan-key <key> --github-token <token> --output report.json
```

## Key Functions

### `search_shodan(api_key, query, max_results)`
Searches Shodan for hosts matching a query string, returning IP, ports, org, OS, SSL cert subjects.

### `shodan_host_lookup(api_key, ip_address)`
Looks up detailed information about a specific IP including open ports and known vulnerabilities.

### `query_crtsh(domain)`
Queries certificate transparency logs via crt.sh to discover subdomains from issued SSL certificates.

### `whois_lookup(domain)`
Performs WHOIS lookup using RDAP protocol, returning registration status, nameservers, and event dates.

### `query_securitytrails(api_key, domain)`
Queries SecurityTrails API for current DNS records, historical DNS data, and Alexa ranking.

### `search_github_exposure(query, github_token)`
Searches GitHub for exposed credentials, API keys, or sensitive data related to the target domain.

### `generate_osint_report(domain, subdomains, shodan_results, whois_data, github_results)`
Consolidates all gathered OSINT into a structured JSON report.

## External APIs Used

| API | Endpoint | Auth | Purpose |
|-----|----------|------|---------|
| Shodan | `api.shodan.io` | API key | Internet-wide device search |
| crt.sh | `https://crt.sh/?q=...&output=json` | None | Certificate transparency |
| RDAP | `https://rdap.org/domain/` | None | WHOIS lookup |
| SecurityTrails | `https://api.securitytrails.com/v1/` | API key | DNS history |
| GitHub | `https://api.github.com/search/code` | Token | Code search for exposures |
