# API Reference: IOC Enrichment Automation

## VirusTotal API v3

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v3/ip_addresses/{ip}` | GET | IP address reputation and analysis stats |
| `/api/v3/domains/{domain}` | GET | Domain reputation, WHOIS, and DNS data |
| `/api/v3/files/{hash}` | GET | File hash analysis with 70+ AV engines |
| `/api/v3/urls` | POST | Submit URL for scanning |

Header: `x-apikey: <API_KEY>` | Rate limit: 4 req/min (free), 500/min (premium)

## AbuseIPDB API v2

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/check` | GET | Check IP abuse confidence score |
| `/api/v2/report` | POST | Report an abusive IP address |

Header: `Key: <API_KEY>` | Rate limit: 1000 req/day (free)

## Shodan API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/shodan/host/{ip}` | GET | Host info: ports, OS, vulns |
| `/shodan/host/search` | GET | Search Shodan by query |

Param: `key=<API_KEY>` | Rate limit: 1 req/sec

## GreyNoise Community API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v3/community/{ip}` | GET | IP classification (malicious/benign/unknown) |

Header: `key: <API_KEY>`

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP client for all API calls |
| `vt-py` | >=0.18 | Official VirusTotal Python client |
| `shodan` | >=1.28 | Official Shodan Python client |

## References

- VirusTotal API docs: https://docs.virustotal.com/reference/overview
- AbuseIPDB API docs: https://docs.abuseipdb.com/
- Shodan API docs: https://developer.shodan.io/api
- GreyNoise docs: https://docs.greynoise.io/
- URLScan.io API: https://urlscan.io/docs/api/
