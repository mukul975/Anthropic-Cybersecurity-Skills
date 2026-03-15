# API Reference — Performing IP Reputation Analysis with Shodan

## Libraries Used
- **shodan**: Shodan API client for IP host lookup, port scanning, vulnerability data
- **requests**: HTTP client for AbuseIPDB API reputation checks

## CLI Interface

```
python agent.py --shodan-key <key> [--abuseipdb-key <key>] lookup --ip <ip>
python agent.py --shodan-key <key> [--abuseipdb-key <key>] bulk --ips <ip1> <ip2>
```

## Core Functions

### `shodan_host_lookup(api_key, ip)` — Shodan host details
- `shodan.Shodan(api_key)` / `api.host(ip)`
- Returns: org, ASN, ISP, country, open ports, vulns, services

### `abuseipdb_check(api_key, ip, max_age_days)` — AbuseIPDB reputation
- `GET https://api.abuseipdb.com/api/v2/check`
- Returns: abuse_confidence (0-100), total_reports, is_tor

### `bulk_reputation(shodan_key, ips, abuseipdb_key)` — Multi-IP analysis with risk scoring

## Risk Classification
| Risk | Criteria |
|------|---------|
| Critical | Abuse score >= 80 or 3+ known vulns |
| High | Abuse score >= 50 or 1+ known vulns |
| Medium | Abuse score >= 20 |
| Low | Below thresholds |

## Dependencies
```
pip install shodan requests
```
