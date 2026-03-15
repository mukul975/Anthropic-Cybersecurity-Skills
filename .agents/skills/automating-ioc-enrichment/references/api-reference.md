# API Reference: Automating IOC Enrichment

## VirusTotal API v3

### IP Lookup

```python
import requests
resp = requests.get(
    "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
    headers={"x-apikey": VT_KEY},
)
stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
print(stats["malicious"], "/", sum(stats.values()))
```

### File Hash Lookup

```python
resp = requests.get(
    f"https://www.virustotal.com/api/v3/files/{sha256}",
    headers={"x-apikey": VT_KEY},
)
```

### Domain Lookup

```python
resp = requests.get(
    f"https://www.virustotal.com/api/v3/domains/{domain}",
    headers={"x-apikey": VT_KEY},
)
```

## AbuseIPDB API v2

```python
resp = requests.get(
    "https://api.abuseipdb.com/api/v2/check",
    headers={"Key": ABUSE_KEY, "Accept": "application/json"},
    params={"ipAddress": "1.2.3.4", "maxAgeInDays": 90},
)
data = resp.json()["data"]
print("Confidence:", data["abuseConfidenceScore"])
print("Reports:", data["totalReports"])
```

## Shodan API

```python
import shodan
api = shodan.Shodan(SHODAN_KEY)
info = api.host("1.2.3.4")
print("Ports:", info.get("ports"))
print("Vulns:", info.get("vulns"))
```

## STIX 2.1 Export

```python
from stix2 import Indicator, Bundle
indicator = Indicator(
    pattern="[ipv4-addr:value = '1.2.3.4']",
    pattern_type="stix",
    valid_from="2025-01-01T00:00:00Z",
    confidence=85,
)
bundle = Bundle(objects=[indicator])
```

## Rate Limits

| API | Free Tier | Enterprise |
|-----|-----------|------------|
| VirusTotal | 4 req/min | 500 req/min |
| AbuseIPDB | 1000 req/day | 5000 req/day |
| Shodan | 1 req/sec | 10 req/sec |

### References

- VirusTotal API: https://docs.virustotal.com/reference/overview
- AbuseIPDB API: https://docs.abuseipdb.com/
- stix2 library: https://pypi.org/project/stix2/
- Shodan: https://shodan.readthedocs.io/
