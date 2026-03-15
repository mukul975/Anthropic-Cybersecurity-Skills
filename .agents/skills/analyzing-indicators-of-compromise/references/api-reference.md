# API Reference: IOC Enrichment Tools

## VirusTotal API v3

### File Hash Lookup
```bash
curl -H "x-apikey: $VT_KEY" \
  "https://www.virustotal.com/api/v3/files/<sha256>"
```

### Domain Lookup
```bash
curl -H "x-apikey: $VT_KEY" \
  "https://www.virustotal.com/api/v3/domains/<domain>"
```

### IP Lookup
```bash
curl -H "x-apikey: $VT_KEY" \
  "https://www.virustotal.com/api/v3/ip_addresses/<ip>"
```

### Key Response Fields
| Field | Description |
|-------|-------------|
| `last_analysis_stats.malicious` | Number of AV engines detecting as malicious |
| `last_analysis_stats.undetected` | AV engines finding clean |
| `reputation` | Community reputation score |
| `popular_threat_classification` | Threat label consensus |

### Python (vt-py)
```python
import vt
client = vt.Client("API_KEY")
file_obj = client.get_object(f"/files/{sha256}")
stats = file_obj.last_analysis_stats
client.close()
```

## AbuseIPDB API v2

### Check IP
```bash
curl -G "https://api.abuseipdb.com/api/v2/check" \
  -H "Key: $ABUSE_KEY" -H "Accept: application/json" \
  -d "ipAddress=1.2.3.4" -d "maxAgeInDays=90"
```

### Response Fields
| Field | Description |
|-------|-------------|
| `abuseConfidenceScore` | 0-100 abuse confidence |
| `totalReports` | Report count in timeframe |
| `countryCode` | Source country |
| `isp` | Internet service provider |
| `isTor` | Tor exit node flag |

## MalwareBazaar API (abuse.ch)

### Hash Lookup
```bash
curl -X POST "https://mb-api.abuse.ch/api/v1/" \
  -d "query=get_info" -d "hash=<sha256>"
```

### Response Fields
| Field | Description |
|-------|-------------|
| `signature` | Malware family name |
| `tags` | Associated tags |
| `file_type` | File type identification |
| `first_seen` | First submission date |
| `reporter` | Submitting analyst |

## URLScan.io API

### Submit URL for Scan
```bash
curl -X POST "https://urlscan.io/api/v1/scan/" \
  -H "API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious.com", "visibility": "private"}'
```

### Retrieve Results
```bash
curl "https://urlscan.io/api/v1/result/<uuid>/"
```

## Shodan API

### IP Lookup
```bash
curl "https://api.shodan.io/shodan/host/<ip>?key=$SHODAN_KEY"
```

### Response Fields
| Field | Description |
|-------|-------------|
| `ports` | Open ports list |
| `os` | Operating system |
| `org` | Organization |
| `asn` | Autonomous system number |
| `hostnames` | Associated hostnames |

## IOC Confidence Scoring Framework

| Score | Disposition | Criteria |
|-------|-------------|----------|
| >= 70 | BLOCK | 15+ VT detections, AbuseIPDB >= 70%, or MalwareBazaar match |
| 40-69 | MONITOR | 5-14 VT detections, moderate abuse score |
| < 40 | INVESTIGATE | Low detection, no campaign attribution |

## Defanging Convention

| Original | Defanged |
|----------|----------|
| `http://` | `hxxp://` |
| `https://` | `hxxps://` |
| `.com` | `[.]com` |
| `evil.com` | `evil[.]com` |
