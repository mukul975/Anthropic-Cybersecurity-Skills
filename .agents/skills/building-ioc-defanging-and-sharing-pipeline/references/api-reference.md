# API Reference: IOC Defanging and Sharing Pipeline

## IOC Defanging Rules
| Type | Original | Defanged |
|------|----------|----------|
| IPv4 | `192.168.1.1` | `192[.]168[.]1[.]1` |
| Domain | `evil.com` | `evil[.]com` |
| URL | `https://evil.com/payload` | `hxxps://evil[.]com/payload` |
| Email | `attacker@evil.com` | `attacker@evil[.]com` |

## IOC Extraction Patterns
| Type | Regex |
|------|-------|
| IPv4 | `\b(?:\d{1,3}\.){3}\d{1,3}\b` |
| Domain | `\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b` |
| URL | `https?://[^\s"'<>]+` |
| MD5 | `\b[a-fA-F0-9]{32}\b` |
| SHA256 | `\b[a-fA-F0-9]{64}\b` |

## STIX 2.1 Indicator Format
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "pattern_type": "stix",
  "pattern": "[ipv4-addr:value = '1.2.3.4']",
  "valid_from": "2024-01-01T00:00:00Z",
  "labels": ["malicious-activity"]
}
```

## VirusTotal API v3
```
GET https://www.virustotal.com/api/v3/files/{hash}
x-apikey: YOUR_KEY
```

## AbuseIPDB API v2
```
GET https://api.abuseipdb.com/api/v2/check
Key: YOUR_KEY
Params: ipAddress, maxAgeInDays
```

## STIX Pattern Examples
| IOC Type | STIX Pattern |
|----------|-------------|
| IPv4 | `[ipv4-addr:value = '1.2.3.4']` |
| Domain | `[domain-name:value = 'evil.com']` |
| URL | `[url:value = 'https://evil.com']` |
| MD5 | `[file:hashes.'MD5' = 'abc123...']` |
| SHA256 | `[file:hashes.'SHA-256' = 'def456...']` |

## TAXII 2.1 Sharing
```
POST https://taxii.server/api/collections/{id}/objects/
Authorization: Basic BASE64
Content-Type: application/taxii+json;version=2.1
Body: STIX Bundle JSON
```
