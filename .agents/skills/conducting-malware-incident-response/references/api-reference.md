# API Reference: Malware Incident Response Agent

## Overview

Automates malware incident triage: hashes samples, queries VirusTotal and MalwareBazaar for family attribution, retrieves related IOCs from ThreatFox, isolates endpoints via CrowdStrike, and generates IR reports.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | API communication |

## CLI Usage

```bash
python agent.py --incident-id INC-001 --sample malware.exe --vt-key <key> \
  --cs-token <token> --device-id <id> --output report.json
```

## Key Functions

### `hash_file(file_path)`
Computes SHA-256 and MD5 hashes of a malware sample file.

### `query_virustotal(file_hash, api_key)`
Queries VirusTotal v3 API for detection stats, threat classification, tags, and first seen date.

### `query_malwarebazaar(file_hash)`
Queries MalwareBazaar for sample family attribution, file type, delivery method, and tags.

### `query_threatfox_iocs(malware_family)`
Retrieves IOCs associated with a malware family from ThreatFox (C2 IPs, domains, URLs).

### `isolate_endpoint_crowdstrike(api_base, token, device_id)`
Isolates an infected endpoint using CrowdStrike Falcon network containment API.

### `search_enterprise_iocs(splunk_url, session_key, iocs)`
Searches Splunk for enterprise-wide IOC matches from the malware family.

## External APIs Used

| API | Endpoint | Auth | Purpose |
|-----|----------|------|---------|
| VirusTotal v3 | `/api/v3/files/{hash}` | API key | File reputation |
| MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | None | Sample metadata |
| ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` | None | Family IOCs |
| CrowdStrike | `/devices/entities/devices-actions/v2` | Bearer token | Endpoint isolation |
