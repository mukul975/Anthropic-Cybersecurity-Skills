# API Reference: IOC Collection Agent

## Overview

Extracts indicators of compromise from text/files using regex patterns, enriches them via VirusTotal and MalwareBazaar APIs, assigns confidence scores, and exports as a STIX 2.1 bundle.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | API enrichment calls |
| stix2 | >=3.0 | STIX 2.1 bundle creation |

## CLI Usage

```bash
python agent.py --input-file incident_report.txt --vt-key <key> --output iocs.json
python agent.py --input-text "C2 at 185.220.101.42 hash a1b2c3..." --output iocs.json
```

## Key Functions

### `extract_iocs_from_text(text)`
Extracts IPv4 addresses, domains, SHA-256/MD5 hashes, and URLs using regex patterns.

### `extract_iocs_from_file(file_path)`
Reads a file and delegates to `extract_iocs_from_text`.

### `enrich_ip_virustotal(ip_address, api_key)`
Queries VirusTotal v3 API for IP reputation (malicious count, ASN, country).

### `enrich_hash_malwarebazaar(file_hash)`
Queries MalwareBazaar for file hash metadata (family, type, tags).

### `enrich_domain_abuseipdb(domain, api_key)`
Checks domain reputation via AbuseIPDB API (abuse confidence, report count).

### `score_ioc(ioc_type, enrichment_data)`
Assigns confidence score (0-100) based on enrichment results and detection counts.

### `export_stix_bundle(iocs_with_scores, output_path)`
Creates STIX 2.1 Indicator objects and exports as a Bundle JSON file.

## External APIs Used

| API | Endpoint | Auth | Purpose |
|-----|----------|------|---------|
| VirusTotal v3 | `/api/v3/ip_addresses/{ip}` | API key header | IP reputation |
| MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | None | Hash lookup |
| AbuseIPDB | `/api/v2/check` | API key header | Domain/IP reputation |

## IOC Types Supported

| Type | Regex Pattern | STIX Pattern |
|------|---------------|-------------|
| IPv4 | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | `[ipv4-addr:value = '...']` |
| Domain | `\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b` | `[domain-name:value = '...']` |
| SHA-256 | `\b[a-fA-F0-9]{64}\b` | `[file:hashes.'SHA-256' = '...']` |
| MD5 | `\b[a-fA-F0-9]{32}\b` | `[file:hashes.MD5 = '...']` |
| URL | `https?://[^\s"'<>]+` | `[url:value = '...']` |
