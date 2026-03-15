# API Reference: Phishing Incident Response Agent

## Overview

Analyzes phishing emails: parses EML files, extracts URLs and attachment hashes, checks reputation via VirusTotal and urlscan.io, assesses SPF/DKIM/DMARC authentication, and generates severity-rated IR reports.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | VirusTotal and urlscan.io API calls |

## CLI Usage

```bash
python agent.py --eml suspicious_email.eml --vt-key <key> --output report.json
```

## Key Functions

### `parse_email_file(eml_path)`
Parses EML file extracting Subject, From, To, Received headers, and SPF/DKIM/DMARC authentication results.

### `extract_urls(msg)`
Extracts all URLs from email body (plain text and HTML parts) using regex.

### `extract_attachments(msg)`
Extracts attachment filenames, content types, sizes, and computes SHA-256/MD5 hashes.

### `check_url_virustotal(url, api_key)`
Checks URL reputation on VirusTotal v3 API (malicious, suspicious, harmless counts).

### `check_url_urlscan(url)`
Submits URL to urlscan.io for visual and behavioral analysis.

### `check_hash_virustotal(file_hash, api_key)`
Checks attachment hash reputation on VirusTotal for malware detection.

### `assess_phishing_severity(parsed_email, url_results, attachment_results)`
Rates phishing severity (Low/Medium/Critical) based on auth failures and malicious content.

## External APIs Used

| API | Endpoint | Auth | Purpose |
|-----|----------|------|---------|
| VirusTotal v3 | `/api/v3/urls/{id}` | API key | URL reputation |
| VirusTotal v3 | `/api/v3/files/{hash}` | API key | File hash reputation |
| urlscan.io | `/api/v1/scan/` | None | URL visual analysis |

## Email Authentication Checks

| Check | Pass | Fail | Impact |
|-------|------|------|--------|
| SPF | Sender IP authorized | Possible spoofing | Severity +1 |
| DKIM | Signature valid | Message may be tampered | Severity +1 |
| DMARC | Policy enforced | SPF+DKIM alignment failed | Severity +1 |
