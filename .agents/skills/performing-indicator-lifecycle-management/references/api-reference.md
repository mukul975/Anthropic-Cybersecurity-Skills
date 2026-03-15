# API Reference — Performing Indicator Lifecycle Management

## Libraries Used
- **csv**: Parse IOC feed CSV files
- **re**: Pattern matching for IOC extraction (IP, domain, hash, URL, email, CVE)
- **pathlib**: Read text reports for IOC extraction

## CLI Interface
```
python agent.py extract --file threat_report.txt
python agent.py ingest --csv ioc_feed.csv
python agent.py expire --csv ioc_db.csv [--ttl 90]
python agent.py dedup --csv ioc_feed.csv
python agent.py report --csv ioc_db.csv [--ttl 90]
```

## Core Functions

### `extract_iocs(text_file)` — Extract IOCs from unstructured text
Regex patterns for: IPv4, domain, MD5, SHA1, SHA256, URL, email, CVE.

### `ingest_ioc_feed(csv_file)` — Normalize IOC feed data
Auto-detects IOC type if not specified. Normalizes column names across feed formats.

### `check_expiration(ioc_db_file, ttl_days)` — Identify expired indicators
Compares first_seen date against TTL threshold (default 90 days).

### `deduplicate_iocs(csv_file)` — Merge duplicate IOCs
Groups by indicator value, tracks source attribution and occurrence count.

### `generate_lifecycle_report(csv_file, ttl_days)` — Full lifecycle status
Combines ingestion, deduplication, and expiration into single report.

## IOC Pattern Types
| Type | Example |
|------|---------|
| ipv4 | 192.168.1.1 |
| domain | evil.example.com |
| md5 | d41d8cd98f00b204e9800998ecf8427e |
| sha256 | e3b0c44298fc1c149afbf4c8996fb924... |
| url | https://malware.example.com/payload |
| cve | CVE-2024-12345 |

## Dependencies
No external packages — Python standard library only.
