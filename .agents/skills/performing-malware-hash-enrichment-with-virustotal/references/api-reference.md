# API Reference — Performing Malware Hash Enrichment with VirusTotal

## Libraries Used
- **requests**: HTTP client for VirusTotal API v3
- **hashlib**: Local file hash calculation (MD5, SHA1, SHA256)

## CLI Interface

```
python agent.py --api-key <key> lookup --hash <sha256>
python agent.py --api-key <key> bulk --hashes <h1> <h2> [--rate-limit 4]
python agent.py --api-key <key> behavior --hash <sha256>
python agent.py hash-file --file <path>
```

## VirusTotalClient API Calls

### `get_file_report(file_hash)`
**Endpoint:** `GET /api/v3/files/{hash}`
Returns: detection ratio, file type, tags, threat classification.

### `get_file_behavior(file_hash)`
**Endpoint:** `GET /api/v3/files/{hash}/behaviours`
Returns: sandbox results (processes, files, registry, DNS, HTTP).

## Rate Limiting
Free tier: 4 requests/minute. Agent auto-sleeps after each batch of 4.

## Dependencies
```
pip install requests
```
