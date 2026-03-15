# API Reference: Threat Intelligence Feed Integration Agent

## Overview

Ingests threat intelligence from TAXII 2.1 servers, Abuse.ch URLhaus, and Feodo Tracker. Normalizes all indicators to STIX 2.1 format, deduplicates, and exports as a STIX bundle.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP API calls |
| taxii2-client | >=2.3 | TAXII 2.1 server communication |
| stix2 | >=3.0 | STIX 2.1 object creation and serialization |

## CLI Usage

```bash
# Ingest from multiple sources
python agent.py --urlhaus --feodo --output ti_bundle.json

# Ingest from TAXII feed
python agent.py --taxii-url https://taxii.example.com/taxii2/ \
  --taxii-collection https://taxii.example.com/taxii2/collections/abc/ \
  --taxii-user user --taxii-pass pass
```

## Key Functions

### `ingest_taxii_feed(taxii_url, collection_url, username, password, hours_back)`
Connects to a TAXII 2.1 collection and retrieves indicators added within the specified time window.

### `ingest_urlhaus_feed()`
Fetches recent malicious URLs from the URLhaus API (`https://urlhaus-api.abuse.ch/v1/urls/recent/`).

### `ingest_feodotracker()`
Downloads the Feodo Tracker recommended C2 IP blocklist in JSON format.

### `normalize_to_stix(indicators)`
Converts raw indicators to STIX 2.1 `Indicator` objects with proper patterns for ipv4, domain, url, and sha256 types.

### `deduplicate(indicators)`
Removes duplicate indicators across feeds using SHA-256 hash of `type:value`.

### `export_stix_bundle(stix_objects, output_path)`
Serializes STIX objects into a `Bundle` and writes to a JSON file.

### `push_to_splunk_ti(splunk_url, session_key, indicators)`
Pushes indicators to the Splunk ES threat intelligence framework via REST API.

## External APIs Used

| API | Endpoint | Auth | Purpose |
|-----|----------|------|---------|
| TAXII 2.1 | Configurable | Basic auth | STIX indicator ingestion |
| URLhaus | `https://urlhaus-api.abuse.ch/v1/` | None | Malicious URL feed |
| Feodo Tracker | `https://feodotracker.abuse.ch/downloads/` | None | C2 IP blocklist |
| Splunk REST | `/services/data/threat_intel/item/ip_intel` | Session key | TI push |
