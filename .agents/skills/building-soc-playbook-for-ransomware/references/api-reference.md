# API Reference: Ransomware Playbook Automation Agent

## Overview

Automates ransomware incident response workflow: sample identification, host isolation via CrowdStrike, IOC extraction via MalwareBazaar, and enterprise-wide IOC scanning via Splunk.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP API communication |

## CLI Usage

```bash
python agent.py --incident-id IR-2024-0500 --sample encrypted_file.locked \
  --device-id <device_id> --cs-token <token> \
  --splunk-url https://splunk:8089 --splunk-key <key>
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--incident-id` | Yes | Incident ticket identifier |
| `--sample` | No | Path to encrypted file sample for identification |
| `--device-id` | No | CrowdStrike device ID to isolate |
| `--cs-token` | No | CrowdStrike API bearer token |
| `--splunk-url` | No | Splunk management URL |
| `--splunk-key` | No | Splunk session key |
| `--output` | No | Output report file (default: `ransomware_ir_report.json`) |

## Key Functions

### `check_id_ransomware(sample_path)`
Uploads encrypted file sample to ID Ransomware for variant identification.

### `query_nomoreransom(ransomware_family)`
Checks the No More Ransom Project for available free decryptors.

### `query_malwarebazaar_hash(file_hash)`
Queries Abuse.ch MalwareBazaar API for sample metadata and family attribution.

### `isolate_host_crowdstrike(api_base, token, device_id)`
Isolates a host using the CrowdStrike Falcon `contain` action API.

### `search_iocs_splunk(splunk_url, session_key, ioc_list)`
Searches Splunk Sysmon data for enterprise-wide IOC matches.

### `collect_iocs_from_sample(sample_path)`
Computes SHA-256/MD5 hashes of a sample and enriches via MalwareBazaar.

## External APIs Used

| API | Endpoint | Purpose |
|-----|----------|---------|
| MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | Hash lookup and family ID |
| CrowdStrike Falcon | `/devices/entities/devices-actions/v2` | Host isolation |
| ID Ransomware | `https://id-ransomware.malwarehunterteam.com/` | Variant identification |
| Splunk REST | `/services/search/jobs` | Enterprise IOC search |
