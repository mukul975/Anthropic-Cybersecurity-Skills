# API Reference: Threat Hunting with Elastic SIEM Agent

## Overview

Performs proactive threat hunting against Elasticsearch indices using structured queries for LOLBin abuse, credential dumping, lateral movement, and persistence mechanisms mapped to MITRE ATT&CK.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| elasticsearch | >= 8.0 | Elasticsearch Python client for queries |

## Core Functions

### `get_es_client(host, api_key, verify_certs)`
Creates an authenticated Elasticsearch client.
- **Parameters**: `host` (str), `api_key` (str, optional), `verify_certs` (bool)
- **Returns**: `Elasticsearch` client instance

### `hunt_lolbins(es, index, days)`
Hunts for LOLBin abuse (certutil, mshta, regsvr32, etc.) with suspicious arguments.
- **ATT&CK**: T1105 (Ingress Tool Transfer), T1218 (Signed Binary Proxy Execution)
- **Returns**: `dict` with `hunt`, `total_hits`, `findings`

### `hunt_credential_dumping(es, index, days)`
Detects procdump targeting lsass, mimikatz execution, sekurlsa PowerShell commands.
- **ATT&CK**: T1003 (OS Credential Dumping)
- **Returns**: `dict` with hunt results

### `hunt_lateral_movement(es, index, days)`
Identifies PsExec, Invoke-Command, and SMB/WinRM network flows.
- **ATT&CK**: T1021 (Remote Services)
- **Returns**: `dict` with hunt results

### `hunt_persistence(es, index, days)`
Detects scheduled task creation and registry Run key modifications.
- **ATT&CK**: T1053 (Scheduled Task), T1547 (Boot/Logon Autostart)
- **Returns**: `dict` with hunt results

### `create_detection_rule(es, kibana_url, name, query, severity, risk_score)`
Generates a detection rule payload for Elastic Security API deployment.
- **Returns**: `dict` - rule configuration ready for POST to `/api/detection_engine/rules`

### `run_all_hunts(es, days)`
Executes all hunt queries and aggregates results.

## Elasticsearch Indices Used

| Index Pattern | Data Source |
|---------------|-------------|
| `logs-endpoint.events.process-*` | Elastic Agent process events |
| `logs-endpoint.events.*` | All endpoint event types |
| `logs-windows.sysmon_operational-*` | Sysmon via Winlogbeat |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ES_HOST` | No | Elasticsearch URL (default: https://localhost:9200) |
| `ES_API_KEY` | No | API key for authentication |

## Usage

```bash
python agent.py https://elastic.corp.local:9200
```
