# API Reference: Vulnerability Scanning with Nessus Agent

## Overview

Manages Tenable Nessus vulnerability scans via the REST API: scan creation, launch, monitoring, result analysis, and CSV/PDF export.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >= 2.28 | HTTP client for Nessus REST API |
| urllib3 | >= 1.26 | TLS warning suppression |

## NessusAPI Class

### Constructor

```python
NessusAPI(url="https://localhost:8834", access_key=None, secret_key=None)
```

Authentication via `X-ApiKeys` header with access/secret key pair.

### Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `get_server_status()` | Check Nessus server readiness | `dict` |
| `list_scans()` | List all scans with id, name, status | `list[dict]` |
| `get_scan_details(scan_id)` | Full scan results with severity counts and top vulns | `dict` |
| `create_scan(name, targets, policy_id, template)` | Create new scan configuration | `dict` |
| `launch_scan(scan_id)` | Start a configured scan | `dict` |
| `get_scan_status(scan_id)` | Poll scan status | `str` |
| `wait_for_scan(scan_id, poll_interval, timeout)` | Block until scan completes | `bool` |
| `export_scan(scan_id, fmt)` | Export results as csv, html, or pdf | `bytes` |
| `check_auth_status(scan_id)` | Verify authenticated scanning via plugin 19506 | `list[dict]` |

## Nessus REST API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/server/status` | GET | Server health check |
| `/scans` | GET | List all scans |
| `/scans` | POST | Create new scan |
| `/scans/{id}` | GET | Scan details and results |
| `/scans/{id}/launch` | POST | Launch scan |
| `/scans/{id}/export` | POST | Initiate report export |
| `/scans/{id}/export/{file_id}/download` | GET | Download exported report |
| `/editor/scan/templates` | GET | Available scan templates |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NESSUS_URL` | No | Nessus server URL (default: https://localhost:8834) |
| `NESSUS_ACCESS_KEY` | Yes | API access key |
| `NESSUS_SECRET_KEY` | Yes | API secret key |

## Severity Mapping

| Value | Label | CVSS Range |
|-------|-------|------------|
| 4 | Critical | 9.0-10.0 |
| 3 | High | 7.0-8.9 |
| 2 | Medium | 4.0-6.9 |
| 1 | Low | 0.1-3.9 |
| 0 | Info | N/A |

## Usage

```bash
export NESSUS_ACCESS_KEY="your-access-key"
export NESSUS_SECRET_KEY="your-secret-key"
python agent.py
```
