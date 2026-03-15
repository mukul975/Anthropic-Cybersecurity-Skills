# API Reference: Vulnerability Scanning Workflow Agent

## Overview

Orchestrates vulnerability scanning using Nmap and Nessus, enriches findings with CISA KEV data, applies risk-based prioritization, and generates remediation reports.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| python-nmap | >=0.7.1 | Nmap scan orchestration |
| requests | >=2.28 | REST API communication |

## CLI Usage

```bash
python agent.py --targets 192.168.1.0/24 --ports 1-1024 --output report.json
python agent.py --targets 10.0.0.0/16 --nessus-url https://nessus:8834 --nessus-keys "access;secret"
```

## Key Functions

### `run_nmap_vuln_scan(targets, ports)`
Runs Nmap with `-sV --script=vulners,vulscan` for service version detection and vulnerability matching.

### `fetch_cisa_kev()`
Downloads the CISA Known Exploited Vulnerabilities JSON catalog and returns a set of CVE IDs.

### `launch_nessus_scan(nessus_url, api_keys, scan_name, targets)`
Creates and launches a vulnerability scan via the Nessus REST API.

### `prioritize_vulnerabilities(vulns, kev_set, asset_criticality_map)`
Applies risk scoring: `risk_score = CVSS * asset_criticality * (1.5 if KEV)`. Assigns P1-P4 priority.

### `create_servicenow_ticket(snow_url, token, vuln)`
Creates ServiceNow incident tickets for high-priority vulnerability findings.

### `generate_report(vulns)`
Produces a formatted vulnerability scan summary with priority breakdown.

## External APIs Used

| API | Endpoint | Purpose |
|-----|----------|---------|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Known exploited vulns |
| Nessus | `/scans`, `/scans/{id}/launch` | Scan management |
| ServiceNow | `/api/now/table/incident` | Ticket creation |
