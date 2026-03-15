# Workflows - Scanning Infrastructure with Nessus

## Workflow 1: Initial Infrastructure Assessment

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Asset Discovery │────>│  Policy Creation │────>│  Credential Config │
│  (Host Enum)     │     │  (Custom/Default)│     │  (SSH/WinRM/SNMP)  │
└─────────────────┘     └──────────────────┘     └────────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   Launch Scan    │────>│  Monitor Status  │────>│   Export Results   │
│   (On-Demand)    │     │  (API Polling)   │     │   (CSV/HTML/PDF)   │
└──────────────────┘     └──────────────────┘     └────────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│ Analyze Findings │────>│ Prioritize Vulns │────>│  Create Tickets    │
│ (Severity/CVSS)  │     │ (Risk-Based)     │     │  (Jira/ServiceNow) │
└──────────────────┘     └──────────────────┘     └────────────────────┘
```

## Workflow 2: Recurring Scheduled Scanning

1. **Weekly**: Scan DMZ and internet-facing assets
2. **Bi-weekly**: Scan internal production servers
3. **Monthly**: Full infrastructure scan including workstations
4. **Quarterly**: Comprehensive scan with compliance audits
5. **Ad-hoc**: Post-patch verification scans

## Workflow 3: Scan Result Processing Pipeline

```
Nessus Export (.nessus XML)
    │
    ├──> Parse with Python (xml.etree / defusedxml)
    │        │
    │        ├──> Filter by severity (Critical/High)
    │        ├──> Deduplicate findings across hosts
    │        ├──> Enrich with EPSS scores
    │        └──> Map to MITRE ATT&CK techniques
    │
    ├──> Import to Vulnerability Management Platform
    │        │
    │        ├──> Tenable.sc / Tenable.io
    │        ├──> DefectDojo
    │        └──> Faraday
    │
    └──> Generate Executive Report
             │
             ├──> Vulnerability count by severity
             ├──> Top 10 most critical findings
             ├──> Remediation progress trending
             └──> Risk score by business unit
```

## Workflow 4: API Automation Flow

```python
# Nessus API Workflow Steps:
# 1. POST /session -> Get auth token
# 2. GET /editor/scan/templates -> List available templates
# 3. POST /scans -> Create scan with template UUID
# 4. POST /scans/{id}/launch -> Start the scan
# 5. GET /scans/{id} -> Poll until status == "completed"
# 6. POST /scans/{id}/export -> Request export (format: nessus/csv/html)
# 7. GET /scans/{id}/export/{file_id}/status -> Poll export status
# 8. GET /scans/{id}/export/{file_id}/download -> Download results
# 9. DELETE /session -> Logout
```

## Workflow 5: Multi-Scanner Coordination

For large enterprises with multiple Nessus scanners:

1. **Central Management**: Use Tenable.sc to manage multiple scanners
2. **Zone Assignment**: Assign scanners to specific network zones
3. **Scan Windowing**: Stagger scans to prevent network saturation
4. **Result Aggregation**: Consolidate results in central repository
5. **Deduplication**: Merge findings from overlapping scan ranges
