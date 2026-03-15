# API Reference: Windows Event Log Artifact Extraction Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| evtx (python-evtx) | >=0.8 | Parse Windows EVTX binary log files into JSON records |

## CLI Usage

```bash
python scripts/agent.py \
  --evtx-dir /cases/case-001/evtx/ \
  --output-dir /cases/case-001/analysis/ \
  --output evtx_report.json

# Or specify individual files:
python scripts/agent.py \
  --evtx-files Security.evtx System.evtx \
  --output-dir /cases/analysis/
```

## Functions

### `parse_evtx_file(evtx_path) -> list`
Parses a single EVTX file using PyEvtxParser. Returns list of dicts with event_id, timestamp, channel, computer, event_data.

### `filter_critical_events(records) -> dict`
Filters records to 15 critical Event IDs (4624, 4625, 4688, 4697, 1102, etc.) grouped by Event ID.

### `detect_lateral_movement(records) -> list`
Identifies network logons (Type 3) and RDP (Type 10) from non-local IPs. Flags pass-the-hash indicators (Type 9 + NTLM).

### `detect_privilege_escalation(records) -> list`
Detects special privilege assignment (4672), group membership changes (4728/4732/4756), and account creation (4720).

### `detect_suspicious_processes(records) -> list`
Matches 4688 process creation events against a list of known attack tools (mimikatz, psexec, rubeus, etc.).

### `detect_log_clearing(records) -> list`
Identifies audit log clearing events (Event ID 1102 and 104).

### `detect_persistence(records) -> list`
Detects service installations (4697/7045) and scheduled task creation (4698).

### `generate_summary(records, findings) -> dict`
Computes statistics: total records, top event IDs, alert counts per detection category.

### `export_timeline_csv(records, output_path)`
Exports critical events as a sorted CSV timeline with timestamp, event_id, description, details.

### `analyze_evtx(evtx_paths, output_dir) -> dict`
Orchestrates parsing of multiple EVTX files and runs all detection functions.

## Critical Event IDs

| Event ID | Description |
|----------|-------------|
| 1102 | Audit Log Cleared |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Explicit Credential Logon |
| 4672 | Special Privileges Assigned |
| 4688 | New Process Created |
| 4697 | Service Installed |
| 4698 | Scheduled Task Created |
| 4720 | User Account Created |
| 7045 | New Service Installed (System log) |

## Output Schema

```json
{
  "files_analyzed": ["/cases/evtx/Security.evtx"],
  "summary": {
    "total_records": 245678,
    "lateral_movement_alerts": 12,
    "suspicious_processes": 3,
    "persistence": 5
  },
  "findings": {
    "lateral_movement": [{"user": "admin", "source_ip": "10.0.0.5", "logon_type": "Network"}],
    "suspicious_processes": [{"matched_pattern": "mimikatz", "process": "m.exe"}]
  }
}
```
