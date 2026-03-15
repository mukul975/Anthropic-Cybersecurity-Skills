# API Reference — Hunting for Scheduled Task Persistence

## Libraries Used
- **subprocess**: Execute `schtasks /query` and `schtasks /query /xml` for task enumeration
- **csv**: Parse schtasks CSV output for structured task analysis
- **python-evtx** (Evtx): Parse Security EVTX for Event ID 4698 (Task Created)

## CLI Interface

```
python agent.py enumerate                    # List and risk-score all tasks
python agent.py events --evtx-file <path>    # Scan EVTX for task creation events
python agent.py export --task-name <name>    # Export task XML definition
```

## Core Functions

### `enumerate_tasks()`
Runs `schtasks /query /fo CSV /v` and classifies each task as high/medium/low risk.

**Returns:** dict with `total_tasks`, `high_risk`, `medium_risk`, `suspicious_tasks`, `non_vendor_tasks`.

### `scan_event_log_4698(evtx_file)`
Parses Windows Security EVTX for Event ID 4698 (Scheduled Task Created).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `evtx_file` | str | Path to Security .evtx log file |

### `export_task_xml(task_name)`
Exports a task's full XML definition using `schtasks /query /tn <name> /xml`.

## Risk Classification
| Risk | Criteria |
|------|---------|
| **High** | Action matches suspicious patterns (powershell -enc, certutil, temp paths) |
| **Medium** | Non-vendor task (not under \\Microsoft\\, \\Google\\, etc.) |
| **Low** | Known vendor task prefix |

## Dependencies
```
pip install python-evtx  # Optional, for EVTX parsing
```
