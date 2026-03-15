# API Reference: Splunk SPL Detection Rules

## Splunk REST API - Saved Searches
```
POST /servicesNS/{owner}/{app}/saved/searches
Authorization: Bearer TOKEN
```
| Field | Description |
|-------|-------------|
| `name` | Saved search name |
| `search` | SPL query string |
| `is_scheduled` | 1 for scheduled |
| `cron_schedule` | Cron expression (e.g., `*/5 * * * *`) |
| `dispatch.earliest_time` | Start of search window |
| `alert.severity` | 1-5 (info to critical) |
| `alert_type` | `number of events` |
| `alert_threshold` | Trigger threshold |

## Key SPL Commands
| Command | Description |
|---------|-------------|
| `stats count by field` | Aggregate events |
| `where count > N` | Filter results |
| `table field1, field2` | Select fields |
| `eval` | Compute new fields |
| `lookup` | Enrich from lookup table |
| `tstats` | Accelerated data model search |
| `join` | Join two datasets |

## Windows Event IDs for Detection
| EventCode | Source | Description |
|-----------|--------|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential logon |
| 4698 | Security | Scheduled task created |
| 4104 | PowerShell | Script block logging |
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |
| 10 | Sysmon | Process access |

## Alert Severity Levels
| Level | Value | Description |
|-------|-------|-------------|
| Info | 1 | Informational |
| Low | 2 | Low risk |
| Medium | 3 | Medium risk |
| High | 4 | High risk |
| Critical | 5 | Critical risk |
