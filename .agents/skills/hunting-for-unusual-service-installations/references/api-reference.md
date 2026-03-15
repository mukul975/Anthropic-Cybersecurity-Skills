# API Reference — Hunting for Unusual Service Installations

## Libraries Used
- **python-evtx**: Parse Windows .evtx event log files
- **lxml**: XML parsing of EVTX record XML
- **re**: Regex matching for suspicious binary path patterns
- **collections.Counter**: Statistics aggregation

## CLI Interface
```
python agent.py System.evtx parse
python agent.py System.evtx hunt
python agent.py System.evtx stats
python agent.py System.evtx full
```

## Core Functions

### `parse_evtx_events(evtx_path)` — Extract Event ID 7045 records
Opens .evtx file with `evtx.Evtx()`, iterates records, parses XML with lxml.
Extracts: ServiceName, ImagePath, ServiceType, StartType, AccountName, timestamp.
Namespace: `http://schemas.microsoft.com/win/2004/08/events/event`

### `analyze_service_path(image_path)` — Binary path risk analysis
Matches against 17 suspicious patterns (temp dirs, PowerShell, encoded commands,
LOLBins, download patterns). Checks against 5 legitimate path prefixes.
Scoring: +20 for non-standard path, +15 per suspicious indicator. Max 100.

### `hunt_suspicious_services(evtx_path)` — Main hunting engine
Combines parsing and analysis. Extra +20 risk for LocalSystem account with
non-standard binary path. Results sorted by risk score descending.

### `generate_statistics(results)` — Summary statistics
Counts risk distribution, top indicators, service account usage.

### `full_hunt(evtx_path)` — Comprehensive threat hunt report

## Suspicious Path Patterns
| Pattern | Indicator |
|---------|-----------|
| `\temp\`, `\tmp\` | temp_directory |
| `\appdata\` | appdata_directory |
| `\users\public\` | public_user_directory |
| `powershell.exe` | powershell_execution |
| `cmd.exe /c` | cmd_execution |
| `-enc`, `-encodedcommand` | encoded_command |
| `downloadstring`, `webclient` | download_pattern |
| `invoke-expression`, `iex` | invoke_expression |
| `mshta`, `regsvr32`, `rundll32` | lolbin_execution |

## Legitimate Service Path Prefixes
- `C:\Windows\System32\`
- `C:\Windows\SysWOW64\`
- `C:\Program Files\`
- `C:\Program Files (x86)\`
- `C:\Windows\Microsoft.NET\`

## Event ID 7045 Fields
| Field | Description |
|-------|-------------|
| ServiceName | Display name of installed service |
| ImagePath | Binary path and arguments |
| ServiceType | user mode service, kernel driver, etc. |
| StartType | auto start, demand start, boot start |
| AccountName | Service account (LocalSystem, etc.) |

## MITRE ATT&CK Mapping
- **T1543.003** — Create or Modify System Process: Windows Service
- Tactics: Persistence, Privilege Escalation

## Dependencies
- `python-evtx` >= 0.7.4
- `lxml` >= 4.9.0
