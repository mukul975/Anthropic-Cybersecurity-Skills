# API Reference — Hunting for Persistence Mechanisms in Windows

## Libraries Used
- **subprocess**: Execute `reg query`, `schtasks`, `wmic` commands to enumerate persistence
- **csv**: Parse schtasks CSV output for scheduled task analysis
- **re**: Pattern matching for suspicious command-line indicators

## CLI Interface

```
python agent.py registry    # Enumerate registry Run keys
python agent.py tasks       # Enumerate scheduled tasks
python agent.py services    # Enumerate suspicious services
python agent.py all         # Run all persistence hunts
```

## Core Functions

### `enumerate_registry_persistence()`
Queries 11 common registry persistence locations using `reg query` and flags entries matching suspicious indicators.

**Returns:** dict with `total_entries`, `suspicious_entries`, and `findings` list (each with `key`, `name`, `type`, `value`, `suspicious`).

### `enumerate_scheduled_tasks()`
Runs `schtasks /query /fo CSV /v` and flags tasks with suspicious actions or non-Microsoft authors.

**Returns:** dict with `total_tasks`, `suspicious_tasks`, and `findings` list.

### `enumerate_services()`
Uses `wmic service get` to list services and flags those running from unusual filesystem paths.

**Returns:** dict with `total_services`, `suspicious_services`, and filtered `findings`.

### `parse_reg_output(output, parent_key)`
Parses `reg query` text output into structured entries with key, name, type, value fields.

## Registry Keys Checked
| Key Path | Persistence Type |
|----------|-----------------|
| `HKLM\...\CurrentVersion\Run` | Auto-start programs |
| `HKLM\...\Winlogon` | Logon scripts, shell replacement |
| `HKLM\...\Active Setup` | Per-user component execution |
| `HKLM\...\Services` | Service binary paths |
| `HKLM\...\Image File Execution Options` | Debugger hijacking |

## Suspicious Indicators
Patterns flagging entries: `\\temp\\`, `powershell.*-enc`, `mshta.exe`, `rundll32.exe`, `base64`, `downloadstring`, `\\users\\public\\`

## Dependencies
No external packages required — uses only Python standard library and Windows built-in commands.
