# API Reference — Hunting for Startup Folder Persistence

## Libraries Used
- **watchdog**: Real-time filesystem monitoring — `Observer`, `FileSystemEventHandler`
- **hashlib**: SHA-256 file hashing
- **subprocess**: Registry Run key queries via `reg query`
- **pathlib**: Cross-platform path handling and file metadata

## CLI Interface
```
python agent.py scan
python agent.py registry
python agent.py monitor --duration 120
python agent.py full
```

## Core Functions

### `get_startup_paths()` — Enumerate startup directories
Returns user startup (`%APPDATA%\...\Startup`) and all-users startup
(`%PROGRAMDATA%\...\Startup`) paths.

### `analyze_file(filepath, scope)` — Single file risk analysis
Computes SHA-256 hash, checks extension against risk table, evaluates
file age, size, baseline membership. Risk scoring by extension, recency,
and scope.

### `scan_startup_folders()` — Full startup directory scan
Iterates all files in both startup paths. Returns sorted by risk score.

### `check_registry_run_keys()` — Registry autostart audit
Queries 4 Registry Run keys via `reg query`:
- `HKCU\...\Run`, `HKCU\...\RunOnce`
- `HKLM\...\Run`, `HKLM\...\RunOnce`
Flags entries containing powershell, cmd.exe, temp paths, encoded commands.

### `StartupMonitorHandler` — Watchdog event handler
Subclasses `FileSystemEventHandler`. Handles `on_created`, `on_modified`,
`on_deleted`. Runs `analyze_file()` on new files and prints JSON alerts.

### `monitor_startup(duration_seconds)` — Real-time monitoring
Creates `Observer`, schedules handler on all startup paths. Monitors for
specified duration. Returns detected events.

### `full_hunt()` — Comprehensive persistence hunt

## Startup Folder Paths
| Scope | Path |
|-------|------|
| Current User | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
| All Users | `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |

## File Extension Risk Scores
| Extension | Base Score | Notes |
|-----------|-----------|-------|
| .ps1 | 45 | PowerShell script |
| .hta | 45 | HTML Application |
| .pif | 45 | Program Information File |
| .vbs, .vbe | 40 | VBScript |
| .js, .jse | 40 | JScript |
| .wsf, .wsh | 35-40 | Windows Script |
| .bat, .cmd | 35 | Batch file |
| .exe | 30 | Executable |
| .scr | 40 | Screen saver (executable) |
| .url | 20 | Internet shortcut |
| .lnk | 15 | Shortcut (often legitimate) |

## Additional Risk Factors
| Factor | Points |
|--------|--------|
| Created within 7 days | +25 |
| Created within 24 hours | +15 |
| Zero-byte file | +10 |
| File > 10 MB | +10 |
| Not in baseline | +10 |
| All-users scope | +10 |

## MITRE ATT&CK Mapping
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- Tactics: Persistence, Privilege Escalation

## Dependencies
- `watchdog` >= 3.0.0
- Windows OS (startup folder paths are Windows-specific)
