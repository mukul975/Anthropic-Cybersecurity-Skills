# API Reference — Hunting for Registry Persistence Mechanisms

## Libraries Used
- **subprocess**: Execute `reg query /s` to enumerate registry persistence keys
- **re**: Pattern matching for suspicious values in registry entries
- **json**: Baseline file I/O and structured output

## CLI Interface

```
python agent.py scan [--categories run_keys winlogon ifeo] [--save-baseline out.json]
python agent.py compare --baseline baseline.json
```

## Core Functions

### `scan_persistence_keys(categories=None)`
Enumerates registry persistence keys across 8 categories and flags suspicious entries.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `categories` | list | Optional subset of categories to scan (default: all 8) |

**Returns:** dict with `categories` map, `all_suspicious` list, and `total_suspicious` count.

### `compare_baseline(baseline_file, current_scan=None)`
Compares current registry state against a saved baseline to detect new persistence entries.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `baseline_file` | str | Path to baseline JSON file from previous scan |

**Returns:** dict with `baseline_entries` count, `new_entries` count, and `findings` list.

## Registry Categories Scanned

| Category | Keys | MITRE Technique |
|----------|------|----------------|
| `run_keys` | Run, RunOnce, RunOnceEx | T1547.001 |
| `winlogon` | Winlogon Shell, Userinit | T1547.004 |
| `ifeo` | Image File Execution Options | T1546.012 |
| `appinit` | AppInit_DLLs | T1546.010 |
| `shell_extensions` | ShellExecuteHooks | T1546.015 |
| `browser_helpers` | Browser Helper Objects | T1176 |
| `com_hijack` | CLSID overrides in HKCU | T1546.015 |
| `boot_execute` | BootExecute, Session Manager | T1542.003 |

## Dependencies
No external packages required — uses Python standard library and `reg.exe`.
