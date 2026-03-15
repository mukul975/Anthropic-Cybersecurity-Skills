# API Reference — Performing Endpoint Forensics Investigation

## Libraries Used
- **subprocess**: Execute Windows forensic commands (wmic, netstat, reg, schtasks)
- **hashlib**: Calculate MD5, SHA1, SHA256 hashes for evidence integrity
- **csv**: Parse WMIC CSV output

## CLI Interface

```
python agent.py triage      # Full forensic triage
python agent.py processes   # Running processes with PIDs and command lines
python agent.py network     # Active network connections
python agent.py autoruns    # Persistence entries
python agent.py hash --file <filepath>  # Hash file for evidence
```

## Core Functions

### `full_triage()` — Runs all collection functions
### `collect_system_info()` — Hostname, OS version, network config, uptime
### `collect_running_processes()` — Process list via `wmic process get`
### `collect_network_connections()` — Active connections via `netstat -ano`
### `collect_autoruns()` — Registry Run keys and scheduled tasks
### `hash_file(filepath)` — MD5/SHA1/SHA256 hash calculation

## Dependencies
No external packages — uses Windows built-in commands and Python stdlib.
