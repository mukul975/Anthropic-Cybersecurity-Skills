# API Reference: Memory Forensics Agent (Volatility 3)

## Overview

Automates memory forensics analysis using Volatility 3: process listing, network connections, process injection detection, command line extraction, and hidden driver/rootkit detection.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| volatility3 | >=2.0 | Memory forensics framework (subprocess) |

## CLI Usage

```bash
python agent.py --memory-file memory.raw --output forensics_report.json
```

## Key Functions

### `run_volatility(memory_file, plugin, extra_args)`
Executes a Volatility 3 plugin via subprocess and parses tab-delimited output into dictionaries.

### `analyze_processes(memory_file)`
Runs `windows.pslist` and flags processes matching known offensive tools (mimikatz, cobalt, meterpreter, psexec).

### `analyze_network_connections(memory_file)`
Runs `windows.netscan` to extract network connections and filters for ESTABLISHED state.

### `detect_process_injection(memory_file)`
Runs `windows.malfind` to detect injected code in process memory (RWX pages with executable content).

### `analyze_dlls(memory_file, pid)`
Lists loaded DLLs for a specific process or all processes via `windows.dlllist`.

### `extract_command_history(memory_file)`
Runs `windows.cmdline` and flags suspicious patterns (encoded PowerShell, credential dumping, LOLBins).

### `check_kernel_modules(memory_file)`
Compares `windows.modules` with `windows.driverscan` to detect hidden/rootkit drivers.

## Volatility 3 Plugins Used

| Plugin | Purpose |
|--------|---------|
| `windows.pslist` | List running processes |
| `windows.netscan` | Extract network connections |
| `windows.malfind` | Detect process injection |
| `windows.dlllist` | List loaded DLLs |
| `windows.cmdline` | Extract command line arguments |
| `windows.registry.hivelist` | List registry hives |
| `windows.modules` | List kernel modules |
| `windows.driverscan` | Scan for driver objects |

## Suspicious Process Indicators

Processes flagged: mimikatz, procdump, psexec, cobalt, beacon, meterpreter, nc.exe, ncat, certutil, bitsadmin, mshta, regsvr32, wscript, cscript.

## Suspicious Command Patterns

Commands flagged: `powershell -enc`, `invoke-expression`, `downloadstring`, `net user`, `sekurlsa`, `lsadump`, `reg save`, `vssadmin`, `certutil -urlcache`, `bitsadmin /transfer`.
