# API Reference — Performing Memory Forensics with Volatility3 Plugins

## Libraries Used
- **subprocess**: Execute Volatility3 CLI with JSON output
- **json**: Parse Volatility3 JSON results

## CLI Interface
```
python agent.py plugin --dump memory.raw --name pslist [--args --pid 1234]
python agent.py malproc --dump memory.raw
python agent.py inject --dump memory.raw
python agent.py network --dump memory.raw
python agent.py triage --dump memory.raw
```

## Core Functions

### `run_vol3_plugin(memory_dump, plugin_name, extra_args)` — Execute any Vol3 plugin
Supports 18 built-in plugins with JSON output parsing.

### `detect_malicious_processes(memory_dump)` — Suspicious process detection
Checks pslist against 15 known attack tools (mimikatz, cobalt, rubeus, etc.).
Flags cmd.exe and PowerShell execution.

### `detect_injected_code(memory_dump)` — Code injection via malfind
Identifies memory regions with executable, non-image-backed pages.

### `analyze_network_connections(memory_dump)` — Network artifact extraction
Extracts connections via netscan. Filters external (non-RFC1918) connections.

### `full_triage(memory_dump)` — Combined analysis
Runs processes + injection + network analysis in single report.

## Supported Volatility3 Plugins
| Plugin | Class | Purpose |
|--------|-------|---------|
| pslist | windows.pslist.PsList | Process listing |
| psscan | windows.psscan.PsScan | Hidden process scan |
| malfind | windows.malfind.Malfind | Code injection detection |
| netscan | windows.netscan.NetScan | Network connections |
| cmdline | windows.cmdline.CmdLine | Process command lines |
| dlllist | windows.dlllist.DllList | Loaded DLLs |
| hashdump | windows.hashdump.Hashdump | Password hash extraction |
| svcscan | windows.svcscan.SvcScan | Windows services |

## Dependencies
```
pip install volatility3
```
