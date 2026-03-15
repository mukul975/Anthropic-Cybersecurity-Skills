# API Reference — Hunting for LOLBins Execution in Endpoint Logs

## Libraries Used
- **csv**: Parse exported endpoint log CSV files from SIEM or EDR
- **python-evtx** (Evtx): Parse Windows Sysmon EVTX event logs directly
- **re**: Regex matching for suspicious command-line patterns

## CLI Interface

```
python agent.py csv --file <csv_path> [--process-col Image] [--cmdline-col CommandLine]
python agent.py evtx --file <evtx_path>
```

## Core Functions

### `scan_csv_logs(csv_file, process_col, cmdline_col)`
Scans CSV-exported endpoint logs for LOLBin process executions with suspicious arguments.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `csv_file` | str | Path to CSV log file |
| `process_col` | str | Column name for process image path (default: `Image`) |
| `cmdline_col` | str | Column name for command line (default: `CommandLine`) |

**Returns:** dict with `total_findings`, `by_binary` counts, `by_mitre` counts, `findings` list.

### `scan_evtx_sysmon(evtx_file)`
Parses Sysmon EVTX logs for Event ID 1 (Process Creation) matching LOLBin signatures.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `evtx_file` | str | Path to Sysmon .evtx file |

**Returns:** dict with `total_findings` and `findings` with record IDs, binary names, MITRE IDs.

## LOLBins Detected (14 binaries)
certutil.exe, mshta.exe, regsvr32.exe, rundll32.exe, bitsadmin.exe, wmic.exe,
msiexec.exe, cmstp.exe, forfiles.exe, pcalua.exe, csc.exe, installutil.exe,
msbuild.exe, powershell.exe

## Output Format
```json
{
  "total_findings": 12,
  "by_binary": {"powershell.exe": 5, "certutil.exe": 4},
  "by_mitre": {"T1059.001": 5, "T1140": 4},
  "findings": [{"binary": "...", "mitre": "...", "command_line": "..."}]
}
```

## Dependencies
```
pip install python-evtx
```
