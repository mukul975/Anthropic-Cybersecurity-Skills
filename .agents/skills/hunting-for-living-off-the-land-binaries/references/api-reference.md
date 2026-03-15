# API Reference — Hunting for Living-off-the-Land Binaries

## Libraries Used
- **elasticsearch** (elasticsearch-py): Query Elastic SIEM for LOLBin process events
- **python-evtx** (Evtx): Parse Windows EVTX event logs for Sysmon process creation
- **re**: Regex matching against suspicious command-line argument patterns

## CLI Interface

```
python agent.py hunt --es-host <url> --index <pattern> [--api-key <key>] [--hours <n>]
python agent.py sysmon --evtx-file <path>
```

## Core Functions

### `hunt_lolbins_elastic(es_host, es_index, api_key=None, hours=24)`
Queries Elasticsearch for 12 LOLBin binaries with suspicious argument patterns.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `es_host` | str | Elasticsearch host URL |
| `es_index` | str | Index pattern (default: `logs-*`) |
| `api_key` | str | Optional API key |
| `hours` | int | Lookback window in hours |

**Returns:** dict with `detections` list (each with `binary`, `mitre`, `count`, `events`).

### `scan_sysmon_log(evtx_file)`
Parses Sysmon EVTX logs for Event ID 1 (Process Creation) matching LOLBin names.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `evtx_file` | str | Path to Sysmon .evtx file |

**Returns:** dict with `lolbin_events` count and `findings` list.

## LOLBins Covered

| Binary | MITRE Technique | Suspicious Pattern Examples |
|--------|----------------|---------------------------|
| certutil.exe | T1140, T1105 | `-urlcache`, `-decode`, `-encode` |
| mshta.exe | T1218.005 | `vbscript:`, `javascript:`, HTTP URLs |
| regsvr32.exe | T1218.010 | `/s /n /u /i:`, `scrobj.dll` |
| rundll32.exe | T1218.011 | `javascript:`, `shell32.dll` |
| bitsadmin.exe | T1197 | `/transfer`, `/download` |
| wmic.exe | T1047 | `process call create`, `/node:` |
| powershell.exe | T1059.001 | `-enc`, `IEX`, `DownloadString`, `-w hidden` |

## Dependencies
```
pip install elasticsearch>=8.0 python-evtx
```
