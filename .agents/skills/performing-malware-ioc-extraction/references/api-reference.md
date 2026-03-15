# API Reference — Performing Malware IOC Extraction

## Libraries Used
- **re**: Regex patterns for 16 IOC types including defanged indicators
- **hashlib**: MD5, SHA1, SHA256 file hashing
- **pathlib**: File reading (text and binary)

## CLI Interface
```
python agent.py text --file threat_report.txt
python agent.py hash --file malware.exe
python agent.py strings --file malware.exe [--min-length 6]
python agent.py report --file malware.exe [--output iocs.json]
```

## Core Functions

### `extract_iocs_from_text(text)` — Extract IOCs with defanging support
Handles defanged indicators: `[.]` -> `.`, `hxxp` -> `http`. Filters private IPs.

### `extract_from_file(file_path)` — Extract IOCs from text/report files
### `hash_file(file_path)` — Calculate MD5/SHA1/SHA256 hashes
### `extract_strings(file_path, min_length)` — Binary string extraction
Extracts ASCII and wide (UTF-16LE) strings. Identifies suspicious API calls and keywords.

### `generate_ioc_report(file_path, output)` — Full analysis report

## IOC Pattern Types (16)
| Type | Example |
|------|---------|
| ipv4 | 192.168.1.1 (private filtered) |
| domain | evil.example.com |
| url | https://malware.example.com/payload |
| md5/sha1/sha256 | File hashes |
| cve | CVE-2024-12345 |
| registry_key | HKLM\Software\... |
| file_path_windows | C:\Windows\Temp\mal.exe |
| mutex | Global\MutexName |
| mitre_technique | T1059.001 |
| bitcoin_addr | Bitcoin wallet address |
| user_agent | Mozilla/5.0 strings |

## Suspicious String Keywords
CreateRemoteThread, VirtualAlloc, WriteProcessMemory, LoadLibrary,
GetProcAddress, WinExec, ShellExecute, powershell, cmd.exe

## Dependencies
No external packages — Python standard library only.
