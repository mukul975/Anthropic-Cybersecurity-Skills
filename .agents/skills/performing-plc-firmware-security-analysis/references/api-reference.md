# API Reference — Performing PLC Firmware Security Analysis

## Libraries Used
- **subprocess**: Execute binwalk for firmware extraction
- **hashlib**: MD5/SHA256 firmware hashing
- **re**: Credential and vulnerability pattern scanning
- **pathlib**: Recursive file scanning of extracted firmware
- **math**: Shannon entropy calculation

## CLI Interface
```
python agent.py extract --firmware plc_fw.bin [--output /tmp/fw_extract]
python agent.py metadata --firmware plc_fw.bin
python agent.py creds --dir /tmp/fw_extract
python agent.py vulns --dir /tmp/fw_extract
python agent.py full --firmware plc_fw.bin [--output /tmp/fw_extract]
```

## Core Functions

### `extract_firmware(firmware_file, output_dir)` — Binwalk extraction
### `analyze_firmware_metadata(firmware_file)` — Hash and entropy analysis
High entropy (>7.5) may indicate encryption or compression.

### `scan_for_credentials(extract_dir)` — Hardcoded credential detection
Patterns: passwords, default creds, private keys, API keys, connection strings.

### `scan_for_vulnerabilities(extract_dir)` — Code vulnerability patterns
Detects: command injection (system/popen), buffer overflow risk (strcpy/gets),
insecure protocols (telnet/FTP), debug mode, backdoor indicators.

### `full_analysis(firmware_file, output_dir)` — Complete analysis pipeline

## Vulnerability Patterns
| Pattern | Risk | Indicator |
|---------|------|-----------|
| command_injection | HIGH | system(), popen(), exec() |
| buffer_overflow_risk | HIGH | strcpy, strcat, sprintf, gets |
| insecure_protocol | MEDIUM | telnet, ftp, http:// |
| debug_enabled | MEDIUM | debug=true, DEBUG_MODE |
| backdoor_indicator | CRITICAL | backdoor, rootkit, reverse shell |

## Dependencies
```
pip install binwalk
```
