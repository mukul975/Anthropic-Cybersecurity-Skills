# API Reference: Malware IOC Extraction Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| pefile | >=2023.2 | PE file parsing for imphash, sections, imports |
| yara-python | >=4.3 | YARA rule scanning against malware samples |
| requests | >=2.28 | VirusTotal API v3 IOC validation |

## CLI Usage

```bash
python scripts/agent.py \
  --sample /cases/malware.exe \
  --yara-rules /rules/malware.yar \
  --vt-key YOUR_VT_API_KEY \
  --output-dir /cases/analysis/ \
  --output ioc_report.json
```

## Functions

### `compute_hashes(file_path) -> dict`
Computes MD5, SHA-1, SHA-256 and file size for the sample.

### `extract_pe_metadata(file_path) -> dict`
Parses PE headers via pefile: imphash, compile timestamp, section entropy, import table.

### `extract_strings(file_path, min_length) -> list`
Extracts ASCII and Unicode strings (min 4 chars) from the binary.

### `extract_network_iocs(strings) -> dict`
Regex extraction of IPs, domains, URLs, emails from strings. Filters private IP ranges.

### `extract_host_iocs(strings) -> dict`
Identifies Windows file paths, registry keys, and mutex names from strings.

### `run_yara_scan(file_path, rules_path) -> list`
Compiles and runs YARA rules against the sample. Returns matched rule names, tags, and string offsets.

### `validate_ioc_virustotal(ioc_value, ioc_type, api_key) -> dict`
Queries VirusTotal API v3 for IP, domain, or file hash. Returns malicious/suspicious counts.

### `defang_ioc(value) -> str`
Defangs IOCs by replacing `http` with `hxxp` and `.` with `[.]`.

### `export_stix_bundle(iocs, sha256) -> dict`
Builds a STIX 2.1 indicator bundle with file hash, IP, and domain patterns.

### `export_csv(iocs, hashes, output_path)`
Writes IOCs to CSV format (type, value, context, confidence) for SIEM ingestion.

### `run_extraction(sample_path, output_dir, yara_rules, vt_key) -> dict`
Orchestrates the full extraction pipeline and generates all output files.

## Regex Patterns

| Pattern | Target |
|---------|--------|
| `\b(?:(?:25[0-5]\|...)\.){3}...\b` | IPv4 addresses |
| `\b[a-zA-Z0-9]...\.[a-zA-Z]{2,}+\b` | Domain names |
| `https?://[^\s<>"'{}]+` | URLs |
| `[a-zA-Z0-9_.+-]+@...` | Email addresses |

## Output Schema

```json
{
  "hashes": {"md5": "...", "sha256": "...", "sha1": "..."},
  "pe_metadata": {"imphash": "...", "compile_time": "...", "sections": []},
  "network_iocs": {"ips": [], "domains": [], "urls": []},
  "host_iocs": {"file_paths": [], "registry_keys": [], "mutexes": []},
  "yara_matches": [{"rule": "APT28_dropper", "tags": ["apt"]}],
  "summary": {"ips": 3, "domains": 5, "yara_hits": 1}
}
```
