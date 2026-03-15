# API Reference: Static Malware Analysis with PE Studio Agent

## Overview

Performs automated static analysis of Windows PE binaries using pefile to inspect headers, sections, imports, strings, and resources for malware indicators.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pefile | >= 2023.2.7 | PE file parsing and section analysis |
| hashlib | stdlib | MD5, SHA-1, SHA-256 hash computation |

## Core Functions

### `compute_hashes(filepath)`
Generates MD5, SHA-1, SHA-256 hashes and file size.
- **Returns**: `dict` with `md5`, `sha1`, `sha256`, `size`

### `analyze_sections(pe)`
Inspects PE sections for entropy, virtual/raw size ratios, and packing indicators.
- **Flags**: `HIGH_ENTROPY` (>7.0), `HIGH_VR_RATIO` (>10x)
- **Returns**: `list[dict]` - section analysis entries

### `detect_packer(pe)`
Identifies known packer section names (UPX, ASPack, VMProtect, Themida) and low import counts.
- **Returns**: `list[str]` - detected packer names

### `analyze_imports(pe)`
Categorizes imports into Process Injection, Keylogging, Persistence, Evasion, Network, Crypto.
- **Returns**: `list[dict]` with `category`, `dll`, `function`

### `extract_strings(filepath, min_length=6)`
Extracts ASCII strings and classifies into URLs, IPs, emails, registry keys, file paths.
- **Returns**: `dict[str, list[str]]` - categorized string indicators

### `analyze_resources(pe)`
Inspects PE resources for high-entropy data and embedded PE files.
- **Returns**: `list[dict]` with `type_id`, `size`, `entropy`, `flags`

### `analyze_pe(filepath)`
Full analysis pipeline producing structured report.
- **Returns**: `dict` - complete analysis report

## Suspicious Import Categories

| Category | Example Functions |
|----------|-------------------|
| Process Injection | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| Keylogging | GetAsyncKeyState, SetWindowsHookExA |
| Persistence | RegSetValueExA, CreateServiceA |
| Evasion | IsDebuggerPresent, CheckRemoteDebuggerPresent |
| Network | InternetOpenA, URLDownloadToFileA, WSAStartup |
| Crypto | CryptEncrypt, CryptDecrypt |

## Usage

```bash
python agent.py suspect.exe
```
