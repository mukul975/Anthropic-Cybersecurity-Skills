# API Reference: .NET Malware Reverse Engineering with dnSpy Agent

## Overview

Analyzes .NET malware: validates CLR headers, detects obfuscators (ConfuserEx, SmartAssembly), deobfuscates with de4dot, extracts strings/IOCs, and parses .NET metadata via monodis.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| hashlib | stdlib | Sample hash computation |
| struct | stdlib | PE/CLR header parsing |
| re | stdlib | String pattern extraction |

## External Tools (Optional)

| Tool | Purpose |
|------|---------|
| diec (Detect It Easy) | Obfuscator identification |
| de4dot | Automated .NET deobfuscation |
| monodis | .NET assembly metadata extraction |

## Core Functions

### `detect_dotnet_assembly(filepath)`
Validates PE file has CLR header (COM descriptor directory entry).
- **Checks**: MZ signature, PE signature, optional header magic, CLR RVA
- **Returns**: `dict` with `is_dotnet`, `clr_header_rva`

### `detect_obfuscator(filepath)`
Runs Detect It Easy to identify ConfuserEx, SmartAssembly, .NET Reactor, Dotfuscator, Babel, Eazfuscator, Crypto Obfuscator.
- **Returns**: `dict` with `detected` list

### `deobfuscate_with_de4dot(filepath, output_path)`
Runs de4dot to remove obfuscation, producing a cleaner assembly.
- **Timeout**: 120 seconds
- **Returns**: `dict` with `success`, `output_path`

### `extract_strings(filepath, min_length)`
Extracts ASCII and Unicode strings, classifies into URLs, IPs, emails, registry keys, base64, and suspicious keywords (keylog, stealer, webhook, etc.).
- **Returns**: `dict[str, list[str]]` - categorized indicator lists

### `analyze_dotnet_metadata(filepath)`
Uses monodis to extract assembly info, type definitions, and method counts.
- **Returns**: `dict` with `type_count`, `method_count`, `types`

### `analyze_dotnet_malware(filepath, output_dir)`
Full pipeline: hashes -> .NET check -> obfuscator detection -> deobfuscation -> strings -> metadata.

## Obfuscators Detected

| Obfuscator | Indicator |
|------------|-----------|
| ConfuserEx | Most common open-source .NET obfuscator |
| SmartAssembly | Commercial obfuscator by Redgate |
| .NET Reactor | Code protection with native stub |
| Dotfuscator | Microsoft-provided obfuscator |
| Eazfuscator | Commercial string/flow obfuscation |

## Suspicious String Keywords

`keylog`, `screenshot`, `clipboard`, `password`, `credential`, `smtp`, `telegram`, `discord`, `webhook`, `stealer`, `inject`, `hook`, `persist`, `startup`

## Usage

```bash
python agent.py suspect.exe
```
