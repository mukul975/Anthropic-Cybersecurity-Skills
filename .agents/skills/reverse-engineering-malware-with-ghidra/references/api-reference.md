# API Reference: Malware Reverse Engineering with Ghidra Agent

## Overview

Combines Ghidra headless analysis with r2pipe (radare2) for automated malware binary analysis: function enumeration, import classification, section entropy, cryptographic constant detection, and network indicator extraction.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| r2pipe | >= 1.8 | Radare2 scripting interface for binary analysis |
| hashlib | stdlib | File hash computation |

## External Tools

| Tool | Purpose |
|------|---------|
| Ghidra (analyzeHeadless) | Automated disassembly and decompilation |
| radare2 | Binary analysis, function detection, string extraction |

## Core Functions

### `run_ghidra_headless(ghidra_path, project_dir, project_name, binary_path, script)`
Executes Ghidra in headless mode with optional post-analysis script.
- **Timeout**: 600 seconds
- **Returns**: `dict` with command, returncode, stdout/stderr

### `export_functions_ghidra(...)`
Generates and runs a Ghidra script to export function list as JSON.
- **Exports**: name, address, size, calling convention, is_thunk

### `analyze_with_radare2(filepath)`
Full r2pipe analysis: binary info, functions, imports, strings, sections, entry points.
- **Classifies imports**: injection, network, evasion, crypto, persistence
- **Extracts**: network indicators (URLs, IPs) from strings
- **Returns**: `dict` with info, function_count, suspicious_imports, sections, etc.

### `extract_crypto_constants(filepath)`
Searches binary for known cryptographic constants: AES S-box, RC4 init table, SHA-256 init vector, RSA magic bytes.
- **Returns**: `list[dict]` with constant name and file offset

### `analyze_malware(filepath, ghidra_path, output_dir)`
Full pipeline: hashes -> crypto constants -> radare2 analysis -> Ghidra headless.

## Suspicious Import Categories

| Category | Example Functions |
|----------|-------------------|
| injection | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| network | InternetOpenA, WSAStartup, URLDownloadToFileA |
| evasion | IsDebuggerPresent, NtQueryInformationProcess |
| crypto | CryptEncrypt, CryptDecrypt |
| persistence | RegSetValueExA, CreateServiceA |

## Radare2 Commands Used

| Command | Purpose |
|---------|---------|
| `aaa` | Full auto-analysis |
| `ij` | Binary info as JSON |
| `aflj` | Function list as JSON |
| `iij` | Import list as JSON |
| `izj` | String list as JSON |
| `iSj` | Section list as JSON |
| `iej` | Entry points as JSON |

## Usage

```bash
# With radare2 only
python agent.py malware.exe

# With Ghidra headless analysis
python agent.py malware.exe /opt/ghidra
```
