---
name: analyzing-windows-amcache-artifacts
description: >
  Parse and analyze Windows Amcache.hve registry hive to extract program
  execution evidence, file metadata, SHA-1 hashes, and device connection
  history for digital forensics and incident response investigations.
domain: cybersecurity
subdomain: digital-forensics
tags: [amcache, windows-forensics, registry-analysis, execution-artifacts]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Windows Amcache Artifacts

Extract execution evidence from Amcache.hve including application paths,
SHA-1 hashes, timestamps, and publisher metadata for DFIR investigations.

## Example Output

```
$ AmcacheParser.exe -f "C:\Evidence\Amcache.hve" --csv /analysis/amcache_output

AmcacheParser v1.5.1 - Amcache.hve Parser
============================================
Input: C:\Evidence\Amcache.hve (12.4 MB)
Last Write Time: 2024-01-18 23:59:45 UTC

[+] Parsing File entries...           Found: 4,567
[+] Parsing Program entries...        Found: 234
[+] Parsing Driver entries...         Found: 189
[+] Parsing Device Container entries  Found: 45
[+] Parsing Shortcut entries...       Found: 312

--- Unassociated File Entries (No Known Publisher) ---
SHA-1               | Path                                          | Name              | Size      | First Run (UTC)       | Publisher
--------------------|-----------------------------------------------|-------------------|-----------|-----------------------|----------
a1b2c3d4e5f6a7b8...| C:\ProgramData\Updates\                       | update_client.exe | 1,258,496 | 2024-01-15 14:36:30   | (none)
b2c3d4e5f6a7b8c9...| C:\Windows\Temp\                              | mimikatz.exe      | 1,250,816 | 2024-01-16 02:30:15   | (none)
c3d4e5f6a7b8c9d0...| C:\Windows\Temp\                              | procdump64.exe    | 421,376   | 2024-01-16 02:28:00   | Sysinternals
d4e5f6a7b8c9d0e1...| C:\ProgramData\svc\                           | updater.exe       | 345,088   | 2024-01-15 14:37:00   | (none)
e5f6a7b8c9d0e1f2...| C:\Users\jsmith\AppData\Local\Temp\           | psexec.exe        | 834,936   | 2024-01-16 02:40:00   | Sysinternals
f6a7b8c9d0e1f2a3...| C:\Users\jsmith\Downloads\                    | netscan.exe       | 512,000   | 2024-01-15 15:10:22   | (none)

--- Program Entries (Recently Installed) ---
Name                    | Version       | Publisher              | Install Date    | Source
------------------------|---------------|------------------------|-----------------|--------
PuTTY                   | 0.80          | Simon Tatham           | 2024-01-14      | MSI
WinSCP                  | 6.1.2         | Martin Prikryl         | 2024-01-14      | MSI
7-Zip                   | 23.01         | Igor Pavlov            | 2024-01-15      | MSI
(Unknown)               | (Unknown)     | (none)                 | 2024-01-15      | Manual

--- Driver Entries (Suspicious) ---
Name                    | SHA-1               | Signer                | Install Date
------------------------|---------------------|-----------------------|-------------
WinDivert64.sys         | 1a2b3c4d5e6f...     | (self-signed)         | 2024-01-15
npf.sys                 | 2b3c4d5e6f7a...     | Nmap Project          | 2024-01-15

Summary:
  Total execution artifacts:    4,567
  Unsigned/suspicious entries:  6
  Recently installed programs:  4 (2 suspicious)
  Suspicious drivers:           2
  CSV exported to:              /analysis/amcache_output/
```
