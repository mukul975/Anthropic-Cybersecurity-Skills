---
name: hunting-for-dcom-lateral-movement
description: Hunt for DCOM-based lateral movement (MITRE ATT&CK T1021.003) by detecting abuse of MMC20.Application, ShellBrowserWindow, and ShellWindows COM objects via Sysmon Event ID 1/3 correlation, WMI event analysis, and RPC endpoint mapper traffic on port 135. Use when investigating suspicious mmc.exe/dllhost.exe child processes, building T1021.003 detections, or auditing DCOM exposure during purple-team exercises. Do not use for hunting WMI-based lateral movement - use hunting-for-lateral-movement-via-wmi.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- DCOM
- lateral-movement
- T1021.003
- Sysmon
- MMC20
- ShellWindows
- ShellBrowserWindow
- COM-objects
- WMI
- RPC
version: '1.0'
author: mukul975
license: Apache-2.0
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Network Traffic Community Deviation
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1021
---

# Hunting for DCOM Lateral Movement

> **Authorized Testing Disclaimer**: The offensive techniques and attack simulations described in this skill are intended exclusively for authorized penetration testing, red team engagements, purple team exercises, and security research conducted with explicit written permission from the system owner. Unauthorized use of these techniques against systems you do not own or have permission to test is illegal and unethical. Always operate within the scope of your engagement and comply with applicable laws and regulations.

## Overview

Distributed Component Object Model (DCOM) enables remote execution of COM objects across a network using RPC. Adversaries abuse specific DCOM objects -- MMC20.Application (CLSID {49B2791A-B1AE-4C90-9B8E-E860BA07F889}), ShellBrowserWindow (CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}), and ShellWindows (CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}) -- to execute commands on remote hosts without dropping files, making this a stealthy lateral movement technique mapped to MITRE ATT&CK T1021.003. This skill provides detection strategies using Sysmon telemetry, Windows Security Event correlation, network monitoring, and SIEM detection rules to identify DCOM abuse in enterprise environments.

## When to Use

- Proactively hunting for lateral movement in Active Directory environments where DCOM is enabled
- Investigating alerts for suspicious mmc.exe, dllhost.exe, or explorer.exe child process creation on servers
- Building detection rules for MITRE ATT&CK T1021.003 (Remote Services: Distributed Component Object Model)
- Correlating Sysmon Event ID 1 (Process Create) and Event ID 3 (Network Connection) to trace DCOM-based command execution chains
- Auditing DCOM exposure across the domain to reduce lateral movement attack surface
- During purple team exercises validating detection coverage for DCOM-based techniques

**Do not use** as a replacement for EDR-based lateral movement detection, without Sysmon or equivalent process telemetry deployed on endpoints, or in isolation without correlating network-level and host-level indicators.

## Prerequisites

- Sysmon deployed on endpoints with configuration capturing Event ID 1 (Process Create), Event ID 3 (Network Connection), Event ID 7 (Image Loaded), and Event ID 10 (Process Access)
- Windows Security Event Logs forwarded to SIEM (Event IDs 4624, 4672, 4688)
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) with correlation capability
- Network monitoring for RPC traffic (TCP 135 and dynamic high ports 49152-65535)
- Baseline inventory of legitimate DCOM usage in the environment
- Understanding of MITRE ATT&CK Lateral Movement tactic (TA0008) and T1021.003

## Workflow

### Step 1: Understand DCOM Lateral Movement Attack Vectors

DCOM lateral movement exploits three primary COM objects. Each has distinct forensic artifacts.

**MMC20.Application** -- The attacker instantiates the MMC snap-in remotely and calls `ExecuteShellCommand` to run arbitrary commands on the target. This spawns mmc.exe as a child of svchost.exe (DcomLaunch service) on the target.

**ShellBrowserWindow** -- Uses the `Document.Application.ShellExecute` method to execute commands through an existing explorer.exe process. Unlike MMC20, this does not create a new process for the COM server itself, making it stealthier.

**ShellWindows** -- Similar to ShellBrowserWindow, it activates within an existing explorer.exe instance and executes child processes from explorer.exe. The absence of a new COM server process makes it harder to detect without proper telemetry.

```powershell
# ATTACK SIMULATION (authorized testing only)
# These commands demonstrate what adversaries execute -- use only in lab environments

# MMC20.Application lateral movement
# $dcom = [System.Activator]::CreateInstance(
#     [Type]::GetTypeFromProgID("MMC20.Application", "TARGET_IP"))
# $dcom.Document.ActiveView.ExecuteShellCommand(
#     "cmd.exe", $null, "/c whoami > C:\temp\output.txt", "7")

# ShellWindows lateral movement
# $dcom = [System.Activator]::CreateInstance(
#     [Type]::GetTypeFromCLSID(
#         [guid]"9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET_IP"))
# $dcom.item().Document.Application.ShellExecute(
#     "cmd.exe", "/c calc.exe", "C:\windows\system32", $null, 0)

# ShellBrowserWindow lateral movement
# $dcom = [System.Activator]::CreateInstance(
#     [Type]::GetTypeFromCLSID(
#         [guid]"C08AFD90-F2A1-11D1-8455-00A0C91F3880", "TARGET_IP"))
# $dcom.Document.Application.ShellExecute(
#     "cmd.exe", "/c net user", "C:\windows\system32", $null, 0)
```

### Step 2: Configure Sysmon for DCOM Detection

Extend your Sysmon config to capture the DCOM signals: Event ID 1 (mmc.exe/dllhost.exe/explorer.exe spawning cmd/powershell, DcomLaunch parents), Event ID 3 (RPC endpoint mapper port 135 and DCOM process connections), and Event ID 7 (comsvcs.dll, ole32.dll, rpcrt4.dll image loads).

See the full Sysmon config excerpt and deployment commands in [references/detection-queries.md](references/detection-queries.md#step-2-sysmon-configuration-for-dcom-detection).

### Step 3: Build SIEM Detection Rules for DCOM Object Abuse

Three portable Sigma rules cover the technique: MMC20.Application (mmc.exe spawning script hosts, filtering legitimate .msc snap-ins), ShellWindows/ShellBrowserWindow (explorer.exe spawning script hosts on non-interactive sessions), and a correlation rule tying a port-135 inbound connection to a DCOM parent process creation within 30 seconds.

See the full Sigma rules in [references/detection-queries.md](references/detection-queries.md#step-3-siem-detection-rules-sigma-for-dcom-object-abuse).

### Step 4: Deploy Splunk and KQL Detection Queries

Ready-to-run queries: Splunk searches correlating 4624 Type 3 logons with mmc.exe/explorer.exe process creation and flagging RPC endpoint-mapper connection anomalies, plus Microsoft Sentinel KQL for MMC20 and ShellWindows patterns joining network and process telemetry.

See the full Splunk and KQL queries in [references/detection-queries.md](references/detection-queries.md#step-4-splunk-and-kql-detection-queries).

### Step 5: WMI Event Correlation for DCOM Activity

Because DCOM calls can trigger WMI operations, correlate the WMI-Activity operational log (Event IDs 5857-5861) with DCOM process chains. Includes a Splunk search over WMI events and PowerShell to query the WMI operational log and Sysmon for DCOM parent-child chains during an investigation.

See the full WMI correlation queries in [references/detection-queries.md](references/detection-queries.md#step-5-wmi-event-correlation-for-dcom-activity).

### Step 6: Network-Level DCOM Detection with Zeek

A Zeek script uses SumStats to alert when a single source contacts more than three hosts on RPC/135 within a window, plus zeek-cut pipelines to surface DCOM-related DCE-RPC operations (IDispatch, IRemoteActivation, IRemUnknown, IObjectExporter) and endpoint-mapper connection pairs.

See the full Zeek script and pipelines in [references/detection-queries.md](references/detection-queries.md#step-6-network-level-dcom-detection-with-zeek).

### Step 7: DCOM Attack Surface Audit and Hardening

Audit DCOM exposure by enumerating Win32_DCOMApplication objects and checking launch permissions on high-risk CLSIDs (MMC20, ShellWindows, ShellBrowserWindow, Office apps), then harden via GPO, the EnableDCOM registry value, host firewall rules on port 135, and a restricted dynamic RPC port range.

See the full audit and hardening scripts in [references/detection-queries.md](references/detection-queries.md#step-7-dcom-attack-surface-audit-and-hardening).

## Key Concepts

| Term | Definition |
|------|------------|
| **DCOM (T1021.003)** | Distributed Component Object Model -- extends COM to allow remote object instantiation and method invocation over RPC, abused for lateral movement |
| **MMC20.Application** | COM object (CLSID {49B2791A-B1AE-4C90-9B8E-E860BA07F889}) controlling MMC snap-ins; `ExecuteShellCommand` method enables remote command execution |
| **ShellWindows** | COM object (CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}) that activates within an existing explorer.exe process, executing commands without creating a new COM server process |
| **ShellBrowserWindow** | COM object (CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}) similar to ShellWindows, uses `Document.Application.ShellExecute` for stealthy command execution |
| **RPC Endpoint Mapper** | Service on TCP port 135 that maps RPC interfaces to dynamic ports; all DCOM communication begins with an endpoint mapper query |
| **Sysmon Event ID 1** | Process Create event capturing parent-child process relationships, command lines, and user context -- critical for identifying DCOM-spawned processes |
| **Sysmon Event ID 3** | Network Connection event capturing source/destination IPs and ports -- used to correlate RPC connections with subsequent process creation |
| **DcomLaunch** | Windows service (svchost.exe -k DcomLaunch) that manages DCOM server process activation; parent process of COM servers spawned via remote DCOM calls |
| **WMI-Activity ETW** | Event Tracing for Windows provider that logs WMI method calls, instance creations, and queries -- provides visibility into DCOM-triggered WMI operations |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Sysmon** | Endpoint telemetry for process creation (EID 1), network connections (EID 3), and image loads (EID 7) essential for DCOM detection |
| **Splunk / Elastic SIEM** | Log aggregation and correlation platform for DCOM detection rules and threat hunting queries |
| **Microsoft Sentinel** | Cloud SIEM with built-in KQL queries and analytics rules for DCOM lateral movement detection |
| **Sigma** | Vendor-agnostic detection rule format for portable DCOM detection rules |
| **Zeek** | Network security monitor for DCE-RPC protocol analysis and RPC endpoint mapper traffic monitoring |
| **Atomic Red Team** | MITRE ATT&CK test framework with T1021.003 atomics for validating DCOM detection coverage |
| **Impacket (dcomexec.py)** | Python-based DCOM execution tool used by attackers and red teamers for testing DCOM lateral movement |
| **CIMSession / PowerShell** | Native Windows tooling for DCOM object instantiation used in both legitimate administration and attacks |

## Common Scenarios

### Scenario 1: MMC20.Application Lateral Movement to File Server

**Context**: A SOC analyst receives an alert for mmc.exe spawning cmd.exe on a file server (10.10.20.50) at 03:22 UTC. No administrator activity is scheduled at this time.

**Approach**:
1. Query Sysmon Event ID 1 on 10.10.20.50: confirm mmc.exe (parent: svchost.exe -k DcomLaunch) spawned cmd.exe with command line `/c net user /domain > C:\temp\users.txt`
2. Query Sysmon Event ID 3 on 10.10.20.50: identify inbound TCP connection on port 135 from 10.10.5.30 at 03:22:01, followed by a high-port connection at 03:22:02
3. Correlate Event ID 4624 on 10.10.20.50: find LogonType 3 from 10.10.5.30 at 03:22:00 with admin credentials
4. Investigate 10.10.5.30: check for compromise indicators -- find Mimikatz artifacts in memory, evidence of credential dumping at 03:15
5. Trace the attack chain: initial phishing compromise at 02:45, credential theft at 03:15, DCOM lateral movement at 03:22
6. Contain: isolate 10.10.5.30 and 10.10.20.50, force password reset for compromised admin account, block inbound RPC from non-admin subnets

**Pitfalls**:
- Dismissing mmc.exe activity as legitimate MMC administration without checking the parent process and command line
- Not correlating the network logon (4624) with the process creation to identify the true source host
- Failing to investigate the source host for initial compromise indicators

### Scenario 2: ShellWindows Stealthy Lateral Movement

**Context**: During a threat hunt, an analyst queries for explorer.exe spawning cmd.exe on domain controllers and finds several instances on DC01 with no interactive logon sessions.

**Approach**:
1. Verify no interactive sessions: query Event ID 4624 LogonType 2 or 10 on DC01 -- none found during the time window
2. Query Sysmon Event ID 1: explorer.exe spawning cmd.exe with encoded PowerShell commands at 14:05, 14:12, and 14:18
3. Decode the PowerShell: reveals reconnaissance commands (Get-ADUser, Get-ADGroup, Get-ADComputer)
4. Query Sysmon Event ID 3: inbound RPC connections from 10.10.3.15 preceding each process creation
5. Identify the ShellWindows pattern: no new mmc.exe or dllhost.exe process created -- commands execute through existing explorer.exe, consistent with ShellWindows/ShellBrowserWindow DCOM abuse
6. Investigate 10.10.3.15: compromised workstation with Cobalt Strike beacon artifacts

**Pitfalls**:
- Missing the attack because ShellWindows does not create a separate COM server process -- requires monitoring explorer.exe child processes
- Not having Sysmon Event ID 3 configured to capture network connections from explorer.exe
- Filtering out explorer.exe as a legitimate parent process without considering the server context

## Output Format

```
Hunt ID: TH-DCOM-[DATE]-[SEQ]
Alert Severity: High
MITRE Technique: T1021.003 (Remote Services: DCOM)

Source Host: [IP/Hostname of attacker's machine]
Target Host: [IP/Hostname where DCOM executed]
DCOM Object: [MMC20.Application | ShellWindows | ShellBrowserWindow]
CLSID: [COM object class identifier]

Process Chain:
  Parent: [svchost.exe -k DcomLaunch | explorer.exe | mmc.exe]
  Child:  [cmd.exe | powershell.exe | ...]
  Command Line: [Full command executed]

Network Indicators:
  RPC Connection: [Source IP]:port -> [Target IP]:135 at [timestamp]
  DCOM Port: [Source IP]:port -> [Target IP]:[high-port] at [timestamp]

Authentication Context:
  Event 4624: LogonType 3 from [Source IP] at [timestamp]
  Account: [Domain\Username]
  Logon ID: [Logon session identifier]

Risk Assessment: [Critical/High/Medium]
Recommended Action: [Isolate, investigate source, reset credentials, restrict DCOM]
```
