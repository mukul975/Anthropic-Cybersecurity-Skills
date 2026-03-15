---
name: detecting-dll-sideloading-attacks
description: Detect DLL side-loading attacks where adversaries place malicious DLLs alongside legitimate applications to hijack execution flow for defense evasion.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, mitre-attack, dll-sideloading, defense-evasion, t1574, edr, proactive-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting DLL Sideloading Attacks

## When to Use

- When investigating potential DLL hijacking in enterprise environments
- After EDR alerts on unsigned DLLs loaded by signed applications
- When hunting for APT persistence using legitimate application wrappers
- During incident response to identify trojanized applications
- When threat intel indicates DLL sideloading campaigns targeting specific software

## Prerequisites

- EDR with DLL load monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon Event ID 7 (Image Loaded) with hash verification
- Application whitelisting or DLL integrity monitoring
- Software inventory of legitimate applications and expected DLL paths
- Code signing verification capabilities

## Workflow

1. **Identify Sideloading Targets**: Research known vulnerable applications that load DLLs without full path qualification (LOLBAS, DLL-sideload databases).
2. **Monitor DLL Load Events**: Query Sysmon Event ID 7 for DLL loads where the DLL path differs from the application's expected directory.
3. **Check DLL Signatures**: Flag unsigned or untrusted DLLs loaded by signed executables.
4. **Detect Path Anomalies**: Identify legitimate executables running from unusual locations (Temp, AppData, Public) that may be decoy wrappers.
5. **Hash Verification**: Compare loaded DLL hashes against known-good versions and threat intel feeds.
6. **Correlate with Process Behavior**: Check if the host process exhibits unusual behavior (network connections, child processes) after loading the suspicious DLL.
7. **Document and Remediate**: Report sideloading instances, quarantine malicious DLLs, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1574.002 | DLL Side-Loading |
| T1574.001 | DLL Search Order Hijacking |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order Hijacking |
| DLL Search Order | Windows DLL loading priority path |
| Side-Loading | Placing malicious DLL where legitimate app loads it |
| Phantom DLL | DLL that legitimate apps try to load but does not exist |
| DLL Proxying | Malicious DLL forwarding calls to legitimate DLL |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Event ID 7 DLL load monitoring |
| CrowdStrike Falcon | DLL load detection with process context |
| Microsoft Defender for Endpoint | DLL load anomaly detection |
| Process Monitor | Real-time DLL load tracing |
| DLL Export Viewer | Verify DLL export functions |
| Sigcheck | Digital signature verification |
| pe-sieve | PE analysis for proxied DLLs |

## Common Scenarios

1. **Legitimate App Wrapper**: Adversary copies signed application (e.g., OneDrive updater) to temp folder alongside malicious DLL with same name as expected dependency.
2. **Phantom DLL Exploitation**: Malicious DLL placed in PATH location where legitimate app searches for non-existent DLL.
3. **DLL Proxy Loading**: Malicious version.dll proxies all exports to real version.dll while executing malicious code on DllMain.
4. **Software Update Hijack**: Attacker replaces DLL in update staging directory before legitimate updater loads it.

## Output Format

```
Hunt ID: TH-SIDELOAD-[DATE]-[SEQ]
Technique: T1574.002
Host Application: [Legitimate signed executable]
Sideloaded DLL: [Malicious DLL name and path]
Expected DLL Path: [Where DLL should legitimately be]
DLL Signed: [Yes/No]
App Location: [Expected/Anomalous]
Host: [Hostname]
Risk Level: [Critical/High/Medium/Low]
```
