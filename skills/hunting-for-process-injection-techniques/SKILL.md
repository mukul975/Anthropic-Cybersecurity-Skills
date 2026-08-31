---
name: hunting-for-process-injection-techniques
description: Detects process injection techniques (MITRE T1055) - including CreateRemoteThread injection, process hollowing, and DLL injection - by analyzing Sysmon Event IDs 8 (CreateRemoteThread) and 10 (ProcessAccess) alongside EDR process telemetry. Use when hunting for in-memory code injection or defense evasion via legitimate process abuse on Windows endpoints, correlating Sysmon with EDR data. Do not use for full Sysmon Event ID 1/7/8/10/25 coverage and Sysmon config validation - use detecting-t1055-process-injection-with-sysmon.
domain: cybersecurity
subdomain: threat-hunting
tags:
- process-injection
- t1055
- sysmon
- createremotethread
- dll-injection
- edr
- threat-hunting
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
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
- T1055
---

# Hunting for Process Injection Techniques

## Overview

Process injection (MITRE ATT&CK T1055) allows adversaries to execute code in the address space of another process, enabling defense evasion and privilege escalation. This skill detects injection techniques via Sysmon Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess with suspicious access rights), and analysis of source-target process relationships to distinguish legitimate from malicious injection.


## When to Use

- When investigating security incidents that require hunting for process injection techniques
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Sysmon installed with Event IDs 8 and 10 enabled
- Process creation logs (Sysmon Event ID 1 or Windows 4688)
- Python 3.8+ with standard library
- JSON-formatted Sysmon event logs

## Steps

1. **Parse Sysmon Events** — Ingest Event IDs 1, 8, and 10 from JSON log files
2. **Detect CreateRemoteThread** — Flag Event ID 8 with suspicious source-target process pairs
3. **Analyze ProcessAccess Rights** — Identify Event ID 10 with dangerous access masks (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)
4. **Build Process Relationship Graph** — Map source-to-target injection relationships
5. **Filter Known Legitimate Pairs** — Exclude known benign injection patterns (AV, debuggers, system processes)
6. **Score Injection Severity** — Apply risk scoring based on source process, target process, and access rights
7. **Generate Hunt Report** — Produce structured report with MITRE sub-technique mapping

## Expected Output

- JSON report of detected injection events with severity scores
- Process injection relationship graph
- MITRE ATT&CK sub-technique mapping (T1055.001-T1055.012)
- False positive exclusion recommendations
