---
name: implementing-siem-correlation-rules-for-apt
description: >-
  Write multi-event correlation rules that detect APT lateral movement by chaining Windows authentication events,
  process execution telemetry, and network connection logs across hosts. Uses Splunk SPL and Sigma rule format
  to correlate Event IDs 4624, 4648, 4688, and Sysmon Events 1/3 within sliding time windows to surface attack
  sequences invisible to single-event detections.
domain: cybersecurity
subdomain: security-operations
tags: [implementing, siem, correlation, rules]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install requests pyyaml sigma-cli`
2. Connect to the Splunk REST API and define correlation searches that chain multiple event types across hosts.
3. Build Sigma rules in YAML that express multi-step detection logic for lateral movement patterns:
   - RDP logon (4624 LogonType=10) followed by service installation (7045) on same target within 15 minutes
   - Pass-the-Hash: NTLM logon (4624 LogonType=3) followed by process creation (4688) of admin tools
   - PsExec-style: Named pipe creation (Sysmon 17/18) correlated with remote service creation (7045)
4. Convert Sigma rules to Splunk SPL using `sigma-cli convert`.
5. Deploy correlation searches to Splunk ES via the REST API.
6. Run the agent to generate and install correlation rules, then audit existing rules for coverage gaps.

```bash
python scripts/agent.py --splunk-url https://localhost:8089 --username admin --password changeme --output correlation_report.json
```

## Examples

### Detect RDP Lateral Movement Chain
```
index=wineventlog (EventCode=4624 Logon_Type=10) OR (EventCode=7045)
| transaction Computer maxspan=15m startswith=(EventCode=4624) endswith=(EventCode=7045)
| where eventcount >= 2
| table _time Computer Account_Name ServiceName
```

### Sigma Rule for PsExec Lateral Movement
```yaml
title: PsExec Lateral Movement Detection
logsource:
  product: windows
  service: sysmon
detection:
  pipe_created:
    EventID: 17
    PipeName|startswith: '\PSEXESVC'
  service_installed:
    EventID: 7045
    ServiceFileName|contains: 'PSEXESVC'
  timeframe: 5m
  condition: pipe_created | near service_installed
level: high
```
