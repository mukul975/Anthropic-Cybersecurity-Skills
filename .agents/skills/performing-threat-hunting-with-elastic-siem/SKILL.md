---
name: performing-threat-hunting-with-elastic-siem
description: >
  Performs proactive threat hunting in Elastic Security SIEM using KQL/EQL queries, detection rules,
  and Timeline investigation to identify threats that evade automated detection. Use when SOC teams
  need to hunt for specific ATT&CK techniques, investigate anomalous behaviors, or validate detection
  coverage gaps using Elasticsearch and Kibana Security.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, elastic, siem, threat-hunting, kql, eql, mitre-attack, kibana]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Threat Hunting with Elastic SIEM

## When to Use

Use this skill when:
- SOC teams need to proactively search for threats not caught by existing detection rules
- Threat intelligence reports describe new TTPs requiring validation against historical data
- Red team exercises reveal detection gaps that need hunting query development
- Periodic hunting cadence requires structured hypothesis-driven investigations

**Do not use** for real-time alert triage — that belongs in the Elastic Security Alerts queue with automated detection rules.

## Prerequisites

- Elastic Security 8.x+ with Security app enabled in Kibana
- Data ingestion via Elastic Agent (Endpoint Security integration) or Beats (Winlogbeat, Filebeat, Packetbeat)
- Data normalized to Elastic Common Schema (ECS) field mappings
- User role with `kibana_security_solution` and `read` access to relevant indices
- MITRE ATT&CK framework knowledge for hypothesis generation

## Workflow

### Step 1: Develop Hunting Hypothesis

Start with a hypothesis based on threat intelligence, ATT&CK technique, or anomaly:

**Example Hypothesis**: "Attackers are using living-off-the-land binaries (LOLBins) for execution, specifically certutil.exe for file downloads (T1105 — Ingress Tool Transfer)."

Define scope:
- **Data sources**: `logs-endpoint.events.process-*`, `logs-windows.sysmon_operational-*`
- **Time range**: Last 30 days
- **Expected indicators**: certutil.exe with `-urlcache`, `-split`, or `-decode` flags

### Step 2: Hunt Using KQL in Discover

Open Kibana Discover and query with KQL (Kibana Query Language):

```kql
process.name: "certutil.exe" and process.args: ("-urlcache" or "-split" or "-decode" or "-encode" or "-verifyctl")
```

Refine to exclude known legitimate use:

```kql
process.name: "certutil.exe"
  and process.args: ("-urlcache" or "-split" or "-decode")
  and not process.parent.name: ("sccm*.exe" or "ccmexec.exe")
  and not user.name: "SYSTEM"
```

For PowerShell-based hunting with encoded commands (T1059.001):

```kql
process.name: "powershell.exe"
  and process.args: ("-enc" or "-encodedcommand" or "-e " or "frombase64string" or "iex" or "invoke-expression")
  and not process.parent.executable: "C:\\Windows\\System32\\svchost.exe"
```

### Step 3: Use EQL for Sequence Detection

Elastic Event Query Language (EQL) enables hunting for multi-step attack sequences:

**Detect parent-child process anomalies (T1055 — Process Injection):**

```eql
sequence by host.name with maxspan=5m
  [process where event.type == "start" and process.name == "explorer.exe"]
  [process where event.type == "start" and process.parent.name == "explorer.exe"
    and process.name in ("cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe")]
```

**Detect credential dumping sequence (T1003):**

```eql
sequence by host.name with maxspan=2m
  [process where event.type == "start"
    and process.name in ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe")
    and process.args : "*lsass*"]
  [file where event.type == "creation"
    and file.extension in ("dmp", "dump", "bin")]
```

**Detect lateral movement via PsExec (T1021.002):**

```eql
sequence by source.ip with maxspan=1m
  [authentication where event.outcome == "success" and winlog.logon.type == "Network"]
  [process where event.type == "start"
    and process.name == "psexesvc.exe"]
```

### Step 4: Investigate with Elastic Security Timeline

Create a Timeline investigation in Elastic Security for collaborative analysis:

1. Navigate to **Security > Timelines > Create new timeline**
2. Add events from hunting queries using "Add to timeline" from Discover
3. Pin critical events and add investigation notes
4. Use the Timeline query bar for additional filtering:

```kql
host.name: "WORKSTATION-042" and event.category: ("process" or "network" or "file")
```

Add columns for key fields: `@timestamp`, `event.action`, `process.name`, `process.args`, `user.name`, `source.ip`, `destination.ip`

### Step 5: Build Detection Rules from Findings

Convert successful hunting queries into Elastic detection rules:

```json
{
  "name": "Certutil Download Activity",
  "description": "Detects certutil.exe used for file download, a common LOLBin technique",
  "risk_score": 73,
  "severity": "high",
  "type": "eql",
  "query": "process where event.type == \"start\" and process.name == \"certutil.exe\" and process.args : (\"-urlcache\", \"-split\", \"-decode\") and not process.parent.name : (\"ccmexec.exe\", \"sccm*.exe\")",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0011",
        "name": "Command and Control"
      },
      "technique": [
        {
          "id": "T1105",
          "name": "Ingress Tool Transfer"
        }
      ]
    }
  ],
  "tags": ["Hunting", "LOLBins", "T1105"],
  "interval": "5m",
  "from": "now-6m",
  "enabled": true
}
```

Deploy via Elastic Security API:

```bash
curl -X POST "https://kibana:5601/api/detection_engine/rules" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -d @certutil_rule.json
```

### Step 6: Aggregate and Visualize Findings

Create hunting dashboard with aggregations:

```json
GET logs-endpoint.events.process-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"term": {"process.name": "certutil.exe"}},
        {"range": {"@timestamp": {"gte": "now-30d"}}}
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": {"field": "host.name", "size": 20},
      "aggs": {
        "by_user": {
          "terms": {"field": "user.name", "size": 10}
        },
        "by_args": {
          "terms": {"field": "process.args", "size": 10}
        }
      }
    }
  }
}
```

### Step 7: Document Hunt and Close Loop

Record findings in a structured hunt report and update detection coverage:

- Hypothesis validated or refuted
- IOCs and affected hosts discovered
- Detection rules created or updated
- ATT&CK Navigator layer updated with new coverage
- Recommendations for security control improvements

## Key Concepts

| Term | Definition |
|------|-----------|
| **KQL** | Kibana Query Language — simplified query syntax for filtering data in Kibana Discover and dashboards |
| **EQL** | Event Query Language — Elastic's sequence-aware query language for detecting multi-step attack patterns |
| **ECS** | Elastic Common Schema — standardized field naming convention enabling cross-source correlation |
| **Timeline** | Elastic Security investigation workspace for collaborative event analysis and annotation |
| **Hypothesis-Driven Hunting** | Structured approach starting with a theory about attacker behavior, tested against telemetry data |
| **LOLBins** | Living Off the Land Binaries — legitimate Windows tools (certutil, mshta, rundll32) abused by attackers |

## Tools & Systems

- **Elastic Security**: SIEM platform built on Elasticsearch with detection rules, Timeline, and case management
- **Elastic Agent**: Unified data collection agent replacing Beats for endpoint and network telemetry
- **Elastic Endpoint Security**: EDR capabilities integrated into Elastic Agent for process, file, and network monitoring
- **ATT&CK Navigator**: MITRE tool for tracking detection and hunting coverage across the ATT&CK matrix

## Common Scenarios

- **LOLBin Abuse**: Hunt for mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe with suspicious arguments
- **Persistence Mechanisms**: Query for scheduled task creation, registry run key modification, WMI subscriptions
- **C2 Beaconing**: Analyze network flow data for periodic outbound connections with consistent intervals
- **Data Staging**: Hunt for large file compression (7z, rar, zip) followed by outbound transfers
- **Account Manipulation**: Search for net.exe user creation, group membership changes, or password resets by non-admin users

## Output Format

```
THREAT HUNT REPORT — TH-2024-012
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Hypothesis:   Attackers using certutil.exe for tool download (T1105)
Period:       2024-02-15 to 2024-03-15
Data Sources: Elastic Endpoint (process events), Sysmon

Findings:
  Total certutil executions:     342
  With -urlcache flag:           12 (3.5%)
  Suspicious (non-SCCM):        3 confirmed anomalous

Affected Hosts:
  WORKSTATION-042 (Finance)  — certutil downloading payload.exe from external IP
  SERVER-DB-03 (Database)    — certutil decoding base64 encoded binary
  LAPTOP-EXEC-07 (Executive) — certutil downloading script from Pastebin

Actions Taken:
  [DONE] 3 hosts isolated for forensic investigation
  [DONE] Detection rule "Certutil Download Activity" deployed (ID: elastic-th012)
  [DONE] ATT&CK Navigator updated: T1105 coverage = GREEN

Verdict:      HYPOTHESIS CONFIRMED — 3 true positive findings escalated to IR
```
