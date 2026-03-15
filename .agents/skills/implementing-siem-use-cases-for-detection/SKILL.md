---
name: implementing-siem-use-cases-for-detection
description: >
  Implements SIEM detection use cases by designing correlation rules, threshold alerts, and
  behavioral analytics mapped to MITRE ATT&CK techniques across Splunk, Elastic, and Sentinel.
  Use when SOC teams need to expand detection coverage, formalize use case lifecycle management,
  or build a detection library aligned to organizational threat profile.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, siem, use-cases, detection-engineering, mitre-attack, splunk, elastic, sentinel]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing SIEM Use Cases for Detection

## When to Use

Use this skill when:
- SOC teams need to build or expand their SIEM detection library from scratch
- Threat assessments identify ATT&CK technique gaps requiring new detection rules
- Detection engineers need a structured process for use case design, testing, and deployment
- Compliance requirements mandate specific detection capabilities (PCI DSS, HIPAA, SOX)

**Do not use** for ad-hoc hunting queries — use cases are formalized, tested, and maintained detection rules, not exploratory searches.

## Prerequisites

- SIEM platform (Splunk ES, Elastic Security, or Microsoft Sentinel) with production data
- ATT&CK Navigator for coverage gap analysis
- Log sources normalized to CIM/ECS field standards
- Use case documentation framework (wiki, Git repo, or detection engineering platform)
- Testing environment with attack simulation tools (Atomic Red Team, MITRE Caldera)

## Workflow

### Step 1: Assess Detection Coverage Gaps

Map current detection rules to ATT&CK and identify gaps:

```python
import json

# Load current detection rules mapped to ATT&CK
current_rules = [
    {"name": "Brute Force Detection", "techniques": ["T1110.001", "T1110.003"]},
    {"name": "Malware Hash Match", "techniques": ["T1204.002"]},
    {"name": "Suspicious PowerShell", "techniques": ["T1059.001"]},
]

# Load ATT&CK Enterprise techniques
with open("enterprise-attack.json") as f:
    attack = json.load(f)

all_techniques = set()
for obj in attack["objects"]:
    if obj["type"] == "attack-pattern":
        ext = obj.get("external_references", [])
        for ref in ext:
            if ref.get("source_name") == "mitre-attack":
                all_techniques.add(ref["external_id"])

covered = set()
for rule in current_rules:
    covered.update(rule["techniques"])

gaps = all_techniques - covered
print(f"Total techniques: {len(all_techniques)}")
print(f"Covered: {len(covered)} ({len(covered)/len(all_techniques)*100:.1f}%)")
print(f"Gaps: {len(gaps)}")

# Prioritize gaps by threat relevance
priority_techniques = [
    "T1003", "T1021", "T1053", "T1547", "T1078",
    "T1055", "T1071", "T1105", "T1036", "T1070"
]
priority_gaps = [t for t in priority_techniques if t in gaps]
print(f"Priority gaps: {priority_gaps}")
```

### Step 2: Design Use Case Specification

Document each use case with a standardized template:

```yaml
use_case_id: UC-2024-015
name: Credential Dumping via LSASS Access
description: Detects tools accessing LSASS process memory for credential extraction
mitre_attack:
  tactic: Credential Access (TA0006)
  technique: T1003.001 - LSASS Memory
  data_sources:
    - Process: OS API Execution (Sysmon EventCode 10)
    - Process: Process Access (Windows Security 4663)
log_sources:
  - index: sysmon, sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  - index: wineventlog, sourcetype: WinEventLog:Security
severity: High
confidence: Medium-High
false_positive_sources:
  - Antivirus products scanning LSASS
  - CrowdStrike Falcon sensor
  - Windows Defender ATP
  - SCCM client
tuning_notes: >
  Maintain exclusion list for known security tools that legitimately access LSASS.
  Review exclusions quarterly for newly deployed security products.
sla: Alert within 5 minutes of detection
owner: detection_engineering_team
status: Production
created: 2024-03-15
last_tested: 2024-03-15
```

### Step 3: Implement Detection Logic Across Platforms

**Splunk ES Correlation Search:**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes
  where Processes.process_name="lsass.exe"
  by Processes.dest, Processes.user, Processes.process_name,
     Processes.parent_process_name, Processes.parent_process
| `drop_dm_object_name(Processes)`
| lookup lsass_access_whitelist parent_process AS parent_process OUTPUT is_whitelisted
| where isnull(is_whitelisted) OR is_whitelisted!="true"
| `credential_dumping_lsass_filter`
```

Or using raw Sysmon data:
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1038", "0x1fffff", "0x40")
NOT [| inputlookup lsass_whitelist.csv | fields SourceImage]
| stats count, values(GrantedAccess) AS access_flags by Computer, SourceImage, SourceUser
| where count > 0
```

**Elastic Security EQL Rule:**
```eql
process where event.type == "access" and
  process.name == "lsass.exe" and
  not process.executable : (
    "?:\\Windows\\System32\\svchost.exe",
    "?:\\Windows\\System32\\csrss.exe",
    "?:\\Program Files\\CrowdStrike\\*",
    "?:\\ProgramData\\Microsoft\\Windows Defender\\*"
  )
```

**Microsoft Sentinel KQL Rule:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "lsass.exe"
| where ActionType == "ProcessAccessed"
| where InitiatingProcessFileName !in ("svchost.exe", "csrss.exe", "MsMpEng.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
```

### Step 4: Test with Attack Simulation

Validate detection rules using Atomic Red Team:

```bash
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# Execute T1003.001 - Credential Dumping
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,3

# Execute T1053.005 - Scheduled Task
Invoke-AtomicTest T1053.005 -TestNumbers 1

# Execute T1547.001 - Registry Run Key
Invoke-AtomicTest T1547.001 -TestNumbers 1,2
```

Verify detection in SIEM:
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
earliest=-1h
| stats count by Computer, SourceImage, GrantedAccess
| where count > 0
```

Document test results:
```
TEST RESULTS — UC-2024-015
Atomic Test T1003.001-1 (Mimikatz):      DETECTED (alert fired in 47s)
Atomic Test T1003.001-2 (ProcDump):      DETECTED (alert fired in 32s)
Atomic Test T1003.001-3 (Task Manager):  FALSE NEGATIVE (excluded by whitelist — expected)
False Positive Rate (7-day backtest):     2 events (CrowdStrike scan — added to whitelist)
```

### Step 5: Deploy and Monitor Use Case Health

Track detection rule effectiveness:

```spl
-- Use case firing frequency
index=notable
| stats count AS fires, dc(src) AS unique_sources,
        dc(dest) AS unique_dests
  by rule_name, status_label
| eval true_positive_rate = round(
    sum(eval(if(status_label="Resolved - True Positive", 1, 0))) /
    count * 100, 1)
| sort - fires
| table rule_name, fires, unique_sources, unique_dests, true_positive_rate

-- Detection latency monitoring
index=notable
| eval detection_latency = _time - orig_time
| stats avg(detection_latency) AS avg_latency_sec,
        perc95(detection_latency) AS p95_latency_sec
  by rule_name
| eval avg_latency_min = round(avg_latency_sec / 60, 1)
| sort - avg_latency_sec
```

### Step 6: Maintain Use Case Library

Establish lifecycle management for all detection use cases:

```
USE CASE LIFECYCLE
━━━━━━━━━━━━━━━━━━
1. PROPOSED    → New detection need identified (threat intel, gap analysis, incident finding)
2. DEVELOPMENT → Query written, false positive analysis, tuning
3. TESTING     → Atomic Red Team validation, 7-day backtest
4. STAGING     → Deployed in alert-only mode (no incident creation) for 14 days
5. PRODUCTION  → Full production with incident creation and SOAR integration
6. REVIEW      → Quarterly review of effectiveness, false positive rate, relevance
7. DEPRECATED  → Technique no longer relevant or replaced by better detection
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Use Case** | Formalized detection rule with documented logic, testing, tuning, and lifecycle management |
| **Detection Engineering** | Practice of designing, testing, and maintaining SIEM detection rules as a software development discipline |
| **Correlation Search** | SIEM query that combines events from multiple sources to identify attack patterns |
| **False Positive Rate** | Percentage of alerts that are benign activity — target <20% for production use cases |
| **Detection Latency** | Time between event occurrence and alert generation — target <5 minutes for critical detections |
| **ATT&CK Coverage** | Percentage of relevant ATT&CK techniques with at least one production detection rule |

## Tools & Systems

- **Splunk ES**: Enterprise SIEM with correlation searches, risk-based alerting, and Incident Review
- **Elastic Security**: SIEM with detection rules, EQL sequences, and ML-based anomaly detection
- **Microsoft Sentinel**: Cloud SIEM with KQL analytics rules, Fusion ML engine, and Lighthouse multi-tenant
- **Atomic Red Team**: Open-source attack simulation framework for testing detection rules against ATT&CK techniques
- **ATT&CK Navigator**: MITRE visualization tool for mapping and tracking detection coverage across techniques

## Common Scenarios

- **Post-Incident Use Case**: After a ransomware incident, build detection for the initial access vector discovered during investigation
- **Compliance-Driven**: PCI DSS requires detection of admin account misuse — build use cases for 4672/4720/4732 events
- **Threat-Intel Driven**: New APT group targets your sector — build use cases for their documented TTPs
- **Red Team Findings**: Purple team exercise identifies blind spots — convert findings into production detection rules
- **SIEM Migration**: Migrating from QRadar to Splunk — convert and validate all existing use cases on new platform

## Output Format

```
USE CASE DEPLOYMENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━
Quarter:      Q1 2024
Total Use Cases: 147 (Production: 128, Staging: 12, Development: 7)

New Deployments This Quarter:
  UC-2024-012  Kerberoasting Detection (T1558.003)     — Production
  UC-2024-013  DLL Side-Loading (T1574.002)            — Production
  UC-2024-014  Scheduled Task Persistence (T1053.005)  — Production
  UC-2024-015  LSASS Memory Access (T1003.001)         — Staging

ATT&CK Coverage:
  Overall: 67% of relevant techniques (up from 61%)
  Initial Access:      78%
  Execution:           82%
  Persistence:         71%
  Credential Access:   65%
  Lateral Movement:    58% (priority gap area)

Health Metrics:
  Avg True Positive Rate:    74% (target: >70%)
  Avg Detection Latency:     2.3 min (target: <5 min)
  Use Cases Deprecated:      3 (replaced by improved versions)
```
