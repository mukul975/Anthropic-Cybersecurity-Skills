---
name: performing-purple-team-exercise
description: >
  Performs purple team exercises by coordinating red team adversary emulation with blue team
  detection validation using MITRE ATT&CK-mapped attack scenarios, real-time detection testing,
  and collaborative gap remediation. Use when SOC teams need to validate detection capabilities,
  improve analyst skills, and close detection gaps through structured offensive-defensive collaboration.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, purple-team, red-team, blue-team, mitre-attack, adversary-emulation, detection-validation]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Purple Team Exercise

## When to Use

Use this skill when:
- SOC teams need to validate that detection rules actually fire for the threats they target
- Red team assessments produced findings that need translation into detection improvements
- New detection tools or SIEM migrations require validation of detection coverage
- Analyst training requires hands-on experience with real attack techniques and SIEM responses
- Quarterly or semi-annual detection validation cycles are scheduled

**Do not use** for unannounced red team engagements — purple team exercises require explicit coordination between offensive and defensive teams with real-time collaboration.

## Prerequisites

- Red team capability: internal team or contracted purple team operator
- Attack simulation tools: Atomic Red Team, MITRE Caldera, or C2 framework (authorized)
- SIEM access for real-time alert monitoring during exercise
- ATT&CK-mapped detection rule inventory with expected alert names
- Isolated test environment or approved production scope with change management approval
- Communication channel (Slack/Teams) for real-time red-blue coordination

## Workflow

### Step 1: Define Exercise Scope and Objectives

Document exercise parameters:

```yaml
purple_team_exercise:
  exercise_id: PT-2024-Q1
  date: 2024-03-20
  duration: 8 hours (09:00-17:00 UTC)
  scope:
    environment: Production (Finance VLAN, 10.0.5.0/24)
    systems_in_scope:
      - WORKSTATION-TEST01 (10.0.5.100) — Test endpoint
      - DC-TEST (10.0.5.200) — Test domain controller
      - FILESERVER-TEST (10.0.5.201) — Test file server
    systems_excluded:
      - All production domain controllers
      - Customer-facing systems
  objectives:
    - Validate 15 detection rules mapped to FIN7 TTPs
    - Test SOC analyst response to real attack indicators
    - Identify detection gaps for credential access and lateral movement
    - Measure detection latency for each technique
  threat_scenario: FIN7 campaign targeting financial data via spearphishing
  authorization: Approved by CISO, Change Request CR-2024-0567
  communication: #purple-team-2024q1 Slack channel
```

### Step 2: Build ATT&CK-Mapped Test Plan

Create technique-by-technique test matrix:

| # | ATT&CK ID | Technique | Test Tool | Expected Detection | Blue Team Metric |
|---|-----------|-----------|-----------|-------------------|------------------|
| 1 | T1566.001 | Spearphishing Attachment | Manual email | Email gateway alert | Detection Y/N, latency |
| 2 | T1204.002 | User Execution | Macro document | Sysmon process creation | Detection Y/N, latency |
| 3 | T1059.001 | PowerShell | Atomic RT #1-3 | PowerShell execution alert | Detection Y/N, latency |
| 4 | T1053.005 | Scheduled Task | Atomic RT | Scheduled task creation alert | Detection Y/N, latency |
| 5 | T1547.001 | Registry Run Keys | Atomic RT | Registry modification alert | Detection Y/N, latency |
| 6 | T1003.001 | LSASS Memory | Mimikatz | Credential dumping alert | Detection Y/N, latency |
| 7 | T1550.002 | Pass-the-Hash | Mimikatz | NTLM anomaly detection | Detection Y/N, latency |
| 8 | T1021.002 | SMB/PsExec | PsExec | PsExec service creation alert | Detection Y/N, latency |
| 9 | T1047 | WMI | wmic /node | WMI remote execution alert | Detection Y/N, latency |
| 10| T1021.001 | RDP | xfreerdp | RDP lateral movement alert | Detection Y/N, latency |
| 11| T1071.001 | Web C2 | Cobalt Strike | C2 beacon detection | Detection Y/N, latency |
| 12| T1041 | Exfiltration C2 | Rclone | Data exfiltration alert | Detection Y/N, latency |
| 13| T1490 | Inhibit Recovery | vssadmin | Shadow copy deletion alert | Detection Y/N, latency |
| 14| T1486 | Data Encrypted | Test encryption | Mass encryption detection | Detection Y/N, latency |
| 15| T1070.001 | Clear Logs | wevtutil | Log clearing detection | Detection Y/N, latency |

### Step 3: Execute Red Team Techniques

Run each technique with Atomic Red Team (or manual execution):

```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# Test 1: T1059.001 — PowerShell Execution
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Executing T1059.001 - PowerShell"
Invoke-AtomicTest T1059.001 -TestNumbers 1
# Notify blue team: "T1059.001 executed at $(Get-Date)"

# Test 2: T1053.005 — Scheduled Task Creation
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Executing T1053.005 - Scheduled Task"
Invoke-AtomicTest T1053.005 -TestNumbers 1

# Test 3: T1547.001 — Registry Run Key
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Executing T1547.001 - Registry Persistence"
Invoke-AtomicTest T1547.001 -TestNumbers 1,2

# Test 4: T1003.001 — Credential Dumping
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Executing T1003.001 - LSASS Access"
Invoke-AtomicTest T1003.001 -TestNumbers 1,2

# Test 5: T1490 — Shadow Copy Deletion
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Executing T1490 - Inhibit Recovery"
Invoke-AtomicTest T1490 -TestNumbers 1

# Cleanup after each test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1,2 -Cleanup
```

### Step 4: Monitor Blue Team Detection in Real-Time

Blue team monitors SIEM during execution:

```spl
--- Real-time purple team monitoring dashboard
index=notable earliest=-1h
| where Computer IN ("WORKSTATION-TEST01", "DC-TEST", "FILESERVER-TEST")
  OR src IN ("10.0.5.100", "10.0.5.200", "10.0.5.201")
| eval detection_latency = _time - orig_time
| eval latency_seconds = round(detection_latency, 0)
| sort _time
| table _time, rule_name, urgency, src, dest, user, latency_seconds

--- Check specific technique detection
index=sysmon Computer="WORKSTATION-TEST01" earliest=-15m
(EventCode=1 OR EventCode=3 OR EventCode=10 OR EventCode=11 OR EventCode=13)
| sort _time
| table _time, EventCode, Image, CommandLine, TargetFilename, TargetObject
```

Record results in real-time:

```python
exercise_results = {
    "exercise_id": "PT-2024-Q1",
    "results": [
        {
            "technique": "T1059.001",
            "name": "PowerShell Execution",
            "execution_time": "09:15:00",
            "detected": True,
            "alert_name": "Suspicious PowerShell Encoded Command",
            "detection_time": "09:15:47",
            "latency_seconds": 47,
            "notes": "Detected via Sysmon EventCode 1 with encoded command pattern"
        },
        {
            "technique": "T1003.001",
            "name": "LSASS Memory Access",
            "execution_time": "10:30:00",
            "detected": False,
            "alert_name": None,
            "detection_time": None,
            "latency_seconds": None,
            "notes": "GAP: No detection rule for LSASS access. Sysmon EventCode 10 present but no correlation rule."
        }
    ]
}
```

### Step 5: Collaborative Gap Remediation

For each gap, the blue team builds detection rules immediately:

```spl
--- Gap: T1003.001 — No LSASS access detection
--- Build rule during exercise
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1038", "0x1fffff", "0x40")
NOT SourceImage IN ("*\\svchost.exe", "*\\csrss.exe", "*\\MsMpEng.exe")
| stats count by Computer, SourceImage, SourceUser, GrantedAccess
| where count > 0
```

After building, re-test:
```
Red Team: "Re-executing T1003.001 at 11:45"
Blue Team: "Confirmed — alert 'LSASS Memory Access Detected' fired at 11:45:32 (32s latency)"
Result: GAP CLOSED
```

### Step 6: Generate Exercise Report

```python
def generate_purple_team_report(results):
    total = len(results["results"])
    detected = sum(1 for r in results["results"] if r["detected"])
    gaps = sum(1 for r in results["results"] if not r["detected"])
    avg_latency = sum(r["latency_seconds"] for r in results["results"]
                      if r["latency_seconds"]) / max(detected, 1)

    report = f"""
PURPLE TEAM EXERCISE REPORT — {results['exercise_id']}
{'=' * 60}

SUMMARY:
  Techniques Tested:     {total}
  Detected:              {detected} ({detected/total*100:.0f}%)
  Gaps Identified:       {gaps} ({gaps/total*100:.0f}%)
  Avg Detection Latency: {avg_latency:.0f} seconds

DETAILED RESULTS:
"""
    for r in results["results"]:
        status = "DETECTED" if r["detected"] else "GAP"
        latency = f"{r['latency_seconds']}s" if r["latency_seconds"] else "N/A"
        report += f"  [{status}] {r['technique']} — {r['name']} (Latency: {latency})\n"
        if not r["detected"]:
            report += f"          Action: {r['notes']}\n"

    return report
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Purple Team** | Collaborative exercise where red (offensive) and blue (defensive) teams work together to validate and improve detection |
| **Adversary Emulation** | Structured simulation of specific threat actor TTPs for testing defensive capabilities |
| **Detection Validation** | Process of confirming that detection rules fire correctly when the targeted technique is executed |
| **Detection Latency** | Time between technique execution and SIEM alert generation — measured during purple team exercises |
| **Gap Remediation** | Immediate creation or tuning of detection rules for techniques that were not detected during testing |
| **Atomic Red Team** | Open-source library of small, focused tests for individual ATT&CK techniques |

## Tools & Systems

- **Atomic Red Team**: Open-source attack test library from Red Canary for technique-by-technique validation
- **MITRE Caldera**: Automated adversary emulation platform supporting ATT&CK-mapped attack chains
- **Vectr**: Purple team management platform for tracking exercise results and detection coverage improvements
- **Prelude Operator**: Adversary emulation tool supporting automated multi-step attack scenarios
- **AttackIQ**: Breach and Attack Simulation (BAS) platform for continuous detection validation

## Common Scenarios

- **Quarterly Validation**: Test top 20 detection rules against ATT&CK techniques to ensure continued effectiveness
- **New Tool Validation**: After deploying new EDR, validate detection coverage against baseline techniques
- **Analyst Training**: Junior analysts observe real attacks in real-time with expert guidance on SIEM investigation
- **Post-Incident Validation**: After a real incident, emulate the attack chain to verify detection improvements
- **Compliance Evidence**: Document detection validation results for SOC 2, ISO 27001, or PCI DSS audits

## Output Format

```
PURPLE TEAM EXERCISE REPORT — PT-2024-Q1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Date:         2024-03-20 (09:00-17:00 UTC)
Scenario:     FIN7 Financial Sector Campaign
Scope:        Finance VLAN (10.0.5.0/24)

RESULTS:
  Techniques Tested:     15
  Detected:              11 (73%)
  Gaps Identified:       4 (27%)
  Gaps Remediated Same Day: 3
  Avg Detection Latency: 38 seconds

DETAILED RESULTS:
  [PASS]  T1566.001 Spearphishing Attachment      — 12s latency
  [PASS]  T1204.002 User Execution (Macro)         — 8s latency
  [PASS]  T1059.001 PowerShell Execution            — 47s latency
  [PASS]  T1053.005 Scheduled Task                  — 23s latency
  [PASS]  T1547.001 Registry Run Keys               — 31s latency
  [FAIL]  T1003.001 LSASS Memory Access             — REMEDIATED during exercise
  [FAIL]  T1550.002 Pass-the-Hash                   — REMEDIATED during exercise
  [PASS]  T1021.002 PsExec                          — 15s latency
  [PASS]  T1047 WMI Remote Execution                — 42s latency
  [PASS]  T1021.001 RDP Lateral Movement            — 28s latency
  [FAIL]  T1071.001 Web C2 Beaconing                — REMEDIATED during exercise
  [PASS]  T1041 Exfiltration over C2                — 67s latency
  [PASS]  T1490 Shadow Copy Deletion                — 5s latency
  [FAIL]  T1486 Data Encryption for Impact          — OPEN — requires endpoint telemetry
  [PASS]  T1070.001 Event Log Clearing              — 11s latency

POST-EXERCISE COVERAGE: 93% (14/15) — up from 73% at start
REMAINING GAP: T1486 requires EDR file monitoring enhancement
```
