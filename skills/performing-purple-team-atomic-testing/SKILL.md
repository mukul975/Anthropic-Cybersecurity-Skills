---
name: performing-purple-team-atomic-testing
description: 'Executes Atomic Red Team tests mapped to MITRE ATT&CK techniques, performs
  coverage gap analysis across the ATT&CK matrix, and runs detection validation loops
  to measure blue team visibility. Covers Invoke-AtomicRedTeam PowerShell execution,
  ATT&CK Navigator layer generation for heatmaps, Sigma rule correlation, and continuous
  atomic testing pipelines. Activates for requests involving purple team exercises,
  atomic test execution, ATT&CK coverage assessment, detection engineering validation,
  or adversary emulation testing.

  '
domain: cybersecurity
subdomain: purple-team
tags:
- purple-team
- atomic-red-team
- mitre-attack
- detection-engineering
- adversary-emulation
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- ID.RA-01
- DE.AE-07
- GV.OV-02
mitre_attack:
- T1078
- T1190
- T1059
---

# Performing Purple Team Atomic Testing

## When to Use

- Validating detection coverage against specific MITRE ATT&CK techniques
- Running purple team exercises using Atomic Red Team test library
- Performing ATT&CK coverage gap analysis to identify blind spots in SIEM/EDR
- Building a detection validation loop: execute atomic test, check SIEM, tune rule, retest
- Generating ATT&CK Navigator heatmap layers for executive reporting
- Automating continuous atomic testing in CI/CD or scheduled pipelines
- Mapping threat intelligence reports to executable atomic tests

**Do not use** for full-scope red team engagements requiring custom implants or live adversary simulation beyond atomic tests; use Caldera, SCYTHE, or Cobalt Strike for advanced adversary emulation.

**DISCLAIMER**: Atomic Red Team tests execute real attack techniques. Run only on systems you own or have explicit written authorization to test. Many tests modify system state, create artifacts, or trigger security alerts. Always execute cleanup commands after testing. Never run atomic tests in production without risk acceptance from stakeholders.

## Prerequisites

- Windows host with PowerShell 5.1+ or PowerShell Core 7+ (Linux/macOS supported for cross-platform atomics)
- Invoke-AtomicRedTeam PowerShell module installed from PSGallery
- Atomic Red Team atomics repository cloned locally
- SIEM/EDR with log ingestion from test endpoints (Splunk, Elastic, Microsoft Sentinel, CrowdStrike)
- MITRE ATT&CK Navigator (web-based or local instance) for layer visualization
- Python 3.9+ with `mitreattack-python`, `pyyaml`, and `requests` for automation scripts
- Sigma rules repository for detection correlation
- Administrative/root access on test endpoints
- Isolated test environment (lab, sandbox, or dedicated test range)

## Workflow

### Step 1: Install and Configure Invoke-AtomicRedTeam

Set up the execution framework and download the atomics library:

```powershell
# Install the PowerShell execution module
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
Install-Module -Name powershell-yaml -Scope CurrentUser -Force

# Import the module
Import-Module invoke-atomicredteam

# Install atomics to default location (C:\AtomicRedTeam\atomics)
IEX (IEX (New-Object System.Net.WebClient).DownloadString(
    'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
)); Install-AtomicRedTeam -getAtomics -Force

# Verify installation - list available techniques
$atomicsPath = "C:\AtomicRedTeam\atomics"
$techniques = Get-ChildItem $atomicsPath -Directory | Where-Object { $_.Name -match '^T\d{4}' }
Write-Host "Available techniques: $($techniques.Count)"

# Configure execution logging
$env:ARTLOG = "C:\AtomicRedTeam\logs"
if (-not (Test-Path $env:ARTLOG)) { New-Item -Path $env:ARTLOG -ItemType Directory }
```

### Step 2: Enumerate and Select Atomic Tests

Inventory available tests and select targets based on threat intelligence or gap analysis:

```powershell
# List all tests for a specific technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Show full details including attack commands and cleanup
Invoke-AtomicTest T1059.001 -ShowDetails

# List tests for a tactic (e.g., Persistence)
$persistenceTechniques = @(
    "T1547.001",  # Boot or Logon Autostart - Registry Run Keys
    "T1053.005",  # Scheduled Task
    "T1136.001",  # Create Account - Local Account
    "T1543.003",  # Create or Modify System Process - Windows Service
    "T1546.001",  # Event Triggered Execution - Change Default File Association
    "T1574.001",  # Hijack Execution Flow - DLL Search Order Hijacking
    "T1197"       # BITS Jobs
)

foreach ($tech in $persistenceTechniques) {
    Write-Host "`n=== $tech ===" -ForegroundColor Cyan
    try {
        Invoke-AtomicTest $tech -ShowDetailsBrief
    } catch {
        Write-Host "  No tests available" -ForegroundColor Yellow
    }
}

# Get all atomic techniques from YAML files programmatically
$allAtomics = Get-ChildItem "$atomicsPath\T*\T*.yaml" -Recurse |
    ForEach-Object {
        $yaml = Get-Content $_.FullName -Raw | ConvertFrom-Yaml
        [PSCustomObject]@{
            TechniqueId   = $yaml.attack_technique
            TechniqueName = $yaml.display_name
            TestCount     = $yaml.atomic_tests.Count
            Platforms     = ($yaml.atomic_tests.supported_platforms | Sort-Object -Unique) -join ", "
        }
    }

$allAtomics | Sort-Object TechniqueId | Format-Table -AutoSize
Write-Host "Total techniques with tests: $($allAtomics.Count)"
Write-Host "Total individual tests: $(($allAtomics | Measure-Object -Property TestCount -Sum).Sum)"
```

### Step 3: Execute Atomic Tests with Logging

Run tests with pre/post logging for detection validation:

```powershell
# Execute a single test by technique ID (runs all tests for that technique)
Invoke-AtomicTest T1059.001

# Execute a specific test by number
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Execute by test name
Invoke-AtomicTest T1059.001 -TestNames "Mimikatz - Cradled Invoke Expression"

# Execute by GUID
Invoke-AtomicTest T1059.001 -TestGuids "2e803f96-4e33-4c2c-b0c8-1c10cbb3945f"

# Execute with prerequisite check and installation
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Execute with timeout (seconds)
Invoke-AtomicTest T1003.001 -TimeoutSeconds 120

# Cleanup after testing
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# Execute with full logging wrapper
function Invoke-AtomicWithLogging {
    param(
        [string]$TechniqueId,
        [int[]]$TestNumbers,
        [string]$LogPath = "C:\AtomicRedTeam\logs"
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path $LogPath "${TechniqueId}_${timestamp}.json"

    $result = @{
        technique_id  = $TechniqueId
        test_numbers  = $TestNumbers
        start_time    = (Get-Date).ToString("o")
        hostname      = $env:COMPUTERNAME
        username      = $env:USERNAME
        results       = @()
    }

    foreach ($testNum in $TestNumbers) {
        $testResult = @{
            test_number = $testNum
            status      = "unknown"
            start_time  = (Get-Date).ToString("o")
        }

        try {
            # Show what will execute
            $details = Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -ShowDetails 2>&1
            $testResult["details"] = $details | Out-String

            # Execute the test
            Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Confirm:$false
            $testResult["status"] = "executed"
        } catch {
            $testResult["status"] = "failed"
            $testResult["error"] = $_.Exception.Message
        }

        $testResult["end_time"] = (Get-Date).ToString("o")
        $result.results += $testResult

        # Wait for SIEM ingestion
        Start-Sleep -Seconds 30
    }

    $result["end_time"] = (Get-Date).ToString("o")
    $result | ConvertTo-Json -Depth 10 | Set-Content $logFile
    Write-Host "Log written to: $logFile" -ForegroundColor Green
    return $result
}

# Usage
Invoke-AtomicWithLogging -TechniqueId "T1059.001" -TestNumbers @(1, 2, 3)
```

### Step 4: Validate Detections in SIEM

Query your SIEM to confirm whether atomic tests generated alerts:

```
Splunk SPL Queries for Detection Validation:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- T1059.001: PowerShell Execution
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
  EventCode=4104
  | eval script_block=ScriptBlockText
  | where len(script_block) > 500
  | stats count by host, script_block
  | sort -count

-- T1003.001: LSASS Memory Credential Dumping
index=windows sourcetype="WinEventLog:Security" EventCode=4663
  ObjectName="*lsass*"
  | stats count by host, SubjectUserName, ProcessName
  | where count > 0

-- T1547.001: Registry Run Key Persistence
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=13
  TargetObject="*\\CurrentVersion\\Run*"
  | stats count by host, Image, TargetObject, Details

-- T1053.005: Scheduled Task Creation
index=windows sourcetype="WinEventLog:Security" EventCode=4698
  | stats count by host, SubjectUserName, TaskName, TaskContent
  | sort -count

-- Generic: Hunt for Atomic Red Team artifacts
index=windows (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  OR sourcetype="WinEventLog:Security")
  | search "*AtomicRedTeam*" OR "*atomic*" OR "*Invoke-AtomicTest*"
  | stats count by sourcetype, EventCode, host
```

```
Elastic / KQL Queries:
━━━━━━━━━━━━━━━━━━━━━

-- PowerShell script block logging
event.code: "4104" and powershell.file.script_block_text: *

-- Sysmon process creation from AtomicRedTeam paths
event.code: "1" and process.executable: *AtomicRedTeam*

-- Registry modification (persistence)
event.code: "13" and registry.path: *CurrentVersion\\Run*

-- Credential access indicators
event.code: "10" and winlog.event_data.TargetImage: *lsass.exe*
```

### Step 5: ATT&CK Coverage Gap Analysis

Generate a coverage matrix comparing tested vs. detected techniques:

```python
#!/usr/bin/env python3
"""ATT&CK coverage gap analysis - compares atomic test results against SIEM detections."""

import json
import os
import yaml
from pathlib import Path
from datetime import datetime


def load_atomics_inventory(atomics_path):
    """Parse all atomic test YAML files to build technique inventory."""
    inventory = {}
    atomics_dir = Path(atomics_path)

    for yaml_file in atomics_dir.glob("T*/T*.yaml"):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            tech_id = data.get("attack_technique", "")
            if not tech_id:
                continue

            tests = data.get("atomic_tests", [])
            inventory[tech_id] = {
                "name": data.get("display_name", "Unknown"),
                "test_count": len(tests),
                "platforms": list(set(
                    p for t in tests
                    for p in t.get("supported_platforms", [])
                )),
                "tests": [
                    {
                        "name": t.get("name", "Unnamed"),
                        "description": t.get("description", ""),
                        "platforms": t.get("supported_platforms", []),
                        "executor": t.get("executor", {}).get("name", "unknown"),
                    }
                    for t in tests
                ],
            }
        except Exception as e:
            print(f"[WARN] Failed to parse {yaml_file}: {e}")

    return inventory


def load_execution_logs(log_dir):
    """Load atomic test execution logs."""
    executed = {}
    log_path = Path(log_dir)

    if not log_path.exists():
        return executed

    for log_file in log_path.glob("T*_*.json"):
        try:
            with open(log_file, "r") as f:
                data = json.load(f)
            tech_id = data.get("technique_id", "")
            if tech_id:
                if tech_id not in executed:
                    executed[tech_id] = {
                        "executions": [],
                        "last_executed": data.get("end_time", ""),
                    }
                executed[tech_id]["executions"].append({
                    "timestamp": data.get("start_time", ""),
                    "results": data.get("results", []),
                })
        except Exception as e:
            print(f"[WARN] Failed to parse {log_file}: {e}")

    return executed


def load_detection_results(detection_file):
    """Load SIEM detection validation results (JSON export from SIEM queries)."""
    if not os.path.exists(detection_file):
        return {}

    with open(detection_file, "r") as f:
        data = json.load(f)

    detections = {}
    for entry in data:
        tech_id = entry.get("technique_id", "")
        if tech_id:
            detections[tech_id] = {
                "detected": entry.get("detected", False),
                "alert_count": entry.get("alert_count", 0),
                "rule_name": entry.get("rule_name", ""),
                "confidence": entry.get("confidence", "unknown"),
                "data_sources": entry.get("data_sources", []),
            }

    return detections


# MITRE ATT&CK tactic ordering for structured output
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Tactic-to-technique mapping for common techniques (subset for illustration)
TACTIC_TECHNIQUE_MAP = {
    "execution": [
        "T1059", "T1059.001", "T1059.003", "T1059.004", "T1059.005",
        "T1059.006", "T1059.007", "T1047", "T1053", "T1053.005",
        "T1129", "T1203", "T1569", "T1569.002",
    ],
    "persistence": [
        "T1547", "T1547.001", "T1547.004", "T1547.009",
        "T1053.005", "T1136", "T1136.001", "T1543", "T1543.003",
        "T1546", "T1546.001", "T1546.003", "T1574", "T1574.001",
        "T1197", "T1505", "T1505.003",
    ],
    "credential-access": [
        "T1003", "T1003.001", "T1003.002", "T1003.003",
        "T1003.004", "T1003.005", "T1003.006",
        "T1110", "T1110.001", "T1110.003",
        "T1555", "T1555.003", "T1552", "T1552.001",
        "T1558", "T1558.003",
    ],
    "defense-evasion": [
        "T1070", "T1070.001", "T1070.004",
        "T1218", "T1218.001", "T1218.003", "T1218.005",
        "T1218.010", "T1218.011",
        "T1027", "T1140", "T1562", "T1562.001",
        "T1036", "T1036.005",
    ],
    "discovery": [
        "T1082", "T1083", "T1087", "T1087.001", "T1087.002",
        "T1016", "T1049", "T1057", "T1069", "T1069.001",
        "T1069.002", "T1518", "T1518.001",
    ],
    "lateral-movement": [
        "T1021", "T1021.001", "T1021.002", "T1021.003",
        "T1021.004", "T1021.006", "T1570",
    ],
    "command-and-control": [
        "T1071", "T1071.001", "T1071.004",
        "T1105", "T1132", "T1573", "T1573.001",
        "T1219", "T1090",
    ],
    "exfiltration": [
        "T1041", "T1048", "T1048.003", "T1567",
    ],
    "impact": [
        "T1485", "T1486", "T1489", "T1490", "T1491",
    ],
}


def generate_coverage_report(atomics_inventory, execution_logs, detection_results):
    """Generate comprehensive coverage gap analysis."""
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {},
        "tactics": {},
        "gaps": [],
        "recommendations": [],
    }

    total_available = len(atomics_inventory)
    total_executed = len(execution_logs)
    total_detected = sum(1 for d in detection_results.values() if d.get("detected"))

    report["summary"] = {
        "total_techniques_with_atomics": total_available,
        "total_techniques_executed": total_executed,
        "total_techniques_detected": total_detected,
        "execution_coverage_pct": round(
            (total_executed / total_available * 100) if total_available else 0, 1
        ),
        "detection_coverage_pct": round(
            (total_detected / total_executed * 100) if total_executed else 0, 1
        ),
    }

    # Per-tactic analysis
    for tactic, technique_ids in TACTIC_TECHNIQUE_MAP.items():
        tactic_data = {
            "techniques_available": 0,
            "techniques_executed": 0,
            "techniques_detected": 0,
            "gaps": [],
        }

        for tech_id in technique_ids:
            if tech_id in atomics_inventory:
                tactic_data["techniques_available"] += 1

                executed = tech_id in execution_logs
                detected = detection_results.get(tech_id, {}).get("detected", False)

                if executed:
                    tactic_data["techniques_executed"] += 1
                if detected:
                    tactic_data["techniques_detected"] += 1

                if executed and not detected:
                    gap = {
                        "technique_id": tech_id,
                        "technique_name": atomics_inventory[tech_id]["name"],
                        "tactic": tactic,
                        "status": "BLIND_SPOT",
                        "detail": "Test executed but no detection triggered",
                    }
                    tactic_data["gaps"].append(gap)
                    report["gaps"].append(gap)
                elif not executed and tech_id in atomics_inventory:
                    gap = {
                        "technique_id": tech_id,
                        "technique_name": atomics_inventory[tech_id]["name"],
                        "tactic": tactic,
                        "status": "NOT_TESTED",
                        "detail": "Atomic test available but not yet executed",
                    }
                    tactic_data["gaps"].append(gap)

        avail = tactic_data["techniques_available"]
        tactic_data["coverage_pct"] = round(
            (tactic_data["techniques_detected"] / avail * 100) if avail else 0, 1
        )
        report["tactics"][tactic] = tactic_data

    # Generate prioritized recommendations
    blind_spots = [g for g in report["gaps"] if g["status"] == "BLIND_SPOT"]
    if blind_spots:
        report["recommendations"].append({
            "priority": "CRITICAL",
            "action": f"Write detection rules for {len(blind_spots)} blind spot techniques",
            "techniques": [g["technique_id"] for g in blind_spots],
        })

    low_coverage_tactics = [
        t for t, d in report["tactics"].items() if d["coverage_pct"] < 30
    ]
    if low_coverage_tactics:
        report["recommendations"].append({
            "priority": "HIGH",
            "action": f"Expand testing in low-coverage tactics: {', '.join(low_coverage_tactics)}",
            "detail": "These tactics have less than 30% detection coverage",
        })

    return report


def generate_navigator_layer(atomics_inventory, execution_logs, detection_results,
                             layer_name="Purple Team Coverage"):
    """Generate ATT&CK Navigator layer JSON for heatmap visualization."""
    layer = {
        "name": layer_name,
        "versions": {
            "attack": "15",
            "navigator": "5.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Purple team atomic testing coverage - Generated {datetime.utcnow().isoformat()}Z",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ff6666", "#ffeb3b", "#66bb6a"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "No Coverage (Blind Spot)", "color": "#ff6666"},
            {"label": "Logged Only (Partial)", "color": "#ffeb3b"},
            {"label": "Alert/Detection Active", "color": "#66bb6a"},
            {"label": "Not Tested", "color": "#d3d3d3"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    for tech_id, tech_data in atomics_inventory.items():
        executed = tech_id in execution_logs
        detection = detection_results.get(tech_id, {})
        detected = detection.get("detected", False)
        confidence = detection.get("confidence", "none")

        if detected and confidence in ("high", "medium"):
            score = 100
            color = "#66bb6a"  # Green - high confidence detection
            comment = f"DETECTED - {detection.get('rule_name', 'Alert active')}"
        elif detected:
            score = 50
            color = "#ffeb3b"  # Yellow - logged/partial
            comment = "PARTIAL - Detection exists but low confidence"
        elif executed:
            score = 0
            color = "#ff6666"  # Red - blind spot
            comment = "BLIND SPOT - Test executed, no detection"
        else:
            score = 0
            color = "#d3d3d3"  # Gray - not tested
            comment = f"NOT TESTED - {tech_data['test_count']} atomic tests available"

        technique_entry = {
            "techniqueID": tech_id,
            "tactic": "",
            "color": color,
            "comment": comment,
            "score": score,
            "enabled": True,
            "metadata": [
                {"name": "tests_available", "value": str(tech_data["test_count"])},
                {"name": "executed", "value": str(executed)},
                {"name": "detected", "value": str(detected)},
            ],
            "links": [],
            "showSubtechniques": False,
        }
        layer["techniques"].append(technique_entry)

    return layer


def print_coverage_report(report):
    """Print formatted coverage report to console."""
    print("=" * 72)
    print("PURPLE TEAM ATOMIC TESTING - COVERAGE GAP ANALYSIS")
    print("=" * 72)
    print(f"Generated: {report['generated_at']}")
    print()

    s = report["summary"]
    print("EXECUTIVE SUMMARY")
    print("-" * 40)
    print(f"  Techniques with atomics:  {s['total_techniques_with_atomics']}")
    print(f"  Techniques executed:      {s['total_techniques_executed']}")
    print(f"  Techniques detected:      {s['total_techniques_detected']}")
    print(f"  Execution coverage:       {s['execution_coverage_pct']}%")
    print(f"  Detection coverage:       {s['detection_coverage_pct']}%")
    print()

    print("PER-TACTIC COVERAGE")
    print("-" * 72)
    print(f"{'Tactic':<25} {'Available':>9} {'Executed':>9} {'Detected':>9} {'Coverage':>9}")
    print("-" * 72)
    for tactic in TACTIC_ORDER:
        if tactic in report["tactics"]:
            t = report["tactics"][tactic]
            bar = "#" * int(t["coverage_pct"] / 5) + "." * (20 - int(t["coverage_pct"] / 5))
            print(
                f"  {tactic:<23} {t['techniques_available']:>9} "
                f"{t['techniques_executed']:>9} {t['techniques_detected']:>9} "
                f"{t['coverage_pct']:>8.1f}%"
            )
    print()

    blind_spots = [g for g in report["gaps"] if g["status"] == "BLIND_SPOT"]
    if blind_spots:
        print("CRITICAL BLIND SPOTS (executed but not detected)")
        print("-" * 72)
        for gap in blind_spots:
            print(f"  [!] {gap['technique_id']} - {gap['technique_name']}")
            print(f"      Tactic: {gap['tactic']}")
        print()

    if report["recommendations"]:
        print("RECOMMENDATIONS")
        print("-" * 72)
        for rec in report["recommendations"]:
            print(f"  [{rec['priority']}] {rec['action']}")
            if "techniques" in rec:
                print(f"         Techniques: {', '.join(rec['techniques'][:10])}")
            if "detail" in rec:
                print(f"         {rec['detail']}")
        print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ATT&CK coverage gap analysis for purple team testing")
    parser.add_argument("--atomics-path", default=r"C:\AtomicRedTeam\atomics",
                        help="Path to Atomic Red Team atomics directory")
    parser.add_argument("--log-dir", default=r"C:\AtomicRedTeam\logs",
                        help="Path to atomic test execution logs")
    parser.add_argument("--detections-file", default="detection_results.json",
                        help="Path to SIEM detection validation export (JSON)")
    parser.add_argument("--output-layer", default="navigator_layer.json",
                        help="Output path for ATT&CK Navigator layer JSON")
    parser.add_argument("--output-report", default="coverage_report.json",
                        help="Output path for coverage report JSON")
    args = parser.parse_args()

    print("[*] Loading atomics inventory...")
    inventory = load_atomics_inventory(args.atomics_path)
    print(f"    Found {len(inventory)} techniques with atomic tests")

    print("[*] Loading execution logs...")
    exec_logs = load_execution_logs(args.log_dir)
    print(f"    Found logs for {len(exec_logs)} techniques")

    print("[*] Loading detection results...")
    det_results = load_detection_results(args.detections_file)
    print(f"    Found detection data for {len(det_results)} techniques")

    print("[*] Generating coverage report...")
    report = generate_coverage_report(inventory, exec_logs, det_results)
    print_coverage_report(report)

    # Save report JSON
    with open(args.output_report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to {args.output_report}")

    # Generate and save Navigator layer
    print("[*] Generating ATT&CK Navigator layer...")
    layer = generate_navigator_layer(inventory, exec_logs, det_results)
    with open(args.output_layer, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"[+] Navigator layer saved to {args.output_layer}")
    print(f"    Import at: https://mitre-attack.github.io/attack-navigator/")
```

### Step 6: Run Continuous Atomic Testing Pipeline

Schedule recurring tests against priority techniques:

```powershell
# Continuous Atomic Testing - scheduled execution with validation
# Run as a scheduled task or via CI/CD pipeline

$PriorityTechniques = @(
    # Top MITRE ATT&CK techniques by prevalence (Red Canary Threat Detection Report)
    @{ Id = "T1059.001"; Name = "PowerShell" },
    @{ Id = "T1059.003"; Name = "Windows Command Shell" },
    @{ Id = "T1547.001"; Name = "Registry Run Keys" },
    @{ Id = "T1053.005"; Name = "Scheduled Task" },
    @{ Id = "T1003.001"; Name = "LSASS Memory" },
    @{ Id = "T1003.003"; Name = "NTDS" },
    @{ Id = "T1070.004"; Name = "File Deletion" },
    @{ Id = "T1218.011"; Name = "Rundll32" },
    @{ Id = "T1082";     Name = "System Information Discovery" },
    @{ Id = "T1105";     Name = "Ingress Tool Transfer" }
)

$ResultsLog = @()
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

foreach ($technique in $PriorityTechniques) {
    Write-Host "`n[*] Testing $($technique.Id) - $($technique.Name)" -ForegroundColor Cyan

    # Check prerequisites
    try {
        $prereqs = Invoke-AtomicTest $technique.Id -TestNumbers 1 -CheckPrereqs 2>&1
        $prereqsMet = $prereqs -notmatch "not met"
    } catch {
        $prereqsMet = $false
    }

    if (-not $prereqsMet) {
        Write-Host "    [!] Prerequisites not met, attempting install..." -ForegroundColor Yellow
        try {
            Invoke-AtomicTest $technique.Id -TestNumbers 1 -GetPrereqs 2>&1 | Out-Null
        } catch {
            Write-Host "    [!] Prereq install failed, skipping" -ForegroundColor Red
            $ResultsLog += [PSCustomObject]@{
                TechniqueId = $technique.Id
                Name        = $technique.Name
                Status      = "PREREQS_FAILED"
                Timestamp   = (Get-Date).ToString("o")
            }
            continue
        }
    }

    # Execute the test
    try {
        $startTime = Get-Date
        Invoke-AtomicTest $technique.Id -TestNumbers 1 -Confirm:$false
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Host "    [+] Executed successfully (${duration}s)" -ForegroundColor Green

        $ResultsLog += [PSCustomObject]@{
            TechniqueId = $technique.Id
            Name        = $technique.Name
            Status      = "EXECUTED"
            Duration    = $duration
            Timestamp   = $startTime.ToString("o")
        }
    } catch {
        Write-Host "    [-] Execution failed: $($_.Exception.Message)" -ForegroundColor Red
        $ResultsLog += [PSCustomObject]@{
            TechniqueId = $technique.Id
            Name        = $technique.Name
            Status      = "FAILED"
            Error       = $_.Exception.Message
            Timestamp   = (Get-Date).ToString("o")
        }
    }

    # Cleanup
    try {
        Invoke-AtomicTest $technique.Id -TestNumbers 1 -Cleanup 2>&1 | Out-Null
        Write-Host "    [+] Cleanup completed" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [!] Cleanup failed" -ForegroundColor Yellow
    }

    # Brief pause between tests for log ingestion
    Start-Sleep -Seconds 10
}

# Export results
$ResultsLog | Export-Csv "C:\AtomicRedTeam\logs\continuous_test_$RunTimestamp.csv" -NoTypeInformation
$ResultsLog | Format-Table -AutoSize

# Summary
$executed = ($ResultsLog | Where-Object Status -eq "EXECUTED").Count
$failed = ($ResultsLog | Where-Object Status -ne "EXECUTED").Count
Write-Host "`n=== CONTINUOUS TEST SUMMARY ===" -ForegroundColor Cyan
Write-Host "  Executed: $executed / $($PriorityTechniques.Count)" -ForegroundColor Green
Write-Host "  Failed:   $failed / $($PriorityTechniques.Count)" -ForegroundColor Red
```

### Step 7: Detection Validation Loop

Close the purple team loop by correlating tests with detections and iterating:

```
Detection Validation Loop Workflow:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌──────────────────┐
  │ 1. SELECT        │  Choose technique from threat intel or gap report
  │    TECHNIQUE     │  Map to Atomic Red Team test ID
  └───────┬──────────┘
          │
  ┌───────▼──────────┐
  │ 2. EXECUTE       │  Run Invoke-AtomicTest with logging
  │    ATOMIC TEST   │  Record timestamp, hostname, test details
  └───────┬──────────┘
          │
  ┌───────▼──────────┐
  │ 3. WAIT FOR      │  Allow 30-60 seconds for log ingestion
  │    INGESTION     │  Ensure Sysmon, WinEventLog, EDR agents forward data
  └───────┬──────────┘
          │
  ┌───────▼──────────┐
  │ 4. QUERY SIEM    │  Search for correlated alerts matching technique
  │    FOR ALERTS    │  Check: Did our detection rules fire?
  └───────┬──────────┘
          │
     ┌────┴────┐
     │DETECTED?│
     └────┬────┘
    YES   │   NO
  ┌───────▼──────────┐   ┌──────────────────┐
  │ 5a. MARK GREEN   │   │ 5b. WRITE NEW    │
  │  Update Navigator│   │  Sigma/SIEM Rule │
  │  layer, log pass │   │  for technique   │
  └───────┬──────────┘   └───────┬──────────┘
          │                       │
          │               ┌───────▼──────────┐
          │               │ 5c. DEPLOY RULE  │
          │               │  Push to SIEM    │
          │               └───────┬──────────┘
          │                       │
          │               ┌───────▼──────────┐
          │               │ 5d. RE-EXECUTE   │
          │               │  Re-run atomic   │
          │               │  test, validate  │
          │               └───────┬──────────┘
          │                       │
  ┌───────▼───────────────────────▼──┐
  │ 6. CLEANUP                       │
  │    Run Invoke-AtomicTest -Cleanup│
  │    Document results              │
  └───────┬──────────────────────────┘
          │
  ┌───────▼──────────┐
  │ 7. NEXT          │  Select next technique
  │    TECHNIQUE     │  Repeat from step 1
  └──────────────────┘
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Atomic Red Team** | Open-source library by Red Canary containing small, focused tests mapped to MITRE ATT&CK techniques for validating detection capabilities |
| **Invoke-AtomicRedTeam** | PowerShell execution framework for running atomic tests locally or remotely, with prereq checking and cleanup |
| **ATT&CK Navigator** | Web-based tool for annotating and visualizing MITRE ATT&CK matrices as layered heatmaps showing detection coverage |
| **Navigator Layer** | JSON file defining colors, scores, and comments for each ATT&CK technique; used to generate coverage heatmaps |
| **Detection Validation Loop** | Iterative purple team process: execute attack, check for detection, write/tune rule if missed, re-execute to confirm |
| **Coverage Gap** | ATT&CK technique where no detection rule exists or where the rule fails to fire when the technique is executed |
| **Blind Spot** | Technique that was tested via atomic execution but produced zero SIEM alerts, indicating a critical detection failure |
| **Sigma Rule** | Vendor-agnostic detection rule format that can be converted to Splunk SPL, Elastic KQL, Microsoft KQL, and other SIEM queries |
| **Purple Team** | Collaborative security exercise where red team executes known techniques and blue team validates and improves detections in real time |
| **Continuous Atomic Testing** | Scheduled, automated execution of atomic tests to validate that detection rules remain functional as environments change |

## Tools & Systems

- **Invoke-AtomicRedTeam**: PowerShell module for executing Atomic Red Team tests with prereq management and cleanup
- **Atomic Red Team Atomics**: Library of 700+ tests across 200+ MITRE ATT&CK techniques, organized by technique ID
- **ATT&CK Navigator**: Web tool at mitre-attack.github.io/attack-navigator for creating technique coverage heatmaps
- **VECTR**: Purple team reporting platform by SCYTHE for tracking test campaigns, results, and coverage over time
- **Sigma**: Generic signature format for SIEM systems; convert with sigmac or pySigma to target SIEM platforms
- **Splunk / Elastic / Microsoft Sentinel**: SIEM platforms for querying detection results after atomic test execution
- **Sysmon**: Windows system monitoring driver providing detailed process, network, registry, and file telemetry
- **Caldera**: MITRE-developed adversary emulation platform for automated, multi-step attack chains beyond single atomic tests

## Common Scenarios

### Scenario: Validating Credential Access Detections After EDR Deployment

**Context**: The organization deployed a new EDR agent and needs to verify it detects credential dumping techniques (LSASS access, NTDS extraction, SAM dump). The purple team must confirm detections are working before closing the deployment ticket.

**Approach**:
1. Install Invoke-AtomicRedTeam on a test endpoint enrolled in the new EDR
2. Execute credential access atomics: T1003.001 (LSASS Memory), T1003.002 (SAM), T1003.003 (NTDS)
3. Wait 60 seconds, then query EDR console and SIEM for alerts on the test hostname
4. For each technique: mark as DETECTED (green) or BLIND SPOT (red) in the Navigator layer
5. For blind spots, create Sigma rules targeting Sysmon EventCode 10 (ProcessAccess to lsass.exe) and EventCode 1 (known dumping tools)
6. Deploy rules, re-run atomics, confirm detection
7. Export Navigator layer and coverage report for the deployment ticket

**Pitfalls**:
- Running credential dumping atomics without local admin privileges (tests will fail silently)
- Forgetting to enable Sysmon ProcessAccess logging (EventCode 10) which is disabled by default
- Not running cleanup, leaving test artifacts (created accounts, registry keys, scheduled tasks)
- Testing only one sub-technique of T1003 and assuming all credential access is covered
- Not accounting for EDR agent exclusions that may whitelist PowerShell or the AtomicRedTeam directory

### Scenario: Building Monthly ATT&CK Coverage Reporting for Leadership

**Context**: The CISO requires monthly metrics on detection coverage mapped to MITRE ATT&CK. The security team needs to run recurring tests, track improvements, and produce a visual heatmap showing coverage growth over time.

**Approach**:
1. Define a test plan covering the top 50 ATT&CK techniques from Red Canary Threat Detection Report
2. Schedule continuous atomic testing via Windows Task Scheduler running the PowerShell pipeline weekly
3. Export execution logs and SIEM detection query results to JSON after each run
4. Run the Python gap analysis script to produce Navigator layer and coverage report
5. Import the Navigator layer into ATT&CK Navigator, screenshot for executive slide deck
6. Track month-over-month: number of green (detected) vs. red (blind spot) techniques
7. Prioritize detection engineering sprints on the highest-impact blind spots

**Pitfalls**:
- Counting "logged" as "detected" (seeing an event in logs is not the same as having an alert rule)
- Not updating the atomics repository (new tests are added frequently)
- Focusing only on technique count rather than detection quality (a noisy rule with 90% false positives is worse than no rule)
- Not involving the SOC analysts who will triage the alerts in the validation process

## Output Format

```
PURPLE TEAM ATOMIC TESTING REPORT
====================================
Campaign:         Q1 2026 Detection Validation
Date Range:       2026-01-15 to 2026-03-15
Test Environment: YOURLAB-WIN10-01, YOURLAB-SRV-01
SIEM:             Splunk Enterprise 9.x

EXECUTION SUMMARY
Techniques Tested:        47 / 200+ available
Individual Tests Run:     112
Tests Succeeded:          104
Tests Failed (prereqs):   8
Cleanup Completed:        104 / 104

DETECTION COVERAGE
                            Tested    Detected    Coverage
Execution:                     12          10       83.3%
Persistence:                    8           5       62.5%
Credential Access:              6           4       66.7%
Defense Evasion:               10           3       30.0%
Discovery:                      5           5      100.0%
Lateral Movement:               3           1       33.3%
Command and Control:            2           1       50.0%
Exfiltration:                   1           0        0.0%

CRITICAL BLIND SPOTS
[!] T1218.011 - Rundll32          (defense-evasion)
[!] T1218.005 - Mshta             (defense-evasion)
[!] T1070.004 - File Deletion     (defense-evasion)
[!] T1574.001 - DLL Search Order  (persistence)
[!] T1021.002 - SMB/Admin Shares  (lateral-movement)
[!] T1048.003 - Exfil Over HTTP   (exfiltration)

NAVIGATOR LAYER: coverage_layer_20260315.json
  Import at: https://mitre-attack.github.io/attack-navigator/

RECOMMENDATIONS
[CRITICAL] Write Sigma rules for 6 blind spot techniques
[HIGH]     Expand defense-evasion testing (30% coverage)
[HIGH]     Enable exfiltration monitoring data sources
[MEDIUM]   Increase lateral movement test coverage (3 of 7 tested)
```
