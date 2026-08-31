---
name: performing-purple-team-atomic-testing
description: Executes Atomic Red Team tests mapped to MITRE ATT&CK via Invoke-AtomicRedTeam PowerShell, generates ATT&CK Navigator coverage heatmaps, correlates results against Sigma rules, and runs detection validation loops to measure blue team visibility. Use for purple team exercises that pair Invoke-AtomicRedTeam atomic execution with Sigma rule correlation and Navigator coverage scoring. Do not use for running atomics from the atomic-operator Python framework - use performing-threat-emulation-with-atomic-red-team.
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

See [references/siem-and-automation.md](references/siem-and-automation.md) for the full Splunk SPL and Elastic/KQL detection-validation query catalog.

### Step 5: ATT&CK Coverage Gap Analysis

Generate a coverage matrix comparing tested vs. detected techniques:

The full gap-analysis script parses the atomics library, execution logs, and SIEM detection exports, then emits a coverage report plus an ATT&CK Navigator layer JSON. See [references/coverage-gap-analysis.md](references/coverage-gap-analysis.md) for the complete script and usage.

### Step 6: Run Continuous Atomic Testing Pipeline

Schedule recurring tests against priority techniques:

See [references/siem-and-automation.md](references/siem-and-automation.md) for the full PowerShell continuous-testing pipeline (prereq handling, execution, cleanup, CSV export).

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
