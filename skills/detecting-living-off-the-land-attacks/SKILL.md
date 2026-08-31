---
name: detecting-living-off-the-land-attacks
description: Detect abuse of legitimate Windows binaries (LOLBins) used for living off the land attacks, monitoring process creation, command-line arguments, and parent-child relationships to identify suspicious LOLBin execution patterns. Use when building endpoint detection for LOLBin abuse from live process-creation monitoring. Do not use for retrospective log-based hunting over collected endpoint process telemetry - use hunting-for-lolbins-execution-in-endpoint-logs.
domain: cybersecurity
subdomain: threat-detection
tags:
- lolbins
- lotl
- fileless-attacks
- process-monitoring
version: '1.0'
author: mahipal
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
- DE.AE-06
- ID.RA-05
mitre_attack:
- T1078
- T1190
- T1059
---

# Detecting Living Off the Land Attacks

Monitor for suspicious use of legitimate Windows binaries (LOLBins)
including certutil, mshta, rundll32, regsvr32, and others used in
fileless and living-off-the-land attack techniques.

## When to Use

- Building detection rules for SIEM or EDR platforms to catch LOLBin abuse in real time
- Investigating alerts where legitimate system binaries appear in unexpected execution contexts
- Threat hunting across endpoint telemetry for fileless attack indicators
- Hardening application whitelisting policies (AppLocker, WDAC) to restrict dangerous LOLBin usage
- Creating Sysmon configurations tuned to capture LOLBin-related process creation events
- Responding to incidents where adversaries bypassed AV by using only built-in OS tools

**Do not use** for blocking all LOLBin execution outright; these are legitimate system tools with valid administrative uses. Detection must focus on anomalous context (parent process, command-line arguments, network activity) rather than binary presence alone.

## Prerequisites

- Sysmon v15+ installed on Windows endpoints with a tuned configuration (SwiftOnSecurity or Olaf Hartong baseline)
- SIEM platform ingesting Sysmon Event IDs 1 (Process Create), 3 (Network Connection), 7 (Image Loaded), 11 (File Create)
- Windows Event Log forwarding for Security Event IDs 4688 (Process Creation with command-line logging enabled)
- LOLBAS project reference: https://lolbas-project.github.io/
- Python 3.8+ with `evtx`, `pandas` for offline log analysis
- Sigma rule repository for cross-platform detection rule authoring

## Workflow

### Step 1: Deploy a LOLBin-Focused Sysmon Configuration

Create a Sysmon config that captures the process creation and network events needed for LOLBin detection:

```xml
<!-- File: sysmon-lolbin-detection.xml -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Creation: capture all LOLBin executions with full command lines -->
    <RuleGroup name="LOLBin Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">certutil.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <Image condition="end with">rundll32.exe</Image>
        <Image condition="end with">regsvr32.exe</Image>
        <Image condition="end with">msbuild.exe</Image>
        <Image condition="end with">installutil.exe</Image>
        <Image condition="end with">cmstp.exe</Image>
        <Image condition="end with">wmic.exe</Image>
        <Image condition="end with">bitsadmin.exe</Image>
        <Image condition="end with">certreq.exe</Image>
        <Image condition="end with">esentutl.exe</Image>
        <Image condition="end with">expand.exe</Image>
        <Image condition="end with">extrac32.exe</Image>
        <Image condition="end with">findstr.exe</Image>
        <Image condition="end with">hh.exe</Image>
        <Image condition="end with">ie4uinit.exe</Image>
        <Image condition="end with">mavinject.exe</Image>
        <Image condition="end with">msiexec.exe</Image>
        <Image condition="end with">odbcconf.exe</Image>
        <Image condition="end with">pcalua.exe</Image>
        <Image condition="end with">presentationhost.exe</Image>
        <Image condition="end with">replace.exe</Image>
        <Image condition="end with">xwizard.exe</Image>
        <!-- PowerShell variants -->
        <Image condition="end with">powershell.exe</Image>
        <Image condition="end with">pwsh.exe</Image>
        <!-- Script hosts -->
        <Image condition="end with">cscript.exe</Image>
        <Image condition="end with">wscript.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network connections from LOLBins (highly suspicious) -->
    <RuleGroup name="LOLBin Network" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="end with">certutil.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <Image condition="end with">rundll32.exe</Image>
        <Image condition="end with">regsvr32.exe</Image>
        <Image condition="end with">msbuild.exe</Image>
        <Image condition="end with">bitsadmin.exe</Image>
        <Image condition="end with">expand.exe</Image>
        <Image condition="end with">esentutl.exe</Image>
        <Image condition="end with">replace.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

```powershell
# Install or update Sysmon with the LOLBin config
sysmon64.exe -accepteula -i sysmon-lolbin-detection.xml

# Update existing Sysmon installation
sysmon64.exe -c sysmon-lolbin-detection.xml
```

### Step 2: Build Sigma Detection Rules for Key LOLBins

Write Sigma rules that detect specific abuse patterns, translatable to any SIEM:

```yaml
# File: sigma/certutil_download.yml
title: Certutil Used to Download File
id: a1b2c3d4-5678-9abc-def0-123456789abc
status: stable
description: >
  Detects certutil.exe being used to download files from remote URLs,
  a common LOLBin technique for payload delivery (LOLBAS T1105).
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
  - https://attack.mitre.org/techniques/T1105/
author: Threat Detection Team
date: 2026/01/20
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - 'urlcache'
      - '-f'
      - 'http'
  condition: selection
falsepositives:
  - Legitimate certificate enrollment using certutil with URL parameters
level: high
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.command_and_control
  - attack.t1105
```

```yaml
# File: sigma/mshta_execution.yml
title: MSHTA Executing Remote or Inline Script
id: b2c3d4e5-6789-abcd-ef01-234567890bcd
status: stable
description: >
  Detects mshta.exe executing scripts from URLs or inline VBScript/JavaScript,
  commonly used for application whitelisting bypass and initial access.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Mshta/
  - https://attack.mitre.org/techniques/T1218/005/
logsource:
  category: process_creation
  product: windows
detection:
  selection_remote:
    Image|endswith: '\mshta.exe'
    CommandLine|contains: 'http'
  selection_inline:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'vbscript:'
      - 'javascript:'
  selection_parent_anomaly:
    Image|endswith: '\mshta.exe'
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
      - '\powerpnt.exe'
  condition: selection_remote or selection_inline or selection_parent_anomaly
falsepositives:
  - Legacy HTA-based internal applications
level: high
```

```yaml
# File: sigma/regsvr32_scrobj.yml
title: Regsvr32 Squiblydoo Scriptlet Execution
id: c3d4e5f6-7890-bcde-f012-345678901cde
status: stable
description: >
  Detects regsvr32.exe loading scrobj.dll with a remote scriptlet URL,
  known as the Squiblydoo technique for AppLocker bypass.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
  - https://attack.mitre.org/techniques/T1218/010/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains|all:
      - 'scrobj.dll'
      - '/i:'
  condition: selection
falsepositives:
  - Legitimate COM scriptlet registration (rare in modern environments)
level: critical
```

### Step 3: Analyze Sysmon Logs for LOLBin Abuse Patterns

Parse and correlate Sysmon events to identify suspicious LOLBin execution. The `LOLBIN_SIGNATURES` table maps each LOLBin (certutil, mshta, rundll32, regsvr32, bitsadmin, wmic, msbuild, mavinject) to regex command-line indicators, MITRE technique, and severity; `analyze_sysmon_events` scans process-creation events against it and emits enriched alerts.

See the full signatures table and analyzer in [references/log-correlation-code.md](references/log-correlation-code.md#step-3-analyze-sysmon-logs-for-lolbin-abuse-patterns).

### Step 4: Detect LOLBin Network Connections

LOLBins making outbound network connections is a strong indicator of malicious use. `detect_lolbin_network_activity` correlates Sysmon network events (ID 3) against a set of LOLBins that should rarely reach the network, skipping localhost, and raises a critical alert with destination details.

See the full network-correlation function in [references/log-correlation-code.md](references/log-correlation-code.md#step-4-detect-lolbin-network-connections).

### Step 5: Monitor Anomalous Parent-Child Process Relationships

Suspicious parent-child pairs (Office apps or explorer.exe spawning script hosts, wmiprvse.exe or services.exe spawning shells) are strong LOLBin-abuse signals. `SUSPICIOUS_PARENT_CHILD` encodes these pairings with severity and MITRE technique, and `check_parent_child_anomaly` flags matching process-creation events.

See the full parent-child ruleset and checker in [references/log-correlation-code.md](references/log-correlation-code.md#step-5-monitor-anomalous-parent-child-process-relationships).


### Step 6: Implement AppLocker or WDAC Hardening

Restrict unnecessary LOLBin execution with application control policies:

```powershell
# Query current AppLocker policy
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Create AppLocker rules to restrict certutil to admin-only
$rule = New-AppLockerPolicy -RuleType Publisher -RuleNamePrefix "Block" `
    -FileInformation "C:\Windows\System32\certutil.exe" `
    -User "S-1-1-0" -Deny

# Export current policy for backup before applying changes
Get-AppLockerPolicy -Effective -Xml > AppLocker_Backup.xml

# Block specific LOLBins for standard users via GPO script
$lolbins_to_restrict = @(
    "mshta.exe", "cmstp.exe", "msbuild.exe", "installutil.exe",
    "regsvr32.exe", "presentationhost.exe", "ie4uinit.exe",
    "mavinject.exe", "xwizard.exe"
)

foreach ($binary in $lolbins_to_restrict) {
    $path = "C:\Windows\System32\$binary"
    if (Test-Path $path) {
        Write-Output "Restricting: $path"
        # Apply WDAC deny rule via PowerShell
        # In production, use Group Policy or Intune WDAC policies
    }
}
```

## Verification

- Confirm Sysmon is logging Event ID 1 (Process Creation) with full command-line arguments for all listed LOLBins
- Validate Sigma rules convert correctly to your SIEM query language using `sigmac` or `sigma-cli`
- Test detection by executing benign LOLBin commands in a lab environment and confirming alerts fire
- Verify parent-child anomaly detection catches Office-to-LOLBin chains (e.g., `winword.exe` spawning `certutil.exe`)
- Confirm LOLBin network connection detection triggers when `certutil.exe` or `mshta.exe` reach out to external IPs
- Check that AppLocker or WDAC policies do not break legitimate administrative workflows before deploying to production
- Validate false positive rates by running detection rules against 7 days of baseline telemetry from a clean environment
- Cross-reference detections against the LOLBAS project database at https://lolbas-project.github.io/ for completeness
