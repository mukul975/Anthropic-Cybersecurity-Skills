#!/usr/bin/env python3
"""LOLBin (Living Off the Land Binary) detection agent.

Parses Windows Sysmon Event ID 1 (Process Create) and Event ID 3
(Network Connection) logs in EVTX or JSON format to detect suspicious
LOLBin execution patterns, anomalous parent-child relationships, and
LOLBin network activity.
"""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False


# LOLBin signatures: binary name -> suspicious command-line patterns + MITRE mapping
LOLBIN_SIGNATURES = {
    "certutil.exe": {
        "patterns": [
            r"-urlcache\s+-f\s+https?://",
            r"-decode\s+",
            r"-encode\s+",
            r"-verifyctl\s+.*https?://",
            r"-ping\s+https?://",
        ],
        "mitre": ["T1218", "T1105"],
        "severity": "high",
        "description": "Certificate utility used for file download/decode",
    },
    "mshta.exe": {
        "patterns": [
            r"https?://",
            r"vbscript:",
            r"javascript:",
            r"about:",
        ],
        "mitre": ["T1218.005"],
        "severity": "high",
        "description": "HTML Application host executing remote/inline scripts",
    },
    "rundll32.exe": {
        "patterns": [
            r"javascript:",
            r"shell32\.dll.*ShellExec_RunDLL",
            r"\\\\.*\\.*\.dll",
            r"comsvcs\.dll.*MiniDump",
            r"comsvcs\.dll.*#24",
            r"url\.dll.*OpenURL",
            r"url\.dll.*FileProtocolHandler",
            r"advpack\.dll.*RegisterOCX",
        ],
        "mitre": ["T1218.011"],
        "severity": "critical",
        "description": "DLL proxy execution via rundll32",
    },
    "regsvr32.exe": {
        "patterns": [
            r"/s\s+/n\s+/u\s+/i:",
            r"scrobj\.dll",
            r"https?://",
        ],
        "mitre": ["T1218.010"],
        "severity": "critical",
        "description": "Squiblydoo scriptlet execution via regsvr32",
    },
    "bitsadmin.exe": {
        "patterns": [
            r"/transfer\s+.*https?://",
            r"/create\s+",
            r"/addfile\s+.*https?://",
            r"/SetNotifyCmdLine",
            r"/Resume",
        ],
        "mitre": ["T1197"],
        "severity": "high",
        "description": "BITS job abuse for file download/persistence",
    },
    "wmic.exe": {
        "patterns": [
            r"process\s+call\s+create",
            r"/node:",
            r"os\s+get\s+/format:.*https?://",
            r"/format:.*\.xsl",
        ],
        "mitre": ["T1047"],
        "severity": "high",
        "description": "WMI command-line for remote execution or XSL script",
    },
    "msbuild.exe": {
        "patterns": [
            r"\.xml\b",
            r"\.csproj\b",
            r"\\temp\\",
            r"\\appdata\\",
            r"\\users\\.*\\desktop\\",
        ],
        "mitre": ["T1127.001"],
        "severity": "high",
        "description": "MSBuild executing project from unusual location",
    },
    "installutil.exe": {
        "patterns": [
            r"/logfile=",
            r"/LogToConsole=false",
            r"\\temp\\",
            r"\\appdata\\",
        ],
        "mitre": ["T1218.004"],
        "severity": "high",
        "description": "InstallUtil executing assembly from unusual path",
    },
    "cmstp.exe": {
        "patterns": [
            r"/ni\s+/s\s+",
            r"\.inf\b",
        ],
        "mitre": ["T1218.003"],
        "severity": "high",
        "description": "CMSTP INF file execution for UAC bypass",
    },
    "mavinject.exe": {
        "patterns": [
            r"/INJECTRUNNING\s+\d+",
        ],
        "mitre": ["T1218.013"],
        "severity": "critical",
        "description": "DLL injection via mavinject",
    },
    "powershell.exe": {
        "patterns": [
            r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}",
            r"IEX\s*\(",
            r"Invoke-Expression",
            r"Net\.WebClient",
            r"DownloadString",
            r"DownloadFile",
            r"-nop\s+-w\s+hidden",
            r"FromBase64String",
        ],
        "mitre": ["T1059.001"],
        "severity": "high",
        "description": "PowerShell executing encoded/download commands",
    },
    "pwsh.exe": {
        "patterns": [
            r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}",
            r"IEX\s*\(",
            r"Invoke-Expression",
            r"DownloadString",
        ],
        "mitre": ["T1059.001"],
        "severity": "high",
        "description": "PowerShell Core executing encoded/download commands",
    },
    "cscript.exe": {
        "patterns": [
            r"https?://",
            r"\\temp\\",
            r"\\appdata\\",
        ],
        "mitre": ["T1059.005"],
        "severity": "medium",
        "description": "Console script host executing from unusual location",
    },
    "wscript.exe": {
        "patterns": [
            r"https?://",
            r"\\temp\\",
            r"\\appdata\\",
        ],
        "mitre": ["T1059.005"],
        "severity": "medium",
        "description": "Windows script host executing from unusual location",
    },
}

# Suspicious parent-child process relationships
PARENT_CHILD_RULES = [
    {
        "parents": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                     "msaccess.exe", "mspub.exe", "visio.exe", "onenote.exe"],
        "children": ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
                      "wscript.exe", "cscript.exe", "certutil.exe", "regsvr32.exe",
                      "rundll32.exe", "bitsadmin.exe"],
        "severity": "critical",
        "mitre": "T1204.002",
        "description": "Office application spawned command interpreter or LOLBin",
    },
    {
        "parents": ["wmiprvse.exe"],
        "children": ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
                      "rundll32.exe"],
        "severity": "critical",
        "mitre": "T1047",
        "description": "WMI Provider Host spawned process (possible remote WMI execution)",
    },
    {
        "parents": ["svchost.exe"],
        "children": ["cmd.exe", "powershell.exe", "mshta.exe", "certutil.exe"],
        "severity": "high",
        "mitre": "T1543.003",
        "description": "Service Host spawned suspicious child process",
    },
    {
        "parents": ["explorer.exe"],
        "children": ["mshta.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe",
                      "cmstp.exe", "mavinject.exe"],
        "severity": "high",
        "mitre": "T1218",
        "description": "Explorer spawned proxy execution binary",
    },
    {
        "parents": ["taskeng.exe", "taskhostw.exe"],
        "children": ["cmd.exe", "powershell.exe", "mshta.exe", "certutil.exe",
                      "wscript.exe", "cscript.exe"],
        "severity": "high",
        "mitre": "T1053.005",
        "description": "Scheduled task spawned suspicious process",
    },
]

# LOLBins that should not make outbound network connections
NETWORK_SUSPICIOUS_LOLBINS = {
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msbuild.exe", "installutil.exe", "bitsadmin.exe", "esentutl.exe",
    "expand.exe", "replace.exe", "cmstp.exe", "presentationhost.exe",
    "mavinject.exe",
}


def parse_sysmon_evtx(evtx_path):
    """Parse a Sysmon EVTX file and extract Event ID 1 and 3 records."""
    if not HAS_EVTX:
        print("[WARN] python-evtx not installed. Use: pip install python-evtx")
        return [], []
    process_events = []
    network_events = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            event_id_el = root.find(".//e:System/e:EventID", ns)
            if event_id_el is None:
                continue
            event_id = event_id_el.text

            event_data = {}
            for data_el in root.findall(".//e:EventData/e:Data", ns):
                name = data_el.get("Name", "")
                event_data[name] = data_el.text or ""

            time_el = root.find(".//e:System/e:TimeCreated", ns)
            if time_el is not None:
                event_data["UtcTime"] = time_el.get("SystemTime", "")

            computer_el = root.find(".//e:System/e:Computer", ns)
            if computer_el is not None:
                event_data["Computer"] = computer_el.text or ""

            if event_id == "1":
                process_events.append(event_data)
            elif event_id == "3":
                network_events.append(event_data)

    return process_events, network_events


def parse_sysmon_json(json_path):
    """Parse Sysmon events from a JSON lines file."""
    process_events = []
    network_events = []
    with open(json_path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_id = str(event.get("EventID", event.get("event_id", "")))
            if event_id == "1":
                process_events.append(event)
            elif event_id == "3":
                network_events.append(event)
    return process_events, network_events


def load_events(path):
    """Load Sysmon events from EVTX or JSON file."""
    if path.lower().endswith(".evtx"):
        return parse_sysmon_evtx(path)
    elif path.lower().endswith(".json") or path.lower().endswith(".jsonl"):
        return parse_sysmon_json(path)
    else:
        # Try JSON first, fall back to EVTX
        try:
            return parse_sysmon_json(path)
        except Exception:
            return parse_sysmon_evtx(path)


def detect_lolbin_abuse(process_events):
    """Detect suspicious LOLBin command-line patterns."""
    alerts = []
    for event in process_events:
        image = event.get("Image", event.get("image", "")).lower()
        cmdline = event.get("CommandLine", event.get("command_line", ""))
        if not cmdline:
            continue

        binary_name = image.split("\\")[-1] if "\\" in image else image.split("/")[-1]

        for lolbin, config in LOLBIN_SIGNATURES.items():
            if binary_name == lolbin.lower():
                for pattern in config["patterns"]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        alerts.append({
                            "type": "lolbin_suspicious_cmdline",
                            "severity": config["severity"],
                            "lolbin": lolbin,
                            "description": config["description"],
                            "mitre": config["mitre"],
                            "command_line": cmdline[:500],
                            "image": event.get("Image", event.get("image", "")),
                            "parent_image": event.get("ParentImage", event.get("parent_image", "")),
                            "user": event.get("User", event.get("user", "")),
                            "hostname": event.get("Computer", event.get("hostname", "")),
                            "timestamp": event.get("UtcTime", event.get("timestamp", "")),
                            "pid": event.get("ProcessId", event.get("process_id", "")),
                            "ppid": event.get("ParentProcessId", event.get("parent_process_id", "")),
                            "matched_pattern": pattern,
                        })
                        break
    return alerts


def detect_parent_child_anomalies(process_events):
    """Detect suspicious parent-child process relationships."""
    alerts = []
    for event in process_events:
        parent = event.get("ParentImage", event.get("parent_image", "")).lower()
        child = event.get("Image", event.get("image", "")).lower()
        parent_name = parent.split("\\")[-1] if "\\" in parent else parent.split("/")[-1]
        child_name = child.split("\\")[-1] if "\\" in child else child.split("/")[-1]

        for rule in PARENT_CHILD_RULES:
            if parent_name in rule["parents"] and child_name in rule["children"]:
                alerts.append({
                    "type": "suspicious_parent_child",
                    "severity": rule["severity"],
                    "mitre": rule["mitre"],
                    "description": rule["description"],
                    "parent_process": parent,
                    "child_process": child,
                    "command_line": event.get("CommandLine", event.get("command_line", ""))[:500],
                    "user": event.get("User", event.get("user", "")),
                    "hostname": event.get("Computer", event.get("hostname", "")),
                    "timestamp": event.get("UtcTime", event.get("timestamp", "")),
                })
                break
    return alerts


def detect_lolbin_network(network_events):
    """Detect LOLBins making outbound network connections."""
    alerts = []
    for event in network_events:
        image = event.get("Image", event.get("image", "")).lower()
        binary_name = image.split("\\")[-1] if "\\" in image else image.split("/")[-1]

        if binary_name in NETWORK_SUSPICIOUS_LOLBINS:
            dest_ip = event.get("DestinationIp", event.get("destination_ip", ""))
            if dest_ip.startswith("127.") or dest_ip == "::1":
                continue
            alerts.append({
                "type": "lolbin_network_connection",
                "severity": "critical",
                "binary": binary_name,
                "image": event.get("Image", event.get("image", "")),
                "destination_ip": dest_ip,
                "destination_port": event.get("DestinationPort", event.get("destination_port", "")),
                "destination_hostname": event.get("DestinationHostname", event.get("destination_hostname", "")),
                "source_ip": event.get("SourceIp", event.get("source_ip", "")),
                "user": event.get("User", event.get("user", "")),
                "hostname": event.get("Computer", event.get("hostname", "")),
                "timestamp": event.get("UtcTime", event.get("timestamp", "")),
            })
    return alerts


def generate_statistics(process_events, all_alerts):
    """Generate summary statistics."""
    lolbin_exec_counts = defaultdict(int)
    for event in process_events:
        image = event.get("Image", event.get("image", "")).lower()
        binary_name = image.split("\\")[-1] if "\\" in image else image.split("/")[-1]
        if binary_name in [k.lower() for k in LOLBIN_SIGNATURES]:
            lolbin_exec_counts[binary_name] += 1

    severity_counts = defaultdict(int)
    type_counts = defaultdict(int)
    mitre_counts = defaultdict(int)
    for alert in all_alerts:
        severity_counts[alert.get("severity", "unknown")] += 1
        type_counts[alert.get("type", "unknown")] += 1
        mitre_ids = alert.get("mitre", [])
        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]
        for mid in mitre_ids:
            mitre_counts[mid] += 1

    return {
        "lolbin_execution_counts": dict(lolbin_exec_counts),
        "alert_severity_counts": dict(severity_counts),
        "alert_type_counts": dict(type_counts),
        "mitre_technique_counts": dict(mitre_counts),
        "total_alerts": len(all_alerts),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Living Off the Land (LOLBin) Detection Agent")
    print("Sysmon log analysis for LOLBin abuse, parent-child")
    print("anomalies, and LOLBin network connections")
    print("=" * 60)

    input_path = sys.argv[1] if len(sys.argv) > 1 else None

    if not input_path or not os.path.exists(input_path):
        print("\n[DEMO] Usage: python agent.py <sysmon_events.evtx|json|jsonl>")
        print("[*] Provide Sysmon event logs (EVTX or JSON) for LOLBin analysis.")
        print(f"[*] Monitors {len(LOLBIN_SIGNATURES)} LOLBins with "
              f"{sum(len(v['patterns']) for v in LOLBIN_SIGNATURES.values())} detection patterns")
        print(f"[*] {len(PARENT_CHILD_RULES)} parent-child anomaly rules")
        print(f"[*] {len(NETWORK_SUSPICIOUS_LOLBINS)} LOLBins monitored for network activity")
        sys.exit(0)

    print(f"\n[*] Loading events from: {input_path}")
    process_events, network_events = load_events(input_path)
    print(f"  Process creation events (EID 1): {len(process_events)}")
    print(f"  Network connection events (EID 3): {len(network_events)}")

    all_alerts = []

    print("\n--- LOLBin Command-Line Detection ---")
    cmdline_alerts = detect_lolbin_abuse(process_events)
    print(f"  Suspicious LOLBin executions: {len(cmdline_alerts)}")
    for a in cmdline_alerts[:15]:
        print(f"  [{a['severity'].upper()}] {a['lolbin']} on {a.get('hostname', '?')}")
        print(f"    MITRE: {', '.join(a['mitre']) if isinstance(a['mitre'], list) else a['mitre']}")
        print(f"    Cmd: {a['command_line'][:120]}")
        print(f"    Parent: {a['parent_image']}")
        print(f"    User: {a['user']}")
    all_alerts.extend(cmdline_alerts)

    print("\n--- Parent-Child Anomaly Detection ---")
    pc_alerts = detect_parent_child_anomalies(process_events)
    print(f"  Suspicious parent-child pairs: {len(pc_alerts)}")
    for a in pc_alerts[:15]:
        print(f"  [{a['severity'].upper()}] {a['description']}")
        print(f"    Parent: {a['parent_process']} -> Child: {a['child_process']}")
        print(f"    Cmd: {a['command_line'][:120]}")
    all_alerts.extend(pc_alerts)

    print("\n--- LOLBin Network Connections ---")
    net_alerts = detect_lolbin_network(network_events)
    print(f"  LOLBin network connections: {len(net_alerts)}")
    for a in net_alerts[:15]:
        print(f"  [CRITICAL] {a['binary']} -> {a['destination_ip']}:{a['destination_port']}"
              f" ({a.get('destination_hostname', 'N/A')})")
    all_alerts.extend(net_alerts)

    stats = generate_statistics(process_events, all_alerts)

    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {stats['total_alerts']} total alerts")
    for sev, count in sorted(stats["alert_severity_counts"].items()):
        print(f"  {sev.upper()}: {count}")
    if stats["mitre_technique_counts"]:
        print("\nMITRE ATT&CK techniques triggered:")
        for tech, count in sorted(stats["mitre_technique_counts"].items(), key=lambda x: -x[1]):
            print(f"  {tech}: {count}")
    if stats["lolbin_execution_counts"]:
        print("\nLOLBin execution counts:")
        for binary, count in sorted(stats["lolbin_execution_counts"].items(), key=lambda x: -x[1])[:20]:
            print(f"  {binary}: {count}")
