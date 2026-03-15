#!/usr/bin/env python3
"""Detect credential dumping techniques via Sysmon/Windows event log analysis."""

import json
import re
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime


LSASS_GRANTED_ACCESS_SUSPICIOUS = {
    "0x1010": "PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION (Mimikatz-style)",
    "0x1410": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (procdump-style)",
    "0x1FFFFF": "PROCESS_ALL_ACCESS (full access to LSASS)",
    "0x1438": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE",
    "0x40": "PROCESS_DUP_HANDLE (handle duplication for indirect access)",
}

SUSPICIOUS_CALLERS = [
    "mimikatz", "procdump", "rundll32.exe", "taskmgr.exe",
    "powershell.exe", "cmd.exe", "wmic.exe", "cscript.exe", "wscript.exe",
]

SAM_EXPORT_PATTERNS = [
    r"reg\s+save\s+hklm\\sam",
    r"reg\s+save\s+hklm\\security",
    r"reg\s+save\s+hklm\\system",
    r"esentutl.*ntds\.dit",
    r"ntdsutil.*\"activate instance ntds\"",
    r"vssadmin\s+create\s+shadow",
    r"copy\s+\\\\.*\\c\$.*ntds\.dit",
    r"secretsdump",
]

COMSVCS_PATTERNS = [
    r"comsvcs\.dll.*MiniDump",
    r"comsvcs\.dll.*#24",
    r"rundll32.*comsvcs",
]


def parse_sysmon_xml(xml_path):
    """Parse Sysmon event log XML export for Event ID 10 (ProcessAccess)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    for event_el in root.findall(".//e:Event", ns):
        sys_el = event_el.find("e:System", ns)
        event_id = int(sys_el.find("e:EventID", ns).text)
        time_created = sys_el.find("e:TimeCreated", ns).attrib.get("SystemTime", "")
        data_el = event_el.find("e:EventData", ns)
        fields = {}
        for d in data_el.findall("e:Data", ns):
            fields[d.attrib.get("Name", "")] = d.text or ""
        events.append({"event_id": event_id, "timestamp": time_created, **fields})
    return events


def detect_lsass_access(events):
    """Detect suspicious ProcessAccess (Event ID 10) targeting lsass.exe."""
    alerts = []
    for ev in events:
        if ev["event_id"] != 10:
            continue
        target = ev.get("TargetImage", "").lower()
        if "lsass.exe" not in target:
            continue
        granted = ev.get("GrantedAccess", "")
        source_image = ev.get("SourceImage", "").lower()
        source_name = source_image.split("\\")[-1] if source_image else ""
        severity = "medium"
        reasons = []
        if granted in LSASS_GRANTED_ACCESS_SUSPICIOUS:
            reasons.append(f"Suspicious GrantedAccess {granted}: {LSASS_GRANTED_ACCESS_SUSPICIOUS[granted]}")
            severity = "critical" if granted == "0x1FFFFF" else "high"
        if any(s in source_name for s in SUSPICIOUS_CALLERS):
            reasons.append(f"Suspicious calling process: {source_name}")
            severity = "critical"
        if not reasons:
            continue
        alerts.append({
            "detection": "LSASS Memory Access",
            "mitre_technique": "T1003.001",
            "timestamp": ev["timestamp"],
            "source_process": ev.get("SourceImage", ""),
            "source_pid": ev.get("SourceProcessId", ""),
            "target_process": ev.get("TargetImage", ""),
            "granted_access": granted,
            "call_trace": ev.get("CallTrace", "")[:200],
            "severity": severity,
            "reasons": reasons,
            "user": ev.get("SourceUser", ev.get("User", "")),
            "host": ev.get("Computer", ""),
        })
    return alerts


def detect_credential_commands(events):
    """Detect SAM/NTDS.dit export and comsvcs.dll dump commands from Event ID 1 or 4688."""
    alerts = []
    for ev in events:
        if ev["event_id"] not in (1, 4688):
            continue
        cmdline = ev.get("CommandLine", ev.get("ProcessCommandLine", "")).lower()
        if not cmdline:
            continue
        for pattern in SAM_EXPORT_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                technique = "T1003.002" if "sam" in cmdline or "security" in cmdline else "T1003.003"
                alerts.append({
                    "detection": "Registry Hive / NTDS.dit Export",
                    "mitre_technique": technique,
                    "timestamp": ev["timestamp"],
                    "command_line": ev.get("CommandLine", ev.get("ProcessCommandLine", "")),
                    "process": ev.get("Image", ev.get("NewProcessName", "")),
                    "user": ev.get("User", ev.get("SubjectUserName", "")),
                    "severity": "critical",
                })
                break
        for pattern in COMSVCS_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                alerts.append({
                    "detection": "LSASS Dump via comsvcs.dll",
                    "mitre_technique": "T1003.001",
                    "timestamp": ev["timestamp"],
                    "command_line": ev.get("CommandLine", ev.get("ProcessCommandLine", "")),
                    "process": ev.get("Image", ev.get("NewProcessName", "")),
                    "user": ev.get("User", ev.get("SubjectUserName", "")),
                    "severity": "critical",
                })
                break
    return alerts


def detect_ntdll_access(events):
    """Detect suspicious ntdll.dll access patterns in CallTrace (Mimikatz signature)."""
    alerts = []
    for ev in events:
        if ev["event_id"] != 10:
            continue
        call_trace = ev.get("CallTrace", "")
        if "ntdll.dll" in call_trace.lower() and "UNKNOWN" in call_trace:
            target = ev.get("TargetImage", "").lower()
            if "lsass.exe" in target:
                alerts.append({
                    "detection": "NTDLL Suspicious CallTrace (Mimikatz Signature)",
                    "mitre_technique": "T1003.001",
                    "timestamp": ev["timestamp"],
                    "source_process": ev.get("SourceImage", ""),
                    "call_trace_snippet": call_trace[:300],
                    "severity": "critical",
                })
    return alerts


def generate_splunk_queries():
    """Return SPL detection queries for credential dumping."""
    return {
        "lsass_access": (
            'index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" '
            'GrantedAccess IN ("0x1010","0x1FFFFF","0x1410","0x1438") '
            '| stats count by SourceImage, GrantedAccess, Computer'
        ),
        "comsvcs_dump": (
            'index=sysmon EventCode=1 CommandLine="*comsvcs*MiniDump*" '
            'OR CommandLine="*comsvcs*#24*" | table _time, Computer, User, CommandLine'
        ),
        "sam_export": (
            'index=sysmon EventCode=1 (CommandLine="*reg*save*hklm\\\\sam*" '
            'OR CommandLine="*reg*save*hklm\\\\security*") '
            '| table _time, Computer, User, CommandLine'
        ),
        "ntds_extraction": (
            'index=sysmon EventCode=1 (CommandLine="*ntdsutil*" '
            'OR CommandLine="*vssadmin*create*shadow*") '
            '| table _time, Computer, User, CommandLine'
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Credential Dumping Detection Agent")
    parser.add_argument("--sysmon-xml", help="Path to Sysmon event log XML export")
    parser.add_argument("--output", default="credential_dump_report.json", help="Output report path")
    parser.add_argument("--show-splunk", action="store_true", help="Print Splunk detection queries")
    args = parser.parse_args()

    if args.show_splunk:
        for name, spl in generate_splunk_queries().items():
            print(f"\n--- {name} ---\n{spl}")
        return

    if not args.sysmon_xml:
        print("[!] Provide --sysmon-xml path or use --show-splunk for detection queries")
        return

    events = parse_sysmon_xml(args.sysmon_xml)
    print(f"[+] Parsed {len(events)} Sysmon/Security events")

    lsass_alerts = detect_lsass_access(events)
    cmd_alerts = detect_credential_commands(events)
    ntdll_alerts = detect_ntdll_access(events)

    report = {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "total_events": len(events),
        "detections": {
            "lsass_memory_access": lsass_alerts,
            "credential_export_commands": cmd_alerts,
            "ntdll_suspicious_calltrace": ntdll_alerts,
        },
        "total_alerts": len(lsass_alerts) + len(cmd_alerts) + len(ntdll_alerts),
        "mitre_techniques": ["T1003.001", "T1003.002", "T1003.003"],
        "splunk_queries": generate_splunk_queries(),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] LSASS access alerts: {len(lsass_alerts)}")
    print(f"[+] Credential export commands: {len(cmd_alerts)}")
    print(f"[+] NTDLL suspicious traces: {len(ntdll_alerts)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
