#!/usr/bin/env python3
"""Credential dumping detection agent using Sysmon and Windows Event Log analysis.

Parses EVTX logs for LSASS access (Event ID 10), SAM registry access,
DCSync indicators (Event ID 4662), and suspicious process patterns.
"""

import argparse
import json
import re
import struct
import sys
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as views
except ImportError:
    evtx = None

LSASS_SUSPICIOUS_ACCESS = {
    "0x1010": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (Mimikatz)",
    "0x1038": "PROCESS_VM_READ | PROCESS_QUERY_INFO | PROCESS_VM_WRITE",
    "0x1fffff": "PROCESS_ALL_ACCESS",
    "0x1410": "PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION",
    "0x0810": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
}

LSASS_LEGITIMATE_SOURCES = {
    "csrss.exe", "services.exe", "lsm.exe", "svchost.exe",
    "mrt.exe", "taskmgr.exe", "wmiprvse.exe",
}

DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

SAM_COMMANDS = [
    r"reg\s+save\s+hklm\\sam",
    r"reg\s+save\s+hklm\\security",
    r"reg\s+save\s+hklm\\system",
    r"vssadmin\s+create\s+shadow",
    r"ntdsutil.*ifm",
    r"copy.*ntds\.dit",
    r"esentutl.*ntds",
]

DUMP_TOOLS = {
    "mimikatz.exe": "CRITICAL", "procdump.exe": "HIGH", "procdump64.exe": "HIGH",
    "nanodump.exe": "CRITICAL", "pypykatz": "CRITICAL",
    "secretsdump.py": "CRITICAL", "lazagne.exe": "HIGH",
}


def parse_sysmon_event10(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>10</EventID>" not in xml:
                continue
            target = re.search(r'<Data Name="TargetImage">([^<]+)', xml)
            if not target or "lsass.exe" not in target.group(1).lower():
                continue
            source = re.search(r'<Data Name="SourceImage">([^<]+)', xml)
            access = re.search(r'<Data Name="GrantedAccess">([^<]+)', xml)
            source_user = re.search(r'<Data Name="SourceUser">([^<]+)', xml)
            time_created = re.search(r'SystemTime="([^"]+)"', xml)

            source_name = source.group(1) if source else ""
            source_basename = source_name.rsplit("\\", 1)[-1].lower()
            access_mask = access.group(1) if access else ""

            if source_basename in LSASS_LEGITIMATE_SOURCES:
                continue

            severity = "HIGH"
            technique = "T1003.001"
            if access_mask.lower() in LSASS_SUSPICIOUS_ACCESS:
                severity = "CRITICAL"

            findings.append({
                "event_id": 10,
                "timestamp": time_created.group(1) if time_created else "",
                "source_image": source_name,
                "target_image": target.group(1),
                "granted_access": access_mask,
                "access_meaning": LSASS_SUSPICIOUS_ACCESS.get(access_mask.lower(), ""),
                "source_user": source_user.group(1) if source_user else "",
                "severity": severity,
                "mitre": technique,
            })
    return findings


def parse_security_4662(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>4662</EventID>" not in xml:
                continue
            props = re.search(r'<Data Name="Properties">([^<]+)', xml)
            if not props:
                continue
            prop_text = props.group(1).lower()
            matched_guids = []
            for guid, name in DCSYNC_GUIDS.items():
                if guid in prop_text:
                    matched_guids.append(name)
            if not matched_guids:
                continue
            subject = re.search(r'<Data Name="SubjectUserName">([^<]+)', xml)
            subject_name = subject.group(1) if subject else ""
            if subject_name.endswith("$"):
                continue
            time_created = re.search(r'SystemTime="([^"]+)"', xml)
            findings.append({
                "event_id": 4662,
                "timestamp": time_created.group(1) if time_created else "",
                "subject_user": subject_name,
                "replication_rights": matched_guids,
                "severity": "CRITICAL",
                "mitre": "T1003.006",
                "description": "DCSync - non-DC account requesting replication",
            })
    return findings


def detect_sam_dump_commands(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            for pattern in SAM_COMMANDS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line": line_num,
                        "command": line.strip()[:200],
                        "pattern": pattern,
                        "severity": "CRITICAL",
                        "mitre": "T1003.002",
                    })
            for tool, sev in DUMP_TOOLS.items():
                if tool.lower() in line.lower():
                    findings.append({
                        "line": line_num,
                        "tool": tool,
                        "severity": sev,
                        "mitre": "T1003",
                    })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Credential Dumping Detector")
    parser.add_argument("--sysmon-log", help="Sysmon EVTX file for LSASS access (Event 10)")
    parser.add_argument("--security-log", help="Security EVTX file for DCSync (Event 4662)")
    parser.add_argument("--command-log", help="Text log to scan for SAM dump commands")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.sysmon_log:
        lsass = parse_sysmon_event10(args.sysmon_log)
        if isinstance(lsass, dict) and "error" in lsass:
            results["lsass_error"] = lsass["error"]
        else:
            results["lsass_access"] = lsass
            results["findings"].extend(lsass)

    if args.security_log:
        dcsync = parse_security_4662(args.security_log)
        if isinstance(dcsync, dict) and "error" in dcsync:
            results["dcsync_error"] = dcsync["error"]
        else:
            results["dcsync_events"] = dcsync
            results["findings"].extend(dcsync)

    if args.command_log:
        sam = detect_sam_dump_commands(args.command_log)
        results["sam_dump_commands"] = sam
        results["findings"].extend(sam)

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
