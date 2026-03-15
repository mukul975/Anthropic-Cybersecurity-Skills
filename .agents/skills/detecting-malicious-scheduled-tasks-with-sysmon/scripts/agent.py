#!/usr/bin/env python3
"""Sysmon scheduled task detection agent for hunting malicious persistence."""

import json
import sys
import argparse
import re
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict


SUSPICIOUS_PATHS = [
    r"\\users\\public\\", r"\\programdata\\", r"\\windows\\temp\\",
    r"\\appdata\\local\\temp\\", r"\\downloads\\", r"\\desktop\\",
    r"c:\\temp\\", r"\\recycle",
]

SUSPICIOUS_COMMANDS = [
    r"powershell.*-enc", r"powershell.*-e\s+", r"powershell.*downloadstring",
    r"powershell.*iex", r"powershell.*invoke-expression",
    r"cmd.*/c\s+", r"mshta\s+", r"certutil.*-urlcache",
    r"bitsadmin.*/transfer", r"regsvr32.*/s.*/u",
    r"rundll32.*javascript", r"wscript.*\.vbs",
]


def parse_evtx_xml(xml_path):
    """Parse exported Windows Event Log XML for Sysmon and Security events."""
    events = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        for event_el in root.findall(".//e:Event", ns):
            system = event_el.find("e:System", ns)
            event_data = event_el.find("e:EventData", ns)
            if system is None:
                continue
            event_id = int(system.findtext("e:EventID", "0", ns))
            data = {}
            if event_data is not None:
                for d in event_data.findall("e:Data", ns):
                    name = d.get("Name", "")
                    data[name] = d.text or ""
            events.append({
                "event_id": event_id,
                "timestamp": system.findtext("e:TimeCreated/@SystemTime", "", ns)
                             or system.find("e:TimeCreated", ns).get("SystemTime", "") if system.find("e:TimeCreated", ns) is not None else "",
                "computer": system.findtext("e:Computer", "", ns),
                "data": data,
            })
    except ET.ParseError as e:
        return [{"error": f"XML parse error: {e}"}]
    return events


def detect_schtasks_creation(events):
    """Detect suspicious schtasks.exe process creation (Sysmon Event 1)."""
    findings = []
    for evt in events:
        if evt["event_id"] != 1:
            continue
        image = evt["data"].get("Image", "").lower()
        cmdline = evt["data"].get("CommandLine", "")
        parent = evt["data"].get("ParentImage", "")

        if "schtasks" not in image and "at.exe" not in image:
            continue
        if "/create" not in cmdline.lower() and "/change" not in cmdline.lower():
            continue

        severity = "MEDIUM"
        reasons = []

        for pattern in SUSPICIOUS_PATHS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                severity = "HIGH"
                reasons.append(f"Task executes from suspicious path: {pattern}")

        for pattern in SUSPICIOUS_COMMANDS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                severity = "CRITICAL"
                reasons.append(f"Suspicious command pattern: {pattern}")

        if "/s " in cmdline.lower() or "/s\t" in cmdline:
            severity = "CRITICAL"
            reasons.append("Remote task creation detected (lateral movement)")

        if "-enc" in cmdline.lower() or "-e " in cmdline.lower():
            encoded = re.search(r'-[eE](?:nc)?\s+([A-Za-z0-9+/=]{20,})', cmdline)
            if encoded:
                try:
                    decoded = base64.b64decode(encoded.group(1)).decode("utf-16-le", errors="replace")
                    reasons.append(f"Decoded command: {decoded[:150]}")
                except Exception:
                    pass

        if not reasons:
            reasons.append("Scheduled task creation detected")

        findings.append({
            "timestamp": evt["timestamp"],
            "computer": evt["computer"],
            "image": image,
            "command_line": cmdline[:300],
            "parent_process": parent,
            "user": evt["data"].get("User", ""),
            "severity": severity,
            "reasons": reasons,
            "mitre": "T1053.005",
        })
    return findings


def detect_task_file_creation(events):
    """Detect task XML file creation in System32\\Tasks (Sysmon Event 11)."""
    findings = []
    for evt in events:
        if evt["event_id"] != 11:
            continue
        target = evt["data"].get("TargetFilename", "")
        if "\\windows\\system32\\tasks\\" not in target.lower():
            continue
        process = evt["data"].get("Image", "")
        findings.append({
            "timestamp": evt["timestamp"],
            "task_file": target,
            "created_by": process,
            "severity": "MEDIUM",
            "detail": "New scheduled task XML file created",
        })
    return findings


def detect_event_4698(events):
    """Detect Security Event 4698 — scheduled task registered."""
    findings = []
    for evt in events:
        if evt["event_id"] != 4698:
            continue
        task_name = evt["data"].get("TaskName", "")
        task_content = evt["data"].get("TaskContent", "")
        user = evt["data"].get("SubjectUserName", "")
        severity = "MEDIUM"
        reasons = []

        for pattern in SUSPICIOUS_COMMANDS:
            if re.search(pattern, task_content, re.IGNORECASE):
                severity = "CRITICAL"
                reasons.append(f"Task content contains: {pattern}")

        findings.append({
            "timestamp": evt["timestamp"],
            "task_name": task_name,
            "registered_by": user,
            "severity": severity,
            "reasons": reasons or ["New task registered"],
            "task_content_preview": task_content[:200],
        })
    return findings


def run_audit(args):
    """Execute scheduled task detection audit."""
    print(f"\n{'='*60}")
    print(f"  MALICIOUS SCHEDULED TASK DETECTION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.evtx_xml:
        events = parse_evtx_xml(args.evtx_xml)
        report["total_events"] = len(events)
        print(f"Parsed {len(events)} events from {args.evtx_xml}\n")

        schtask_findings = detect_schtasks_creation(events)
        report["schtasks_findings"] = schtask_findings
        print(f"--- SCHTASKS CREATION (Event 1) — {len(schtask_findings)} findings ---")
        for f in schtask_findings[:15]:
            print(f"  [{f['severity']}] {f['computer']}: {f['command_line'][:80]}")
            for r in f["reasons"]:
                print(f"    -> {r[:100]}")

        file_findings = detect_task_file_creation(events)
        report["task_file_findings"] = file_findings
        print(f"\n--- TASK FILE CREATION (Event 11) — {len(file_findings)} findings ---")
        for f in file_findings[:10]:
            print(f"  [{f['severity']}] {f['task_file']}")

        reg_findings = detect_event_4698(events)
        report["event_4698_findings"] = reg_findings
        print(f"\n--- TASK REGISTRATION (Event 4698) — {len(reg_findings)} findings ---")
        for f in reg_findings[:10]:
            print(f"  [{f['severity']}] {f['task_name']} by {f['registered_by']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Sysmon Scheduled Task Detection Agent")
    parser.add_argument("--evtx-xml", required=True,
                        help="Exported event log XML file to analyze")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
