#!/usr/bin/env python3
"""Agent for hunting shadow copy deletion activity indicating ransomware or anti-forensics."""

import json
import argparse
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None


SHADOW_PATTERNS = [
    r"vssadmin\s+delete\s+shadows",
    r"vssadmin\.exe.*delete.*shadows",
    r"wmic\s+shadowcopy\s+delete",
    r"Get-WmiObject\s+Win32_ShadowCopy.*Delete",
    r"gwmi\s+Win32_ShadowCopy.*Remove",
    r"bcdedit.*recoveryenabled.*no",
    r"bcdedit.*/set.*bootstatuspolicy\s+ignoreallfailures",
    r"wbadmin\s+delete\s+catalog",
    r"Win32_ShadowCopy.*\.Delete",
    r"powershell.*shadowcopy.*delete",
]

RECOVERY_DISABLE_PATTERNS = [
    r"bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no",
    r"reagentc\s+/disable",
    r"vssadmin\s+resize\s+shadowstorage.*maxsize=",
]


def parse_evtx_file(evtx_path):
    """Parse Windows EVTX file for shadow copy deletion events."""
    if evtx is None:
        return []
    events = []
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            xml_str = record.xml()
            try:
                root = ET.fromstring(xml_str)
                ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                event_id_el = root.find(".//ns:EventID", ns)
                if event_id_el is None:
                    continue
                event_id = int(event_id_el.text)
                if event_id in (1, 4688, 4698):
                    data_elements = root.findall(".//ns:Data", ns)
                    event_data = {}
                    for d in data_elements:
                        name = d.get("Name", "")
                        event_data[name] = d.text or ""
                    events.append({
                        "event_id": event_id,
                        "timestamp": record.timestamp().isoformat(),
                        "data": event_data,
                    })
            except ET.ParseError:
                continue
    return events


def scan_command_line(cmd_line):
    """Check a command line string against shadow copy deletion patterns."""
    findings = []
    for pattern in SHADOW_PATTERNS:
        if re.search(pattern, cmd_line, re.IGNORECASE):
            findings.append({"pattern": pattern, "severity": "CRITICAL", "category": "shadow_copy_deletion"})
    for pattern in RECOVERY_DISABLE_PATTERNS:
        if re.search(pattern, cmd_line, re.IGNORECASE):
            findings.append({"pattern": pattern, "severity": "HIGH", "category": "recovery_disable"})
    return findings


def hunt_evtx(evtx_path):
    """Hunt for shadow copy deletion in EVTX logs."""
    events = parse_evtx_file(evtx_path)
    results = []
    for event in events:
        cmd = event["data"].get("CommandLine", "") or event["data"].get("TaskContent", "")
        if not cmd:
            cmd = " ".join(event["data"].values())
        matches = scan_command_line(cmd)
        if matches:
            results.append({
                "timestamp": event["timestamp"],
                "event_id": event["event_id"],
                "command_line": cmd[:500],
                "user": event["data"].get("SubjectUserName", event["data"].get("User", "")),
                "computer": event["data"].get("Computer", ""),
                "findings": matches,
            })
    return results


def scan_sysmon_json(log_path):
    """Scan JSON-exported Sysmon logs for shadow copy deletion."""
    results = []
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            cmd = entry.get("CommandLine", entry.get("command_line", ""))
            image = entry.get("Image", entry.get("process_name", ""))
            matches = scan_command_line(cmd)
            if matches:
                results.append({
                    "timestamp": entry.get("UtcTime", entry.get("timestamp", "")),
                    "image": image,
                    "command_line": cmd[:500],
                    "parent_image": entry.get("ParentImage", ""),
                    "user": entry.get("User", ""),
                    "hostname": entry.get("Computer", entry.get("hostname", "")),
                    "findings": matches,
                })
    return results


def generate_sigma_rule():
    """Generate a Sigma detection rule for shadow copy deletion."""
    return {
        "title": "Shadow Copy Deletion via Vssadmin or WMIC",
        "id": "faa6e1e2-5b4c-4e1a-bb2a-5c1f3e5e3f0a",
        "status": "production",
        "level": "critical",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_vssadmin": {
                "Image|endswith": "\\vssadmin.exe",
                "CommandLine|contains|all": ["delete", "shadows"],
            },
            "selection_wmic": {
                "Image|endswith": "\\wmic.exe",
                "CommandLine|contains|all": ["shadowcopy", "delete"],
            },
            "selection_powershell": {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains": "Win32_ShadowCopy",
            },
            "condition": "selection_vssadmin or selection_wmic or selection_powershell",
        },
        "tags": ["attack.impact", "attack.t1490"],
    }


def main():
    parser = argparse.ArgumentParser(description="Shadow Copy Deletion Hunter")
    parser.add_argument("--evtx", help="Path to EVTX log file")
    parser.add_argument("--json-log", help="Path to JSON Sysmon log")
    parser.add_argument("--output", default="shadow_copy_hunt_report.json")
    parser.add_argument("--action", choices=["hunt_evtx", "hunt_json", "sigma", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("hunt_evtx", "full") and args.evtx:
        results = hunt_evtx(args.evtx)
        report["findings"]["evtx_hits"] = results
        print(f"[+] EVTX shadow copy deletion events: {len(results)}")

    if args.action in ("hunt_json", "full") and args.json_log:
        results = scan_sysmon_json(args.json_log)
        report["findings"]["sysmon_hits"] = results
        print(f"[+] Sysmon JSON shadow copy hits: {len(results)}")

    if args.action in ("sigma", "full"):
        rule = generate_sigma_rule()
        report["findings"]["sigma_rule"] = rule
        print("[+] Sigma rule generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
