#!/usr/bin/env python3
"""
T1055 Process Injection Detection Script
Analyzes Sysmon Event 8 (CreateRemoteThread), Event 10 (ProcessAccess),
and Event 25 (ProcessTampering) to identify process injection activity.
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

HIGH_VALUE_TARGETS = {
    "svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe",
    "csrss.exe", "services.exe", "spoolsv.exe", "dllhost.exe",
    "runtimebroker.exe", "dwm.exe", "smss.exe",
}

LEGITIMATE_SOURCES = {
    "csrss.exe", "lsass.exe", "services.exe", "svchost.exe",
    "msmpe ng.exe", "securityhealthservice.exe", "vmtoolsd.exe",
    "taskmgr.exe", "procexp64.exe", "procexp.exe", "procmon.exe",
}

SUSPICIOUS_ACCESS_MASKS = {
    "0x1fffff": "PROCESS_ALL_ACCESS",
    "0x1f3fff": "Nearly full access",
    "0x143a": "Mimikatz-style access",
    "0x1f0fff": "High privilege access",
    "0x0040": "PROCESS_VM_READ (credential access)",
}


def parse_events(input_path: str) -> list[dict]:
    """Parse Sysmon event logs."""
    path = Path(input_path)
    events = []
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            events = data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            events = [dict(row) for row in csv.DictReader(f)]
    return events


def detect_injection(events: list[dict]) -> list[dict]:
    """Detect process injection from Sysmon events."""
    findings = []

    for event in events:
        event_code = str(event.get("EventCode", event.get("EventID", event.get("event_id", ""))))
        computer = event.get("Computer", event.get("host", ""))
        timestamp = event.get("UtcTime", event.get("_time", event.get("timestamp", "")))
        user = event.get("User", event.get("user", ""))

        if event_code == "8":
            source = event.get("SourceImage", "")
            target = event.get("TargetImage", "")
            source_name = source.split("\\")[-1].lower() if source else ""
            target_name = target.split("\\")[-1].lower() if target else ""

            if source_name in LEGITIMATE_SOURCES:
                continue
            if source == target:
                continue

            severity = "CRITICAL" if target_name in HIGH_VALUE_TARGETS else "HIGH"
            findings.append({
                "timestamp": timestamp,
                "computer": computer,
                "event_type": "CreateRemoteThread",
                "sysmon_event": 8,
                "source_image": source,
                "target_image": target,
                "severity": severity,
                "technique": "T1055.001",
                "description": f"Remote thread created by {source_name} in {target_name}",
            })

        elif event_code == "10":
            source = event.get("SourceImage", "")
            target = event.get("TargetImage", "")
            access = event.get("GrantedAccess", "").lower()
            source_name = source.split("\\")[-1].lower() if source else ""
            target_name = target.split("\\")[-1].lower() if target else ""

            if source_name in LEGITIMATE_SOURCES:
                continue
            if source == target:
                continue
            if access not in SUSPICIOUS_ACCESS_MASKS:
                continue

            severity = "CRITICAL" if target_name == "lsass.exe" else "HIGH"
            findings.append({
                "timestamp": timestamp,
                "computer": computer,
                "event_type": "ProcessAccess",
                "sysmon_event": 10,
                "source_image": source,
                "target_image": target,
                "granted_access": access,
                "access_description": SUSPICIOUS_ACCESS_MASKS.get(access, "Unknown"),
                "severity": severity,
                "technique": "T1055",
                "description": f"{source_name} accessed {target_name} with {access} ({SUSPICIOUS_ACCESS_MASKS.get(access, '')})",
            })

        elif event_code == "25":
            image = event.get("Image", "")
            tampering_type = event.get("Type", "")
            findings.append({
                "timestamp": timestamp,
                "computer": computer,
                "event_type": "ProcessTampering",
                "sysmon_event": 25,
                "image": image,
                "tampering_type": tampering_type,
                "severity": "CRITICAL",
                "technique": "T1055.012",
                "description": f"Process tampering detected: {image} - {tampering_type}",
            })

    return sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute process injection detection hunt."""
    print(f"[*] T1055 Process Injection Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_events(input_path)
    print(f"[*] Loaded {len(events)} Sysmon events")

    findings = detect_injection(events)
    print(f"[!] Injection detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "injection_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-INJECT-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "findings_count": len(findings),
            "findings": findings,
        }, f, indent=2)

    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="T1055 Process Injection Detection")
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", default="./injection_hunt_output")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
