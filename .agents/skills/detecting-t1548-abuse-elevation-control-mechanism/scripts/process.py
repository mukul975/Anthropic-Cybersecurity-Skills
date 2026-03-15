#!/usr/bin/env python3
"""
T1548 Elevation Control Abuse Detection Script
Detects UAC bypass attempts via registry modifications, auto-elevating
process abuse, and unusual privilege escalation patterns.
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

UAC_REGISTRY_PATTERNS = [
    r"(?i)ms-settings\\shell\\open\\command",
    r"(?i)mscfile\\shell\\open\\command",
    r"(?i)exefile\\shell\\open\\command",
    r"(?i)Folder\\shell\\open\\command",
    r"(?i)Policies\\System\\EnableLUA",
    r"(?i)Policies\\System\\ConsentPromptBehaviorAdmin",
]

AUTO_ELEVATE_BINARIES = {
    "fodhelper.exe", "computerdefaults.exe", "eventvwr.exe",
    "sdclt.exe", "slui.exe", "cmstp.exe", "cleanmgr.exe",
}

EXPECTED_PARENTS = {"explorer.exe", "svchost.exe", "services.exe", "winlogon.exe"}


def parse_events(input_path: str) -> list[dict]:
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


def detect_elevation_abuse(events: list[dict]) -> list[dict]:
    findings = []
    for event in events:
        event_code = str(event.get("EventCode", event.get("EventID", "")))
        computer = event.get("Computer", event.get("host", ""))
        timestamp = event.get("UtcTime", event.get("_time", ""))
        user = event.get("User", event.get("user", ""))

        if event_code in ("12", "13"):
            target_obj = event.get("TargetObject", "")
            details = event.get("Details", "")
            image = event.get("Image", "")
            for pattern in UAC_REGISTRY_PATTERNS:
                if re.search(pattern, target_obj):
                    findings.append({
                        "timestamp": timestamp, "computer": computer, "user": user,
                        "detection_type": "UAC_Registry_Modification",
                        "registry_key": target_obj, "value": details,
                        "modifying_process": image,
                        "severity": "CRITICAL", "technique": "T1548.002",
                    })
                    break

        elif event_code == "1":
            image = event.get("Image", "")
            parent = event.get("ParentImage", "")
            cmdline = event.get("CommandLine", "")
            image_name = image.split("\\")[-1].lower() if image else ""
            parent_name = parent.split("\\")[-1].lower() if parent else ""

            if image_name in AUTO_ELEVATE_BINARIES and parent_name not in EXPECTED_PARENTS:
                findings.append({
                    "timestamp": timestamp, "computer": computer, "user": user,
                    "detection_type": "Auto_Elevate_Abuse",
                    "auto_elevate_binary": image, "parent_process": parent,
                    "command_line": cmdline,
                    "severity": "HIGH", "technique": "T1548.002",
                })

            if parent_name in AUTO_ELEVATE_BINARIES and image_name in {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
                findings.append({
                    "timestamp": timestamp, "computer": computer, "user": user,
                    "detection_type": "Elevated_Child_Process",
                    "child_process": image, "auto_elevate_parent": parent,
                    "command_line": cmdline,
                    "severity": "CRITICAL", "technique": "T1548.002",
                })

    return sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))


def run_hunt(input_path: str, output_dir: str) -> None:
    print(f"[*] T1548 Elevation Control Abuse Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_events(input_path)
    findings = detect_elevation_abuse(events)
    print(f"[!] Elevation abuse detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "elevation_abuse_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-UAC-{datetime.date.today().isoformat()}",
                    "findings": findings}, f, indent=2)
    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="T1548 Elevation Control Abuse Detection")
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", default="./elevation_hunt_output")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
