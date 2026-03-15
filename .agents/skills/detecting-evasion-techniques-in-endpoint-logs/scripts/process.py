#!/usr/bin/env python3
"""
Endpoint Evasion Technique Detector

Analyzes Windows event logs (exported as EVTX/CSV) for common defense
evasion techniques mapped to MITRE ATT&CK TA0005.
"""

import json
import csv
import re
import sys
import os
from collections import defaultdict
from datetime import datetime


EVASION_PATTERNS = {
    "T1070.001-log_clearing": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "severity": "high",
        "patterns": [
            r"wevtutil\s+(cl|clear-log)",
            r"Clear-EventLog",
            r"Remove-EventLog",
        ],
        "event_ids": ["1102", "104"],
    },
    "T1055-process_injection": {
        "name": "Process Injection",
        "severity": "high",
        "sysmon_event_ids": ["8", "10", "25"],
        "patterns": [
            r"VirtualAllocEx",
            r"WriteProcessMemory",
            r"CreateRemoteThread",
            r"NtMapViewOfSection",
        ],
    },
    "T1562.001-disable_security": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "severity": "critical",
        "patterns": [
            r"Set-MpPreference\s+-Disable",
            r"sc\s+(stop|config)\s+(WinDefend|Sense|MBAMService)",
            r"net\s+stop\s+(windefend|sense|csagent)",
            r"DisableAntiSpyware",
            r"DisableRealtimeMonitoring",
        ],
    },
    "T1036-masquerading": {
        "name": "Masquerading",
        "severity": "medium",
        "suspicious_paths": {
            "svchost.exe": r"C:\\Windows\\System32\\svchost\.exe",
            "csrss.exe": r"C:\\Windows\\System32\\csrss\.exe",
            "lsass.exe": r"C:\\Windows\\System32\\lsass\.exe",
            "smss.exe": r"C:\\Windows\\System32\\smss\.exe",
            "services.exe": r"C:\\Windows\\System32\\services\.exe",
        },
    },
    "T1218-lolbin_abuse": {
        "name": "System Binary Proxy Execution",
        "severity": "high",
        "patterns": [
            r"mshta\.exe.*https?://",
            r"mshta\.exe.*javascript:",
            r"certutil\.exe.*-urlcache",
            r"certutil\.exe.*-decode",
            r"regsvr32\.exe.*/s.*/n.*/u.*/i:",
            r"rundll32\.exe.*javascript:",
            r"MSBuild\.exe(?!.*\.(sln|csproj|vbproj))",
            r"installutil\.exe.*/logfile=",
        ],
    },
    "T1070.006-timestomping": {
        "name": "Indicator Removal: Timestomp",
        "severity": "medium",
        "sysmon_event_ids": ["2"],
    },
}


def analyze_sysmon_csv(csv_path: str) -> list:
    """Analyze Sysmon events exported as CSV for evasion techniques."""
    detections = []

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get("Event ID", row.get("EventID", ""))
            message = row.get("Message", row.get("Details", ""))
            command_line = row.get("CommandLine", "")
            image = row.get("Image", row.get("Process Name", ""))
            timestamp = row.get("Date and Time", row.get("TimeCreated", ""))

            full_text = f"{message} {command_line} {image}".lower()

            for technique_id, technique in EVASION_PATTERNS.items():
                detected = False
                detection_detail = ""

                if "event_ids" in technique and event_id in technique["event_ids"]:
                    detected = True
                    detection_detail = f"Event ID {event_id} detected"

                if "sysmon_event_ids" in technique and event_id in technique["sysmon_event_ids"]:
                    detected = True
                    detection_detail = f"Sysmon Event ID {event_id}"

                for pattern in technique.get("patterns", []):
                    if re.search(pattern, full_text, re.IGNORECASE):
                        detected = True
                        detection_detail = f"Pattern match: {pattern}"
                        break

                if "suspicious_paths" in technique and image:
                    image_lower = image.lower()
                    for proc_name, expected_path in technique["suspicious_paths"].items():
                        if proc_name in image_lower:
                            if not re.match(expected_path, image, re.IGNORECASE):
                                detected = True
                                detection_detail = f"Masquerading: {proc_name} from unexpected path {image}"

                if detected:
                    detections.append({
                        "timestamp": timestamp,
                        "technique_id": technique_id.split("-")[0],
                        "technique_name": technique["name"],
                        "severity": technique["severity"],
                        "event_id": event_id,
                        "process": image,
                        "command_line": command_line[:300],
                        "detail": detection_detail,
                        "host": row.get("Computer", row.get("host", "")),
                    })

    return detections


def generate_detection_report(detections: list, output_path: str) -> None:
    """Generate evasion detection report."""
    by_technique = defaultdict(list)
    by_severity = defaultdict(int)
    by_host = defaultdict(int)

    for d in detections:
        by_technique[d["technique_id"]].append(d)
        by_severity[d["severity"]] += 1
        by_host[d["host"]] += 1

    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "total_detections": len(detections),
        "summary": {
            "by_severity": dict(by_severity),
            "by_technique": {k: len(v) for k, v in by_technique.items()},
            "by_host": dict(by_host),
        },
        "detections": detections[:200],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <sysmon_events.csv>")
        print()
        print("Analyzes exported Sysmon/Windows event logs for defense evasion techniques.")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    print("Analyzing endpoint logs for evasion techniques...")
    detections = analyze_sysmon_csv(csv_path)

    base = os.path.splitext(os.path.basename(csv_path))[0]
    out_dir = os.path.dirname(csv_path) or "."

    report_path = os.path.join(out_dir, f"{base}_evasion_report.json")
    generate_detection_report(detections, report_path)
    print(f"Detection report: {report_path}")

    print(f"\n--- Evasion Detection Summary ---")
    print(f"Total detections: {len(detections)}")

    severity_counts = defaultdict(int)
    technique_counts = defaultdict(int)
    for d in detections:
        severity_counts[d["severity"]] += 1
        technique_counts[d["technique_id"]] += 1

    for sev in ["critical", "high", "medium", "low"]:
        if severity_counts[sev]:
            print(f"  {sev.upper()}: {severity_counts[sev]}")

    if technique_counts:
        print(f"\nBy technique:")
        for tid, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
            print(f"  {tid}: {count}")
