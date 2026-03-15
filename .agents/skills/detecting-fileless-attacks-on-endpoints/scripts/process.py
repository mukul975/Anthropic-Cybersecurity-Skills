#!/usr/bin/env python3
"""Fileless Attack Detector - Scans PowerShell logs for fileless attack indicators."""

import json, csv, re, sys, os
from collections import Counter
from datetime import datetime

FILELESS_PATTERNS = {
    "encoded_command": r"(?i)(-enc\s|-e\s|-encodedcommand|frombase64string)",
    "download_cradle": r"(?i)(downloadstring|invoke-webrequest|net\.webclient|wget\s|curl\s)",
    "amsi_bypass": r"(?i)(amsiutils|amsiinitfailed|amsi\.dll)",
    "reflection": r"(?i)(system\.reflection|loadassembly|gettype.*invoke)",
    "wmi_abuse": r"(?i)(win32_process.*create|wmiclass|managementclass)",
    "credential_access": r"(?i)(mimikatz|invoke-mimikatz|sekurlsa|logonpasswords)",
    "invoke_expression": r"(?i)(iex\s|invoke-expression)",
}


def scan_powershell_logs(csv_path: str) -> list:
    detections = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            script = row.get("ScriptBlockText", row.get("Message", ""))
            for pattern_name, pattern in FILELESS_PATTERNS.items():
                if re.search(pattern, script):
                    detections.append({
                        "timestamp": row.get("TimeCreated", row.get("Date and Time", "")),
                        "host": row.get("Computer", row.get("MachineName", "")),
                        "technique": pattern_name,
                        "script_excerpt": script[:300],
                    })
                    break
    return detections


def generate_report(detections: list, output_path: str) -> None:
    by_technique = Counter(d["technique"] for d in detections)
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "total_detections": len(detections),
        "by_technique": dict(by_technique),
        "detections": detections[:100],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <powershell_logs.csv>")
        sys.exit(1)
    detections = scan_powershell_logs(sys.argv[1])
    out = os.path.join(os.path.dirname(sys.argv[1]) or ".", "fileless_detection_report.json")
    generate_report(detections, out)
    print(f"Detections: {len(detections)}")
