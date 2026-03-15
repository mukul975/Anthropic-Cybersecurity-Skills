#!/usr/bin/env python3
"""
T1003 Credential Dumping Detection Script
Analyzes EDR/Sysmon logs for LSASS access, credential tool execution,
and registry hive exports indicating credential theft.
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

LSASS_SUSPICIOUS_ACCESS = {"0x1fffff", "0x1f3fff", "0x143a", "0x1f0fff", "0x0040", "0x1010", "0x1410"}
LSASS_LEGITIMATE_SOURCES = {
    "csrss.exe", "lsass.exe", "svchost.exe", "msmpe ng.exe", "wmiprvse.exe",
    "securityhealthservice.exe", "smartscreen.exe", "taskmgr.exe",
}

CREDENTIAL_TOOL_PATTERNS = [
    (r"(?i)sekurlsa", "Mimikatz_sekurlsa", "T1003.001", "CRITICAL"),
    (r"(?i)lsadump", "Mimikatz_lsadump", "T1003.001", "CRITICAL"),
    (r"(?i)procdump.*lsass", "ProcDump_LSASS", "T1003.001", "CRITICAL"),
    (r"(?i)comsvcs.*MiniDump", "Comsvcs_MiniDump", "T1003.001", "CRITICAL"),
    (r"(?i)ntdsutil.*ifm", "NTDS_IFM_Creation", "T1003.003", "CRITICAL"),
    (r"(?i)vssadmin.*create\s+shadow", "VSS_Shadow_Copy", "T1003.003", "HIGH"),
    (r"(?i)reg\s+(save|export)\s+hklm\\\\sam", "SAM_Hive_Export", "T1003.002", "CRITICAL"),
    (r"(?i)reg\s+(save|export)\s+hklm\\\\security", "SECURITY_Hive_Export", "T1003.004", "CRITICAL"),
    (r"(?i)reg\s+(save|export)\s+hklm\\\\system", "SYSTEM_Hive_Export", "T1003.002", "HIGH"),
    (r"(?i)esentutl.*ntds", "NTDS_Esentutl", "T1003.003", "CRITICAL"),
    (r"(?i)lazagne", "LaZagne", "T1003", "HIGH"),
]


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


def detect_credential_dumping(events: list[dict]) -> list[dict]:
    findings = []
    for event in events:
        event_code = str(event.get("EventCode", event.get("EventID", "")))
        computer = event.get("Computer", event.get("host", ""))
        timestamp = event.get("UtcTime", event.get("_time", ""))
        user = event.get("User", event.get("user", ""))

        if event_code == "10":
            target = event.get("TargetImage", "")
            source = event.get("SourceImage", "")
            access = event.get("GrantedAccess", "").lower()
            if "lsass.exe" not in target.lower():
                continue
            source_name = source.split("\\")[-1].lower()
            if source_name in LSASS_LEGITIMATE_SOURCES:
                continue
            if access not in LSASS_SUSPICIOUS_ACCESS:
                continue
            findings.append({
                "timestamp": timestamp, "computer": computer, "user": user,
                "detection_type": "LSASS_Access",
                "source_process": source, "target": "lsass.exe",
                "access_mask": access,
                "technique": "T1003.001", "severity": "CRITICAL",
                "description": f"{source_name} accessed LSASS with {access}",
            })

        elif event_code == "1":
            cmdline = event.get("CommandLine", "")
            image = event.get("Image", "")
            for pattern, tool_name, technique, severity in CREDENTIAL_TOOL_PATTERNS:
                if re.search(pattern, cmdline):
                    findings.append({
                        "timestamp": timestamp, "computer": computer, "user": user,
                        "detection_type": "Credential_Tool",
                        "tool": tool_name, "image": image,
                        "command_line": cmdline,
                        "technique": technique, "severity": severity,
                        "description": f"Credential dumping tool detected: {tool_name}",
                    })
                    break

    return sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))


def run_hunt(input_path: str, output_dir: str) -> None:
    print(f"[*] T1003 Credential Dumping Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_events(input_path)
    print(f"[*] Loaded {len(events)} events")
    findings = detect_credential_dumping(events)
    print(f"[!] Credential dumping detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "credential_dumping_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-CRED-{datetime.date.today().isoformat()}",
                    "findings_count": len(findings), "findings": findings}, f, indent=2)
    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="T1003 Credential Dumping Detection")
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", default="./cred_dump_hunt_output")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
