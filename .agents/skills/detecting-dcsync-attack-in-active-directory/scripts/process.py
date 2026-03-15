#!/usr/bin/env python3
"""
DCSync Attack Detection Script
Analyzes Windows Security Event 4662 logs to identify non-domain-controller
accounts requesting Active Directory replication rights.
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

GUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def load_dc_list(dc_file: str) -> set:
    """Load known domain controller accounts from file."""
    dcs = set()
    if dc_file:
        path = Path(dc_file)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        dcs.add(line.lower())
    return dcs


def parse_events(input_path: str) -> list[dict]:
    """Parse Windows event log exports (JSON, CSV, EVTX-exported CSV)."""
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


def detect_dcsync(events: list[dict], known_dcs: set) -> list[dict]:
    """Detect DCSync activity from Event 4662 logs."""
    findings = []
    for event in events:
        event_id = str(event.get("EventID", event.get("EventCode", event.get("event_id", ""))))
        if event_id != "4662":
            continue

        properties = event.get("Properties", event.get("properties", ""))
        if not properties:
            continue

        found_guids = GUID_PATTERN.findall(properties.lower())
        replication_guids = [g for g in found_guids if g in REPLICATION_GUIDS]
        if not replication_guids:
            continue

        subject_user = event.get("SubjectUserName", event.get("subject_user_name", ""))
        subject_domain = event.get("SubjectDomainName", event.get("subject_domain_name", ""))
        computer = event.get("Computer", event.get("computer", ""))
        timestamp = event.get("TimeCreated", event.get("_time", event.get("timestamp", "")))

        # Check if this is a legitimate domain controller
        is_dc = False
        subject_lower = subject_user.lower()
        if subject_lower.endswith("$"):
            if subject_lower in known_dcs or subject_lower.rstrip("$") in known_dcs:
                is_dc = True

        if is_dc:
            continue

        replication_rights = [REPLICATION_GUIDS[g] for g in replication_guids]
        has_get_changes_all = "DS-Replication-Get-Changes-All" in replication_rights

        severity = "CRITICAL" if has_get_changes_all else "HIGH"

        findings.append({
            "timestamp": timestamp,
            "subject_user": subject_user,
            "subject_domain": subject_domain,
            "computer": computer,
            "replication_guids": replication_guids,
            "replication_rights": replication_rights,
            "has_get_changes_all": has_get_changes_all,
            "is_machine_account": subject_user.endswith("$"),
            "severity": severity,
            "description": f"Non-DC account '{subject_user}' requested replication rights: {', '.join(replication_rights)}",
        })

    return sorted(findings, key=lambda x: x.get("timestamp", ""), reverse=True)


def run_hunt(input_path: str, dc_file: str, output_dir: str) -> None:
    """Execute DCSync detection hunt."""
    print(f"[*] DCSync Detection Hunt - {datetime.datetime.now().isoformat()}")

    known_dcs = load_dc_list(dc_file)
    print(f"[*] Known domain controllers: {len(known_dcs)}")

    events = parse_events(input_path)
    print(f"[*] Loaded {len(events)} events")

    findings = detect_dcsync(events, known_dcs)
    print(f"[!] DCSync detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "dcsync_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-DCSYNC-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "findings_count": len(findings),
            "findings": findings,
        }, f, indent=2)

    with open(output_path / "dcsync_report.md", "w", encoding="utf-8") as f:
        f.write("# DCSync Attack Detection Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Events Analyzed**: {len(events)}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        for finding in findings:
            f.write(f"## [{finding['severity']}] {finding['subject_user']}\n")
            f.write(f"- **Time**: {finding['timestamp']}\n")
            f.write(f"- **Computer**: {finding['computer']}\n")
            f.write(f"- **Rights**: {', '.join(finding['replication_rights'])}\n")
            f.write(f"- **Description**: {finding['description']}\n\n")

    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="DCSync Attack Detection")
    parser.add_argument("--input", "-i", required=True, help="Path to Windows event logs")
    parser.add_argument("--dc-list", "-d", default="", help="File with known DC accounts")
    parser.add_argument("--output", "-o", default="./dcsync_hunt_output", help="Output directory")
    args = parser.parse_args()
    run_hunt(args.input, args.dc_list, args.output)


if __name__ == "__main__":
    main()
