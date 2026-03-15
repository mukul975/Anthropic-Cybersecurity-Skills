#!/usr/bin/env python3
"""
WMI Lateral Movement Tracker and Report Generator

Tracks WMI-based lateral movement activities during red team
engagements and generates movement reports.
For authorized red team engagements only.
"""

import json
import sys
import os
from datetime import datetime


def load_movement_log(filepath: str) -> list:
    """Load lateral movement log entries."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading log: {e}")
        return []


def generate_movement_report(entries: list) -> str:
    """Generate lateral movement tracking report."""
    report = [
        "=" * 60,
        "WMI Lateral Movement Report",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 60,
        "",
        f"Total Movements: {len(entries)}",
        ""
    ]

    hosts_accessed = set()
    credentials_used = set()

    for i, entry in enumerate(entries, 1):
        source = entry.get("source", "N/A")
        target = entry.get("target", "N/A")
        method = entry.get("method", "wmiexec")
        credential = entry.get("credential", "N/A")
        timestamp = entry.get("timestamp", "N/A")
        result = entry.get("result", "N/A")

        hosts_accessed.add(target)
        credentials_used.add(credential)

        report.append(f"  [{i}] {source} → {target}")
        report.append(f"      Method: {method}")
        report.append(f"      Credential: {credential}")
        report.append(f"      Time: {timestamp}")
        report.append(f"      Result: {result}")
        report.append("")

    report.extend([
        f"Unique Hosts Accessed: {len(hosts_accessed)}",
        f"Unique Credentials Used: {len(credentials_used)}",
        "",
        "Hosts:",
    ])
    for host in sorted(hosts_accessed):
        report.append(f"  - {host}")

    report.append("")
    report.append("=" * 60)
    return "\n".join(report)


def create_example_log():
    """Create an example movement log template."""
    example = [
        {
            "source": "10.10.10.100",
            "target": "10.10.10.50",
            "method": "wmiexec.py",
            "credential": "domain\\admin (PtH)",
            "timestamp": "2024-01-15T10:30:00",
            "result": "Shell obtained, credentials harvested"
        }
    ]
    with open("movement_log.json", "w") as f:
        json.dump(example, f, indent=2)
    print("Example log created: movement_log.json")


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <movement_log.json>")
        print("       python process.py --create-template")
        return

    if sys.argv[1] == "--create-template":
        create_example_log()
        return

    entries = load_movement_log(sys.argv[1])
    if entries:
        report = generate_movement_report(entries)
        print(report)


if __name__ == "__main__":
    main()
