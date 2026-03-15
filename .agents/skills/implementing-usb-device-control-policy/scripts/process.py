#!/usr/bin/env python3
"""USB Device Control Audit - Analyzes USB device activity from endpoint logs."""

import json
import csv
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime


def parse_usb_events(csv_path: str) -> list:
    """Parse USB device events from exported Windows event logs or EDR data."""
    events = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append({
                "timestamp": row.get("Timestamp", row.get("Date and Time", "")),
                "host": row.get("Computer", row.get("DeviceName", "")),
                "user": row.get("User", row.get("AccountName", "")),
                "action": row.get("Action", row.get("ActionType", "")),
                "device_name": row.get("DeviceName", row.get("FriendlyName", "")),
                "device_id": row.get("DeviceId", row.get("HardwareId", "")),
                "vid_pid": row.get("VID_PID", ""),
                "serial": row.get("SerialNumber", ""),
                "blocked": row.get("Blocked", row.get("ActionType", "")).lower() in ("blocked", "deny", "prevented"),
            })
    return events


def analyze_usb_activity(events: list) -> dict:
    """Analyze USB events for policy violations and usage patterns."""
    analysis = {
        "total_events": len(events),
        "blocked_events": sum(1 for e in events if e["blocked"]),
        "unique_devices": len({e["device_id"] for e in events if e["device_id"]}),
        "devices_by_host": defaultdict(set),
        "top_users": Counter(),
        "blocked_devices": Counter(),
        "allowed_devices": Counter(),
    }

    for event in events:
        if event["host"] and event["device_id"]:
            analysis["devices_by_host"][event["host"]].add(event["device_id"])
        if event["user"]:
            analysis["top_users"][event["user"]] += 1
        if event["blocked"]:
            analysis["blocked_devices"][event.get("device_name", event["device_id"])] += 1
        else:
            analysis["allowed_devices"][event.get("device_name", event["device_id"])] += 1

    analysis["devices_by_host"] = {k: len(v) for k, v in analysis["devices_by_host"].items()}
    return analysis


def generate_report(analysis: dict, output_path: str) -> None:
    """Generate USB activity report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_events": analysis["total_events"],
            "blocked": analysis["blocked_events"],
            "unique_devices": analysis["unique_devices"],
        },
        "top_users": dict(analysis["top_users"].most_common(20)),
        "top_blocked_devices": dict(analysis["blocked_devices"].most_common(20)),
        "hosts_with_most_devices": dict(sorted(
            analysis["devices_by_host"].items(), key=lambda x: -x[1])[:20]),
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <usb_events.csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    events = parse_usb_events(csv_path)
    analysis = analyze_usb_activity(events)

    out = os.path.join(os.path.dirname(csv_path) or ".", "usb_audit_report.json")
    generate_report(analysis, out)
    print(f"Report: {out}")
    print(f"Total events: {analysis['total_events']}, Blocked: {analysis['blocked_events']}")
