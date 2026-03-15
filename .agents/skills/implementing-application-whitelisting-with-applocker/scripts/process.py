#!/usr/bin/env python3
"""
AppLocker Audit Log Analyzer

Parses Windows AppLocker audit event logs to identify blocked applications,
generate rule recommendations, and track policy effectiveness.
"""

import json
import csv
import sys
import os
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from datetime import datetime


def parse_applocker_evtx_export(csv_path: str) -> list:
    """
    Parse AppLocker events exported from Event Viewer as CSV.
    Export: Event Viewer → AppLocker/EXE and DLL → Save All Events As → CSV
    """
    events = []

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event = {
                "timestamp": row.get("Date and Time", ""),
                "event_id": row.get("Event ID", ""),
                "level": row.get("Level", ""),
                "source": row.get("Source", ""),
                "message": row.get("Message", ""),
                "user": "",
                "file_path": "",
                "file_hash": "",
                "publisher": "",
                "rule_name": "",
            }

            msg = event["message"]
            if msg:
                if "was allowed to run" in msg:
                    event["action"] = "allowed"
                elif "was prevented from running" in msg:
                    event["action"] = "blocked"
                elif "would have been prevented" in msg:
                    event["action"] = "audit_block"
                else:
                    event["action"] = "unknown"

                lines = msg.split("\n")
                for line in lines:
                    line = line.strip()
                    if line.startswith("File path:") or line.startswith("Filer path:"):
                        event["file_path"] = line.split(":", 1)[1].strip()
                    elif line.startswith("User:"):
                        event["user"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Publisher name:"):
                        event["publisher"] = line.split(":", 1)[1].strip()
                    elif line.startswith("File hash:"):
                        event["file_hash"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Rule name:"):
                        event["rule_name"] = line.split(":", 1)[1].strip()

            events.append(event)

    return events


def analyze_blocked_applications(events: list) -> dict:
    """Analyze which applications are being blocked and why."""
    analysis = {
        "total_events": len(events),
        "blocked_events": 0,
        "allowed_events": 0,
        "audit_block_events": 0,
        "unique_blocked_files": set(),
        "blocked_by_path": defaultdict(int),
        "blocked_by_user": defaultdict(int),
        "blocked_by_publisher": defaultdict(int),
        "top_blocked_files": Counter(),
        "user_writable_blocks": [],
        "potential_legitimate": [],
    }

    user_writable_indicators = [
        "\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\",
        "\\desktop\\", "\\documents\\", "%temp%", "%appdata%",
    ]

    signed_publishers = set()

    for event in events:
        action = event.get("action", "")
        if action in ("blocked", "audit_block"):
            analysis["blocked_events"] += 1
            file_path = event.get("file_path", "").lower()
            user = event.get("user", "Unknown")
            publisher = event.get("publisher", "Unknown")

            analysis["unique_blocked_files"].add(file_path)
            analysis["blocked_by_path"][file_path] += 1
            analysis["blocked_by_user"][user] += 1
            analysis["top_blocked_files"][file_path] += 1

            if publisher and publisher != "Unknown":
                analysis["blocked_by_publisher"][publisher] += 1
                signed_publishers.add(publisher)

            is_user_writable = any(ind in file_path for ind in user_writable_indicators)
            if is_user_writable:
                analysis["user_writable_blocks"].append({
                    "file": file_path,
                    "user": user,
                    "timestamp": event.get("timestamp", ""),
                })

            if publisher and publisher != "Unknown" and not is_user_writable:
                analysis["potential_legitimate"].append({
                    "file": file_path,
                    "publisher": publisher,
                    "user": user,
                    "recommendation": "Consider creating publisher rule",
                })

        elif action == "allowed":
            analysis["allowed_events"] += 1

        if action == "audit_block":
            analysis["audit_block_events"] += 1

    analysis["unique_blocked_files"] = len(analysis["unique_blocked_files"])
    analysis["signed_publishers_blocked"] = list(signed_publishers)

    return analysis


def generate_rule_recommendations(analysis: dict) -> list:
    """Generate AppLocker rule recommendations based on audit analysis."""
    recommendations = []

    for item in analysis.get("potential_legitimate", []):
        recommendations.append({
            "type": "publisher_rule",
            "action": "allow",
            "publisher": item["publisher"],
            "file": item["file"],
            "reason": f"Signed application blocked for user {item['user']}",
            "priority": "high",
        })

    top_blocked = analysis.get("top_blocked_files", Counter())
    for file_path, count in top_blocked.most_common(20):
        if count >= 10:
            is_in_recommendations = any(
                r["file"] == file_path for r in recommendations
            )
            if not is_in_recommendations:
                recommendations.append({
                    "type": "investigate",
                    "action": "review",
                    "file": file_path,
                    "count": count,
                    "reason": f"Blocked {count} times - determine if legitimate",
                    "priority": "medium",
                })

    return recommendations


def export_analysis_report(analysis: dict, recommendations: list, output_path: str) -> None:
    """Export analysis and recommendations to JSON report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_events": analysis["total_events"],
            "blocked": analysis["blocked_events"],
            "audit_blocked": analysis["audit_block_events"],
            "allowed": analysis["allowed_events"],
            "unique_blocked_files": analysis["unique_blocked_files"],
        },
        "top_blocked_files": dict(analysis["top_blocked_files"].most_common(30)),
        "blocked_by_user": dict(analysis["blocked_by_user"]),
        "signed_publishers_blocked": analysis.get("signed_publishers_blocked", []),
        "user_writable_path_blocks": len(analysis.get("user_writable_blocks", [])),
        "rule_recommendations": recommendations,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def export_blocked_apps_csv(analysis: dict, output_path: str) -> None:
    """Export blocked applications to CSV for review."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File Path", "Block Count", "Action Needed", "Rule Type"])
        for file_path, count in analysis["top_blocked_files"].most_common(100):
            writer.writerow([file_path, count, "Review", "TBD"])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <applocker_events.csv>")
        print()
        print("Analyzes AppLocker audit events exported from Windows Event Viewer.")
        print("Export events from: Event Viewer → AppLocker/EXE and DLL → Save All Events As CSV")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    print("Parsing AppLocker audit events...")
    events = parse_applocker_evtx_export(csv_path)
    print(f"Parsed {len(events)} events")

    print("Analyzing blocked applications...")
    analysis = analyze_blocked_applications(events)

    print("Generating rule recommendations...")
    recommendations = generate_rule_recommendations(analysis)

    base_name = os.path.splitext(os.path.basename(csv_path))[0]
    output_dir = os.path.dirname(csv_path) or "."

    report_path = os.path.join(output_dir, f"{base_name}_analysis.json")
    export_analysis_report(analysis, recommendations, report_path)
    print(f"Analysis report: {report_path}")

    blocked_csv = os.path.join(output_dir, f"{base_name}_blocked_apps.csv")
    export_blocked_apps_csv(analysis, blocked_csv)
    print(f"Blocked apps CSV: {blocked_csv}")

    print(f"\n--- AppLocker Audit Summary ---")
    print(f"Total events: {analysis['total_events']}")
    print(f"Blocked: {analysis['blocked_events']}")
    print(f"Audit-blocked: {analysis['audit_block_events']}")
    print(f"Unique blocked files: {analysis['unique_blocked_files']}")
    print(f"Rule recommendations: {len(recommendations)}")
