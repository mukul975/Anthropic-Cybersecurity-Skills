#!/usr/bin/env python3
"""
HIDS Alert Analyzer

Parses Wazuh/OSSEC alerts JSON and generates summary reports for
file integrity monitoring and intrusion detection events.
"""

import json
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime


def parse_wazuh_alerts(json_path: str) -> list:
    """Parse Wazuh alerts JSON file (one JSON object per line)."""
    alerts = []

    with open(json_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append({
                    "timestamp": alert.get("timestamp", ""),
                    "rule_id": alert.get("rule", {}).get("id", ""),
                    "rule_description": alert.get("rule", {}).get("description", ""),
                    "rule_level": alert.get("rule", {}).get("level", 0),
                    "rule_groups": alert.get("rule", {}).get("groups", []),
                    "agent_name": alert.get("agent", {}).get("name", ""),
                    "agent_ip": alert.get("agent", {}).get("ip", ""),
                    "syscheck_path": alert.get("syscheck", {}).get("path", ""),
                    "syscheck_event": alert.get("syscheck", {}).get("event", ""),
                    "syscheck_md5_after": alert.get("syscheck", {}).get("md5_after", ""),
                    "src_ip": alert.get("data", {}).get("srcip", ""),
                    "full_log": alert.get("full_log", "")[:300],
                })
            except json.JSONDecodeError:
                continue

    return alerts


def analyze_alerts(alerts: list) -> dict:
    """Analyze parsed alerts for patterns and summary statistics."""
    analysis = {
        "total_alerts": len(alerts),
        "by_level": Counter(),
        "by_rule": Counter(),
        "by_agent": Counter(),
        "by_group": Counter(),
        "fim_events": {
            "modified": 0,
            "added": 0,
            "deleted": 0,
            "top_modified_files": Counter(),
        },
        "high_severity": [],
        "attack_sources": Counter(),
    }

    for alert in alerts:
        level = alert["rule_level"]
        analysis["by_level"][level] += 1
        analysis["by_rule"][f"{alert['rule_id']}: {alert['rule_description']}"] += 1
        analysis["by_agent"][alert["agent_name"]] += 1

        for group in alert["rule_groups"]:
            analysis["by_group"][group] += 1

        if "syscheck" in alert["rule_groups"] or alert["syscheck_path"]:
            event = alert["syscheck_event"]
            if event == "modified":
                analysis["fim_events"]["modified"] += 1
                analysis["fim_events"]["top_modified_files"][alert["syscheck_path"]] += 1
            elif event == "added":
                analysis["fim_events"]["added"] += 1
            elif event == "deleted":
                analysis["fim_events"]["deleted"] += 1

        if level >= 10:
            analysis["high_severity"].append({
                "timestamp": alert["timestamp"],
                "agent": alert["agent_name"],
                "rule": alert["rule_description"],
                "level": level,
                "detail": alert["full_log"],
            })

        if alert["src_ip"]:
            analysis["attack_sources"][alert["src_ip"]] += 1

    return analysis


def generate_report(analysis: dict, output_path: str) -> None:
    """Generate HIDS alert analysis report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "total_alerts": analysis["total_alerts"],
        "severity_distribution": dict(analysis["by_level"]),
        "top_rules": dict(analysis["by_rule"].most_common(20)),
        "top_agents": dict(analysis["by_agent"].most_common(20)),
        "alert_groups": dict(analysis["by_group"].most_common(15)),
        "file_integrity": {
            "files_modified": analysis["fim_events"]["modified"],
            "files_added": analysis["fim_events"]["added"],
            "files_deleted": analysis["fim_events"]["deleted"],
            "top_modified": dict(analysis["fim_events"]["top_modified_files"].most_common(20)),
        },
        "high_severity_alerts": analysis["high_severity"][:50],
        "top_attack_sources": dict(analysis["attack_sources"].most_common(20)),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <wazuh_alerts.json>")
        print()
        print("Analyzes Wazuh/OSSEC alerts JSON for HIDS event patterns.")
        sys.exit(1)

    json_path = sys.argv[1]
    if not os.path.exists(json_path):
        print(f"Error: File not found: {json_path}")
        sys.exit(1)

    print("Parsing Wazuh alerts...")
    alerts = parse_wazuh_alerts(json_path)
    print(f"Parsed {len(alerts)} alerts")

    print("Analyzing alert patterns...")
    analysis = analyze_alerts(alerts)

    base = os.path.splitext(os.path.basename(json_path))[0]
    out_dir = os.path.dirname(json_path) or "."
    report_path = os.path.join(out_dir, f"{base}_analysis.json")
    generate_report(analysis, report_path)
    print(f"Analysis report: {report_path}")

    print(f"\n--- HIDS Alert Summary ---")
    print(f"Total alerts: {analysis['total_alerts']}")
    print(f"High severity (level >= 10): {len(analysis['high_severity'])}")
    print(f"FIM: {analysis['fim_events']['modified']} modified, "
          f"{analysis['fim_events']['added']} added, "
          f"{analysis['fim_events']['deleted']} deleted")
