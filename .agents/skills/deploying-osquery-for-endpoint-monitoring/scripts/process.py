#!/usr/bin/env python3
"""Osquery Results Analyzer - Parses osquery JSON results for anomaly detection."""

import json
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime


def parse_osquery_results(json_path: str) -> list:
    """Parse osquery result log (JSON lines format)."""
    results = []
    with open(json_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                results.append(entry)
            except json.JSONDecodeError:
                continue
    return results


def analyze_results(results: list) -> dict:
    """Analyze osquery results for security anomalies."""
    analysis = {
        "total_entries": len(results),
        "queries": Counter(),
        "hosts": Counter(),
        "added_items": [],
        "removed_items": [],
    }

    for entry in results:
        name = entry.get("name", "unknown")
        analysis["queries"][name] += 1
        analysis["hosts"][entry.get("hostIdentifier", "unknown")] += 1

        action = entry.get("action", "")
        columns = entry.get("columns", {})

        if action == "added":
            analysis["added_items"].append({
                "query": name,
                "host": entry.get("hostIdentifier", ""),
                "timestamp": entry.get("unixTime", ""),
                "data": columns,
            })
        elif action == "removed":
            analysis["removed_items"].append({
                "query": name,
                "host": entry.get("hostIdentifier", ""),
                "data": columns,
            })

    return analysis


def generate_report(analysis: dict, output_path: str) -> None:
    """Generate osquery analysis report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "total_entries": analysis["total_entries"],
        "queries_executed": dict(analysis["queries"]),
        "hosts_reporting": dict(analysis["hosts"].most_common(50)),
        "new_items_detected": len(analysis["added_items"]),
        "items_removed": len(analysis["removed_items"]),
        "recent_additions": analysis["added_items"][:50],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <osqueryd.results.log>")
        sys.exit(1)
    results = parse_osquery_results(sys.argv[1])
    analysis = analyze_results(results)
    out = os.path.join(os.path.dirname(sys.argv[1]) or ".", "osquery_analysis.json")
    generate_report(analysis, out)
    print(f"Entries: {analysis['total_entries']} | New items: {len(analysis['added_items'])}")
