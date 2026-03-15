#!/usr/bin/env python3
"""DLP Policy Analyzer - Analyzes DLP alert exports for policy tuning."""

import json, csv, sys, os
from collections import Counter
from datetime import datetime


def parse_dlp_alerts(csv_path: str) -> list:
    alerts = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            alerts.append({
                "timestamp": row.get("Date", ""),
                "user": row.get("User", ""),
                "activity": row.get("Activity", ""),
                "policy": row.get("Policy", ""),
                "sit": row.get("Sensitive Info Type", ""),
                "action": row.get("Action", ""),
                "location": row.get("Location", ""),
                "overridden": row.get("Override", "").lower() == "true",
            })
    return alerts


def analyze(alerts: list) -> dict:
    return {
        "total": len(alerts),
        "by_policy": dict(Counter(a["policy"] for a in alerts).most_common(20)),
        "by_user": dict(Counter(a["user"] for a in alerts).most_common(20)),
        "by_activity": dict(Counter(a["activity"] for a in alerts).most_common(10)),
        "by_sit": dict(Counter(a["sit"] for a in alerts).most_common(10)),
        "override_rate": round(sum(1 for a in alerts if a["overridden"]) / max(len(alerts), 1) * 100, 2),
        "blocked": sum(1 for a in alerts if "block" in a["action"].lower()),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <dlp_alerts.csv>")
        sys.exit(1)
    alerts = parse_dlp_alerts(sys.argv[1])
    result = analyze(alerts)
    out = os.path.join(os.path.dirname(sys.argv[1]) or ".", "dlp_analysis.json")
    with open(out, "w") as f:
        json.dump({"report_generated": datetime.utcnow().isoformat() + "Z", **result}, f, indent=2)
    print(f"Total: {result['total']} | Blocked: {result['blocked']} | Override rate: {result['override_rate']}%")
