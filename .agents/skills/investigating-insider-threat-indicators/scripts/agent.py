#!/usr/bin/env python3
"""
Insider Threat Investigation Agent
Automates insider threat indicator collection by correlating SIEM data,
DLP alerts, access logs, and HR events to build investigation timelines.
"""

import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone, timedelta


def load_dlp_alerts(filepath: str) -> list[dict]:
    """Load DLP alert data from exported CSV."""
    alerts = []
    if not os.path.exists(filepath):
        print(f"[!] DLP alerts file not found: {filepath}")
        return alerts
    with open(filepath, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alerts.append({
                "timestamp": row.get("timestamp", ""),
                "user": row.get("user", ""),
                "policy": row.get("policy_name", ""),
                "action": row.get("action", ""),
                "destination": row.get("destination", ""),
                "file_count": int(row.get("file_count", 0)),
                "bytes_transferred": int(row.get("bytes_transferred", 0)),
                "severity": row.get("severity", "medium"),
            })
    return alerts


def load_access_logs(filepath: str) -> list[dict]:
    """Load authentication and access logs from exported JSON."""
    if not os.path.exists(filepath):
        print(f"[!] Access logs file not found: {filepath}")
        return []
    with open(filepath, "r") as f:
        return json.load(f)


def analyze_data_movement(dlp_alerts: list[dict], subject_user: str) -> dict:
    """Analyze data exfiltration indicators for the subject."""
    user_alerts = [a for a in dlp_alerts if a["user"].lower() == subject_user.lower()]

    total_bytes = sum(a["bytes_transferred"] for a in user_alerts)
    total_files = sum(a["file_count"] for a in user_alerts)
    destinations = {}
    for alert in user_alerts:
        dest = alert["destination"]
        destinations[dest] = destinations.get(dest, 0) + alert["file_count"]

    high_severity = [a for a in user_alerts if a["severity"] == "high"]

    return {
        "total_alerts": len(user_alerts),
        "total_bytes_transferred": total_bytes,
        "total_bytes_gb": round(total_bytes / (1024**3), 2),
        "total_files": total_files,
        "destinations": destinations,
        "high_severity_alerts": len(high_severity),
        "alert_details": user_alerts,
    }


def analyze_access_patterns(access_logs: list[dict], subject_user: str) -> dict:
    """Detect anomalous access patterns for the subject."""
    user_logs = [l for l in access_logs if l.get("user", "").lower() == subject_user.lower()]

    off_hours_events = []
    weekend_events = []
    unique_apps = set()
    unique_ips = set()

    for log in user_logs:
        ts = log.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
            weekday = dt.weekday()
            if hour < 7 or hour > 19:
                off_hours_events.append(log)
            if weekday >= 5:
                weekend_events.append(log)
        except (ValueError, AttributeError):
            pass

        unique_apps.add(log.get("application", "unknown"))
        unique_ips.add(log.get("source_ip", "unknown"))

    return {
        "total_events": len(user_logs),
        "off_hours_events": len(off_hours_events),
        "off_hours_pct": round(len(off_hours_events) / max(len(user_logs), 1) * 100, 1),
        "weekend_events": len(weekend_events),
        "weekend_pct": round(len(weekend_events) / max(len(user_logs), 1) * 100, 1),
        "unique_applications": sorted(unique_apps),
        "unique_source_ips": sorted(unique_ips),
    }


def detect_pre_departure_indicators(
    data_movement: dict, access_patterns: dict, notice_date: str
) -> list[dict]:
    """Identify pre-departure behavioral indicators."""
    indicators = []

    if data_movement["total_bytes_gb"] > 1.0:
        indicators.append({
            "severity": "HIGH",
            "indicator": "Bulk data transfer",
            "detail": f"{data_movement['total_bytes_gb']} GB transferred across {data_movement['total_files']} files",
        })

    if data_movement["high_severity_alerts"] > 0:
        indicators.append({
            "severity": "HIGH",
            "indicator": "High-severity DLP violations",
            "detail": f"{data_movement['high_severity_alerts']} high-severity DLP alerts triggered",
        })

    personal_storage = ["dropbox", "drive.google", "onedrive.live", "mega.nz", "wetransfer"]
    for dest, count in data_movement["destinations"].items():
        if any(ps in dest.lower() for ps in personal_storage):
            indicators.append({
                "severity": "HIGH",
                "indicator": "Transfer to personal cloud storage",
                "detail": f"{count} files sent to {dest}",
            })

    if access_patterns["off_hours_pct"] > 30:
        indicators.append({
            "severity": "MEDIUM",
            "indicator": "Elevated off-hours activity",
            "detail": f"{access_patterns['off_hours_pct']}% of activity outside business hours",
        })

    if access_patterns["weekend_pct"] > 15:
        indicators.append({
            "severity": "MEDIUM",
            "indicator": "Elevated weekend activity",
            "detail": f"{access_patterns['weekend_pct']}% of activity on weekends",
        })

    if len(access_patterns["unique_applications"]) > 15:
        indicators.append({
            "severity": "MEDIUM",
            "indicator": "Broad application access",
            "detail": f"Accessed {len(access_patterns['unique_applications'])} unique applications",
        })

    return indicators


def create_evidence_log(case_id: str, evidence_files: list[str]) -> dict:
    """Create chain-of-custody evidence log with file hashes."""
    items = []
    for filepath in evidence_files:
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                content = f.read()
            items.append({
                "item_id": f"EV-{len(items)+1:03d}",
                "file": filepath,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })

    return {
        "case_id": case_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "investigator": os.getenv("USER", "soc_analyst"),
        "evidence_items": items,
    }


def generate_report(case_id: str, subject: str, data_mv: dict, access: dict, indicators: list) -> str:
    """Generate insider threat investigation report."""
    lines = [
        f"INSIDER THREAT INVESTIGATION REPORT - {case_id}",
        "=" * 55,
        f"Subject: {subject}",
        f"Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "DATA MOVEMENT ANALYSIS:",
        f"  DLP Alerts: {data_mv['total_alerts']}",
        f"  Data Transferred: {data_mv['total_bytes_gb']} GB ({data_mv['total_files']} files)",
        f"  High-Severity Alerts: {data_mv['high_severity_alerts']}",
        f"  Destinations: {json.dumps(data_mv['destinations'], indent=4)}",
        "",
        "ACCESS PATTERN ANALYSIS:",
        f"  Total Events: {access['total_events']}",
        f"  Off-Hours Activity: {access['off_hours_pct']}%",
        f"  Weekend Activity: {access['weekend_pct']}%",
        f"  Applications Accessed: {len(access['unique_applications'])}",
        "",
        f"INDICATORS IDENTIFIED: {len(indicators)}",
        "-" * 40,
    ]
    for ind in indicators:
        lines.append(f"  [{ind['severity']}] {ind['indicator']}: {ind['detail']}")

    return "\n".join(lines)


if __name__ == "__main__":
    case_id = sys.argv[1] if len(sys.argv) > 1 else "IT-2024-0001"
    subject_user = sys.argv[2] if len(sys.argv) > 2 else "jsmith"
    dlp_file = sys.argv[3] if len(sys.argv) > 3 else "dlp_alerts.csv"
    access_file = sys.argv[4] if len(sys.argv) > 4 else "access_logs.json"

    print(f"[*] Starting insider threat investigation: {case_id}")
    print(f"[*] Subject: {subject_user}")

    dlp_alerts = load_dlp_alerts(dlp_file)
    access_logs = load_access_logs(access_file)

    data_movement = analyze_data_movement(dlp_alerts, subject_user)
    access_patterns = analyze_access_patterns(access_logs, subject_user)
    indicators = detect_pre_departure_indicators(data_movement, access_patterns, "2024-03-15")

    report = generate_report(case_id, subject_user, data_movement, access_patterns, indicators)
    print(report)

    output = f"insider_threat_{case_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"data_movement": data_movement, "access_patterns": access_patterns, "indicators": indicators}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
