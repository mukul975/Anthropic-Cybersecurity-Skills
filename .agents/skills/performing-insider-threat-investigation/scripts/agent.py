#!/usr/bin/env python3
"""Agent for performing insider threat investigation.

Analyzes user activity logs, detects behavioral anomalies, builds
activity timelines, and generates investigation reports for insider
threat cases.
"""

import json
import sys
import csv
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


class InsiderThreatAgent:
    """Analyzes user behavior for insider threat investigation."""

    def __init__(self, case_id, output_dir):
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events = []
        self.baseline = {}

    def load_events_csv(self, csv_path, timestamp_col="timestamp",
                        user_col="user", action_col="action"):
        """Load user activity events from a CSV file."""
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.events.append({
                    "timestamp": row.get(timestamp_col, ""),
                    "user": row.get(user_col, ""),
                    "action": row.get(action_col, ""),
                    "source": row.get("source", "unknown"),
                    "details": row.get("details", ""),
                    "destination": row.get("destination", ""),
                    "bytes": int(row.get("bytes", 0) or 0),
                })

    def set_baseline(self, avg_files_per_day=20, avg_emails_per_day=50,
                     avg_data_mb_per_day=50, normal_hours=(8, 18),
                     usb_usage=False):
        """Set behavioral baseline for comparison."""
        self.baseline = {
            "avg_files_per_day": avg_files_per_day,
            "avg_emails_per_day": avg_emails_per_day,
            "avg_data_mb_per_day": avg_data_mb_per_day,
            "normal_hours_start": normal_hours[0],
            "normal_hours_end": normal_hours[1],
            "usb_usage": usb_usage,
        }

    def filter_events_by_user(self, username):
        """Filter events for a specific user."""
        return [e for e in self.events if e["user"] == username]

    def detect_after_hours_activity(self, username):
        """Detect activity outside normal business hours."""
        user_events = self.filter_events_by_user(username)
        after_hours = []
        start = self.baseline.get("normal_hours_start", 8)
        end = self.baseline.get("normal_hours_end", 18)

        for event in user_events:
            try:
                ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                hour = ts.hour
                if hour < start or hour >= end:
                    after_hours.append(event)
            except (ValueError, AttributeError):
                continue
        return {
            "total_events": len(user_events),
            "after_hours_events": len(after_hours),
            "after_hours_pct": round(len(after_hours) / max(len(user_events), 1) * 100, 1),
            "events": after_hours[:50],
        }

    def detect_data_exfiltration_indicators(self, username):
        """Detect potential data exfiltration patterns."""
        user_events = self.filter_events_by_user(username)
        indicators = {
            "usb_connections": [],
            "large_transfers": [],
            "email_forwarding": [],
            "cloud_uploads": [],
            "print_jobs": [],
        }

        exfil_keywords = {
            "usb_connections": ["usb", "removable", "mass_storage"],
            "large_transfers": ["transfer", "copy", "download"],
            "email_forwarding": ["forward", "auto-forward", "gmail", "yahoo", "hotmail"],
            "cloud_uploads": ["dropbox", "gdrive", "onedrive", "mega", "wetransfer"],
            "print_jobs": ["print", "printer"],
        }

        for event in user_events:
            action_lower = event["action"].lower()
            details_lower = event.get("details", "").lower()
            dest_lower = event.get("destination", "").lower()
            combined = f"{action_lower} {details_lower} {dest_lower}"

            for category, keywords in exfil_keywords.items():
                if any(kw in combined for kw in keywords):
                    indicators[category].append(event)

            if event.get("bytes", 0) > 100_000_000:
                indicators["large_transfers"].append(event)

        return indicators

    def build_activity_timeline(self, username):
        """Build a chronological activity timeline for the subject."""
        user_events = self.filter_events_by_user(username)
        sorted_events = sorted(user_events, key=lambda e: e.get("timestamp", ""))

        daily_summary = defaultdict(lambda: {
            "event_count": 0, "total_bytes": 0, "actions": defaultdict(int),
        })

        for event in sorted_events:
            try:
                ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                day = ts.strftime("%Y-%m-%d")
            except (ValueError, AttributeError):
                day = "unknown"
            daily_summary[day]["event_count"] += 1
            daily_summary[day]["total_bytes"] += event.get("bytes", 0)
            daily_summary[day]["actions"][event["action"]] += 1

        return {
            "user": username,
            "total_events": len(sorted_events),
            "date_range": {
                "start": sorted_events[0]["timestamp"] if sorted_events else None,
                "end": sorted_events[-1]["timestamp"] if sorted_events else None,
            },
            "daily_summary": {
                day: {
                    "event_count": s["event_count"],
                    "total_bytes": s["total_bytes"],
                    "total_mb": round(s["total_bytes"] / 1_048_576, 1),
                    "top_actions": dict(sorted(
                        s["actions"].items(), key=lambda x: x[1], reverse=True
                    )[:5]),
                }
                for day, s in sorted(daily_summary.items())
            },
        }

    def calculate_anomaly_score(self, username):
        """Calculate a composite behavioral anomaly score (0-100)."""
        score = 0
        after_hours = self.detect_after_hours_activity(username)
        exfil = self.detect_data_exfiltration_indicators(username)
        timeline = self.build_activity_timeline(username)

        if after_hours["after_hours_pct"] > 30:
            score += 25
        elif after_hours["after_hours_pct"] > 15:
            score += 10

        if len(exfil["usb_connections"]) > 0:
            score += 20
        if len(exfil["cloud_uploads"]) > 0:
            score += 15
        if len(exfil["email_forwarding"]) > 0:
            score += 15
        if len(exfil["large_transfers"]) > 3:
            score += 15

        daily_data = timeline.get("daily_summary", {})
        for day, summary in daily_data.items():
            if summary["total_mb"] > self.baseline.get("avg_data_mb_per_day", 50) * 5:
                score += 10
                break

        return min(score, 100)

    def generate_investigation_report(self, username):
        """Generate a comprehensive insider threat investigation report."""
        report = {
            "case_id": self.case_id,
            "subject": username,
            "report_date": datetime.utcnow().isoformat(),
            "anomaly_score": self.calculate_anomaly_score(username),
            "after_hours_analysis": self.detect_after_hours_activity(username),
            "exfiltration_indicators": {
                k: len(v) for k, v in
                self.detect_data_exfiltration_indicators(username).items()
            },
            "activity_timeline": self.build_activity_timeline(username),
        }

        score = report["anomaly_score"]
        if score >= 70:
            report["risk_level"] = "CRITICAL"
        elif score >= 40:
            report["risk_level"] = "HIGH"
        elif score >= 20:
            report["risk_level"] = "MEDIUM"
        else:
            report["risk_level"] = "LOW"

        report_path = self.output_dir / f"{self.case_id}_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    if len(sys.argv) < 4:
        print("Usage: agent.py <case_id> <events_csv> <username> [output_dir]")
        sys.exit(1)

    case_id = sys.argv[1]
    events_csv = sys.argv[2]
    username = sys.argv[3]
    output_dir = sys.argv[4] if len(sys.argv) > 4 else "./investigation_output"

    agent = InsiderThreatAgent(case_id, output_dir)
    agent.load_events_csv(events_csv)
    agent.set_baseline()
    agent.generate_investigation_report(username)


if __name__ == "__main__":
    main()
