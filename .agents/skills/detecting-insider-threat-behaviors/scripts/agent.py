#!/usr/bin/env python3
"""Insider threat behavior detection agent using UEBA indicators.

Analyzes user activity logs to detect anomalous behaviors: off-hours access,
mass file downloads, unusual data access patterns, and privilege abuse.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

RISK_INDICATORS = {
    "off_hours_access": {"weight": 15, "desc": "Activity outside business hours"},
    "mass_download": {"weight": 25, "desc": "Bulk file download/copy"},
    "privilege_escalation": {"weight": 30, "desc": "Unauthorized privilege use"},
    "unusual_destination": {"weight": 20, "desc": "Data sent to unusual destination"},
    "resignation_correlated": {"weight": 35, "desc": "Activity correlated with resignation"},
    "usb_mass_copy": {"weight": 30, "desc": "Mass copy to removable media"},
    "cloud_upload": {"weight": 20, "desc": "Large upload to personal cloud"},
    "email_to_personal": {"weight": 15, "desc": "Forwarding to personal email"},
}

BUSINESS_HOURS = (8, 18)
PERSONAL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                    "protonmail.com", "icloud.com", "aol.com"}
CLOUD_STORAGE = {"dropbox.com", "drive.google.com", "onedrive.live.com",
                 "box.com", "mega.nz", "wetransfer.com"}


def parse_activity_log(filepath):
    events = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                events.append(evt)
            except json.JSONDecodeError:
                parts = line.split(",")
                if len(parts) >= 4:
                    events.append({
                        "timestamp": parts[0], "user": parts[1],
                        "action": parts[2], "detail": ",".join(parts[3:]),
                    })
    return events


def detect_off_hours(events):
    findings = []
    for evt in events:
        ts = evt.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
            if hour < BUSINESS_HOURS[0] or hour >= BUSINESS_HOURS[1]:
                findings.append({
                    "indicator": "off_hours_access",
                    "user": evt.get("user", ""),
                    "timestamp": ts,
                    "hour": hour,
                    "action": evt.get("action", ""),
                })
        except (ValueError, TypeError):
            continue
    return findings


def detect_mass_download(events, threshold=50):
    user_downloads = defaultdict(list)
    for evt in events:
        action = evt.get("action", "").lower()
        if any(kw in action for kw in ("download", "copy", "export", "fileaccessed")):
            user_downloads[evt.get("user", "")].append(evt)

    findings = []
    for user, downloads in user_downloads.items():
        if len(downloads) >= threshold:
            findings.append({
                "indicator": "mass_download",
                "user": user,
                "file_count": len(downloads),
                "time_range": f"{downloads[0].get('timestamp', '')} - {downloads[-1].get('timestamp', '')}",
                "severity": "HIGH" if len(downloads) > 100 else "MEDIUM",
            })
    return findings


def detect_data_exfil_destinations(events):
    findings = []
    for evt in events:
        detail = evt.get("detail", "").lower()
        dest = evt.get("destination", "").lower()
        target = detail + " " + dest

        for domain in PERSONAL_DOMAINS:
            if domain in target:
                findings.append({
                    "indicator": "email_to_personal",
                    "user": evt.get("user", ""),
                    "destination": domain,
                    "timestamp": evt.get("timestamp", ""),
                })
        for cloud in CLOUD_STORAGE:
            if cloud in target:
                findings.append({
                    "indicator": "cloud_upload",
                    "user": evt.get("user", ""),
                    "destination": cloud,
                    "timestamp": evt.get("timestamp", ""),
                })
        if any(kw in target for kw in ("usb", "removable", "external drive", "e:")):
            findings.append({
                "indicator": "usb_mass_copy",
                "user": evt.get("user", ""),
                "timestamp": evt.get("timestamp", ""),
            })
    return findings


def calculate_risk_score(user_findings):
    score = 0
    indicators = set()
    for f in user_findings:
        ind = f.get("indicator", "")
        if ind in RISK_INDICATORS:
            score += RISK_INDICATORS[ind]["weight"]
            indicators.add(ind)
    risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else \
           "MEDIUM" if score >= 25 else "LOW"
    return {"score": min(score, 100), "risk_level": risk, "indicators": list(indicators)}


def main():
    parser = argparse.ArgumentParser(description="Insider Threat Behavior Detector")
    parser.add_argument("--activity-log", required=True, help="User activity log (JSON lines or CSV)")
    parser.add_argument("--download-threshold", type=int, default=50)
    args = parser.parse_args()

    events = parse_activity_log(args.activity_log)
    all_findings = []
    all_findings.extend(detect_off_hours(events))
    all_findings.extend(detect_mass_download(events, args.download_threshold))
    all_findings.extend(detect_data_exfil_destinations(events))

    user_findings = defaultdict(list)
    for f in all_findings:
        user_findings[f.get("user", "unknown")].append(f)

    user_risks = {}
    for user, findings in user_findings.items():
        user_risks[user] = calculate_risk_score(findings)
        user_risks[user]["finding_count"] = len(findings)

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_events": len(events),
        "total_findings": len(all_findings),
        "user_risk_scores": user_risks,
        "findings": all_findings,
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
