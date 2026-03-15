#!/usr/bin/env python3
"""Adversary-in-the-Middle (AiTM) Phishing Detection agent - analyzes sign-in
logs and inbox rules to detect AiTM phishing campaigns that bypass MFA by
proxying authentication sessions."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from math import radians, cos, sin, asin, sqrt


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two points."""
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return 2 * 6371 * asin(sqrt(a))


def load_sign_in_logs(log_path: str) -> list[dict]:
    """Load Azure AD / Entra ID sign-in logs in JSON format."""
    content = Path(log_path).read_text(encoding="utf-8")
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return [json.loads(line) for line in content.strip().splitlines() if line.strip()]


def detect_impossible_travel(logs: list[dict], max_speed_kmh: float = 900) -> list[dict]:
    """Detect impossible travel - logins from distant locations in short time."""
    findings = []
    user_logins = defaultdict(list)
    for log in logs:
        user = log.get("userPrincipalName", "")
        ts = log.get("createdDateTime", "")
        lat = log.get("location", {}).get("latitude")
        lon = log.get("location", {}).get("longitude")
        ip = log.get("ipAddress", "")
        if user and ts and lat is not None and lon is not None:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                user_logins[user].append({"dt": dt, "lat": lat, "lon": lon, "ip": ip})
            except ValueError:
                continue

    for user, logins in user_logins.items():
        logins.sort(key=lambda x: x["dt"])
        for i in range(1, len(logins)):
            prev, curr = logins[i - 1], logins[i]
            dist = haversine_km(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            hours = (curr["dt"] - prev["dt"]).total_seconds() / 3600
            if hours > 0 and dist / hours > max_speed_kmh and dist > 100:
                findings.append({
                    "type": "impossible_travel",
                    "severity": "critical",
                    "user": user,
                    "distance_km": round(dist, 1),
                    "time_hours": round(hours, 2),
                    "speed_kmh": round(dist / hours, 0),
                    "from_ip": prev["ip"],
                    "to_ip": curr["ip"],
                    "detail": f"Login from {round(dist)}km away in {round(hours, 1)}h ({round(dist/hours)}km/h)",
                })
    return findings


def detect_suspicious_inbox_rules(rules_path: str) -> list[dict]:
    """Detect inbox rules commonly created by AiTM attackers."""
    findings = []
    rules = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    suspicious_actions = {"moveToDeletedItems", "permanentDelete", "forwardTo",
                          "redirectTo", "markAsRead"}
    suspicious_keywords = {"invoice", "payment", "wire", "bank", "urgent",
                           "password", "mfa", "security", "verify"}

    for rule in rules:
        actions = set(rule.get("actions", {}).keys())
        matched_actions = actions & suspicious_actions
        conditions = json.dumps(rule.get("conditions", {})).lower()
        matched_keywords = {kw for kw in suspicious_keywords if kw in conditions}

        if matched_actions:
            severity = "critical" if "forwardTo" in matched_actions or "redirectTo" in matched_actions else "high"
            findings.append({
                "type": "suspicious_inbox_rule",
                "severity": severity,
                "rule_name": rule.get("displayName", "unnamed"),
                "user": rule.get("mailboxOwner", "unknown"),
                "suspicious_actions": sorted(matched_actions),
                "keyword_triggers": sorted(matched_keywords),
                "created": rule.get("createdDateTime", ""),
                "detail": f"Rule with {', '.join(matched_actions)} actions",
            })
    return findings


def detect_token_replay(logs: list[dict]) -> list[dict]:
    """Detect potential session token replay from new device/location."""
    findings = []
    user_sessions = defaultdict(list)
    for log in logs:
        user = log.get("userPrincipalName", "")
        session_id = log.get("correlationId", "")
        device = log.get("deviceDetail", {}).get("displayName", "unknown")
        ip = log.get("ipAddress", "")
        user_agent = log.get("userAgent", "")
        if user:
            user_sessions[user].append({
                "session": session_id, "device": device,
                "ip": ip, "ua": user_agent,
            })

    for user, sessions in user_sessions.items():
        ips = set(s["ip"] for s in sessions)
        devices = set(s["device"] for s in sessions)
        if len(ips) > 3 and len(devices) > 3:
            findings.append({
                "type": "possible_token_replay",
                "severity": "high",
                "user": user,
                "unique_ips": len(ips),
                "unique_devices": len(devices),
                "detail": f"{len(ips)} IPs and {len(devices)} devices in session data",
            })
    return findings


def generate_report(log_path: str, rules_path: str = None,
                    max_speed: float = 900) -> dict:
    """Run all detection checks and build consolidated report."""
    logs = load_sign_in_logs(log_path)
    findings = []
    findings.extend(detect_impossible_travel(logs, max_speed))
    findings.extend(detect_token_replay(logs))
    if rules_path:
        findings.extend(detect_suspicious_inbox_rules(rules_path))

    severity_counts = Counter(f["severity"] for f in findings)
    return {
        "report": "aitm_phishing_detection",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_sign_ins_analyzed": len(logs),
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="AiTM Phishing Detection Agent")
    parser.add_argument("--logs", required=True, help="Azure AD sign-in logs JSON file")
    parser.add_argument("--inbox-rules", help="Inbox rules JSON export")
    parser.add_argument("--max-speed", type=float, default=900, help="Max travel speed km/h (default: 900)")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.logs, args.inbox_rules, args.max_speed)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
