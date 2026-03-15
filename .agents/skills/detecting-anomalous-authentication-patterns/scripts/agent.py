#!/usr/bin/env python3
"""Authentication anomaly detection agent using UEBA analytics."""

import json
import sys
import csv
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
from collections import Counter
from pathlib import Path


def haversine_km(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance between two coordinates in km."""
    R = 6371
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))


def load_auth_logs(csv_path):
    """Load authentication logs from CSV with columns:
    timestamp,user,source_ip,result,lat,lon,city,country,app,device
    """
    events = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["lat"] = float(row["lat"]) if row.get("lat") else None
            row["lon"] = float(row["lon"]) if row.get("lon") else None
            events.append(row)
    return events


def detect_impossible_travel(events, max_speed_kmh=900):
    """Detect logins from locations requiring travel speed above threshold."""
    alerts = []
    by_user = {}
    for e in events:
        user = e.get("user", "")
        if user not in by_user:
            by_user[user] = []
        by_user[user].append(e)

    for user, user_events in by_user.items():
        successful = [e for e in user_events if e.get("result") == "success"]
        successful.sort(key=lambda x: x.get("timestamp", ""))

        for i in range(1, len(successful)):
            prev = successful[i - 1]
            curr = successful[i]
            if not prev.get("lat") or not curr.get("lat"):
                continue
            if prev["lat"] is None or curr["lat"] is None:
                continue

            dist = haversine_km(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            try:
                t1 = datetime.fromisoformat(prev["timestamp"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(curr["timestamp"].replace("Z", "+00:00"))
                hours = (t2 - t1).total_seconds() / 3600
            except Exception:
                continue

            if hours <= 0 or dist < 100:
                continue
            speed = dist / hours
            if speed > max_speed_kmh:
                alerts.append({
                    "type": "IMPOSSIBLE_TRAVEL",
                    "severity": "HIGH",
                    "user": user,
                    "from": f"{prev.get('city', '?')}, {prev.get('country', '?')}",
                    "to": f"{curr.get('city', '?')}, {curr.get('country', '?')}",
                    "distance_km": round(dist, 1),
                    "time_hours": round(hours, 2),
                    "speed_kmh": round(speed, 1),
                    "ip_from": prev.get("source_ip"),
                    "ip_to": curr.get("source_ip"),
                })
    return alerts


def detect_brute_force(events, threshold=10, window_min=10):
    """Detect brute force: many failures for same user in time window."""
    alerts = []
    by_user = {}
    for e in events:
        if e.get("result") == "failure":
            user = e.get("user", "")
            if user not in by_user:
                by_user[user] = []
            by_user[user].append(e)

    for user, fails in by_user.items():
        fails.sort(key=lambda x: x.get("timestamp", ""))
        for i, event in enumerate(fails):
            try:
                t_start = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                t_end = t_start + timedelta(minutes=window_min)
            except Exception:
                continue
            window = [
                f for f in fails
                if t_start <= datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00")) <= t_end
            ]
            if len(window) >= threshold:
                ips = list(set(w.get("source_ip", "") for w in window))
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "user": user,
                    "failures": len(window),
                    "window_minutes": window_min,
                    "source_ips": ips,
                    "distributed": len(ips) > 1,
                })
                break
    return alerts


def detect_password_spray(events, user_threshold=10, window_min=30):
    """Detect password spray: many users targeted from same IP."""
    alerts = []
    by_ip = {}
    for e in events:
        if e.get("result") == "failure":
            ip = e.get("source_ip", "")
            if ip not in by_ip:
                by_ip[ip] = []
            by_ip[ip].append(e)

    for ip, fails in by_ip.items():
        fails.sort(key=lambda x: x.get("timestamp", ""))
        for event in fails:
            try:
                t_start = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                t_end = t_start + timedelta(minutes=window_min)
            except Exception:
                continue
            window = [
                f for f in fails
                if t_start <= datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00")) <= t_end
            ]
            users = set(w.get("user", "") for w in window)
            if len(users) >= user_threshold:
                avg_per_user = len(window) / len(users)
                if avg_per_user <= 3:
                    alerts.append({
                        "type": "PASSWORD_SPRAY",
                        "severity": "CRITICAL",
                        "source_ip": ip,
                        "targeted_users": len(users),
                        "total_attempts": len(window),
                        "avg_per_user": round(avg_per_user, 1),
                    })
                    break
    return alerts


def build_user_baseline(events, user):
    """Build behavioral baseline for a user from historical events."""
    user_events = [e for e in events if e.get("user") == user]
    if not user_events:
        return {"error": f"No events for user {user}"}

    hours = []
    ips = Counter()
    countries = Counter()
    apps = Counter()
    devices = Counter()

    for e in user_events:
        try:
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            hours.append(ts.hour)
        except Exception:
            pass
        ips[e.get("source_ip", "")] += 1
        countries[e.get("country", "")] += 1
        apps[e.get("app", "")] += 1
        devices[e.get("device", "")] += 1

    return {
        "user": user,
        "event_count": len(user_events),
        "typical_hours": sorted(set(hours)),
        "top_ips": ips.most_common(10),
        "top_countries": countries.most_common(5),
        "top_apps": apps.most_common(10),
        "top_devices": devices.most_common(5),
        "failure_rate": round(
            sum(1 for e in user_events if e.get("result") == "failure") / len(user_events), 3
        ),
    }


def calculate_risk_score(alerts):
    """Calculate composite risk score from detected anomalies."""
    weights = {
        "IMPOSSIBLE_TRAVEL": 40,
        "PASSWORD_SPRAY": 35,
        "BRUTE_FORCE": 30,
        "NEW_COUNTRY": 25,
        "OFF_HOURS": 15,
    }
    score = sum(weights.get(a.get("type", ""), 10) for a in alerts)
    score = min(100, score)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"score": score, "level": level, "alert_count": len(alerts)}


def run_full_analysis(csv_path):
    """Run all detection modules on an auth log CSV file."""
    events = load_auth_logs(csv_path)
    travel = detect_impossible_travel(events)
    brute = detect_brute_force(events)
    spray = detect_password_spray(events)
    all_alerts = travel + brute + spray
    return {
        "file": csv_path,
        "total_events": len(events),
        "impossible_travel": travel,
        "brute_force": brute,
        "password_spray": spray,
        "risk": calculate_risk_score(all_alerts),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: agent.py <auth_logs.csv> [--user <username>]")
        sys.exit(1)

    csv_file = sys.argv[1]
    if "--user" in sys.argv:
        idx = sys.argv.index("--user")
        user = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        if user:
            events = load_auth_logs(csv_file)
            print(json.dumps(build_user_baseline(events, user), indent=2, default=str))
    else:
        print(json.dumps(run_full_analysis(csv_file), indent=2, default=str))
