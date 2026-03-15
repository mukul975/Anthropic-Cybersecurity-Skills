#!/usr/bin/env python3
"""OAuth token theft detection agent.

Analyzes sign-in logs for impossible travel, new device sign-ins,
token replay from unusual IPs, and anomalous scope requests.
"""

import argparse
import json
import math
import sys
import datetime
import collections

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


EARTH_RADIUS_KM = 6371


def haversine(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance between two points in km."""
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def detect_impossible_travel(sign_ins, max_speed_kmh=900):
    """Detect impossible travel based on geo and time between logins."""
    alerts = []
    by_user = collections.defaultdict(list)
    for event in sign_ins:
        by_user[event.get("user", "")].append(event)

    for user, events in by_user.items():
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        for i in range(1, len(sorted_events)):
            prev, curr = sorted_events[i - 1], sorted_events[i]
            if not all(k in prev for k in ("lat", "lon")) or not all(k in curr for k in ("lat", "lon")):
                continue
            dist = haversine(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            try:
                t1 = datetime.datetime.fromisoformat(prev["timestamp"].replace("Z", "+00:00"))
                t2 = datetime.datetime.fromisoformat(curr["timestamp"].replace("Z", "+00:00"))
                hours = max((t2 - t1).total_seconds() / 3600, 0.001)
            except (ValueError, KeyError):
                continue
            speed = dist / hours
            if speed > max_speed_kmh and dist > 100:
                alerts.append({
                    "type": "impossible_travel",
                    "user": user,
                    "from_ip": prev.get("ip", ""),
                    "to_ip": curr.get("ip", ""),
                    "distance_km": round(dist, 1),
                    "time_hours": round(hours, 2),
                    "speed_kmh": round(speed, 1),
                    "severity": "HIGH",
                })
    return alerts


def detect_token_replay(sign_ins):
    """Detect token replay from multiple IPs in short timeframe."""
    alerts = []
    by_user = collections.defaultdict(list)
    for event in sign_ins:
        by_user[event.get("user", "")].append(event)

    for user, events in by_user.items():
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        window = []
        for event in sorted_events:
            try:
                ts = datetime.datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except (ValueError, KeyError):
                continue
            window = [e for e in window
                      if (ts - datetime.datetime.fromisoformat(
                          e["timestamp"].replace("Z", "+00:00"))).total_seconds() < 300]
            window.append(event)
            unique_ips = set(e.get("ip") for e in window if e.get("ip"))
            if len(unique_ips) >= 3:
                alerts.append({
                    "type": "token_replay",
                    "user": user,
                    "ips": list(unique_ips),
                    "window_seconds": 300,
                    "severity": "CRITICAL",
                })
    return alerts


def detect_new_device(sign_ins, known_devices=None):
    """Detect sign-ins from previously unseen devices."""
    known = set(known_devices or [])
    alerts = []
    for event in sign_ins:
        device_id = event.get("device_id", event.get("user_agent", ""))
        if device_id and device_id not in known:
            alerts.append({
                "type": "new_device",
                "user": event.get("user", ""),
                "device": device_id,
                "ip": event.get("ip", ""),
                "timestamp": event.get("timestamp", ""),
                "severity": "MEDIUM",
            })
            known.add(device_id)
    return alerts


def detect_suspicious_scopes(sign_ins):
    """Detect OAuth requests with overly broad or sensitive scopes."""
    sensitive_scopes = {
        "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
        "Directory.ReadWrite.All", "User.ReadWrite.All",
        "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    }
    alerts = []
    for event in sign_ins:
        scopes = set(event.get("scopes", []))
        dangerous = scopes & sensitive_scopes
        if len(dangerous) >= 2:
            alerts.append({
                "type": "suspicious_scopes",
                "user": event.get("user", ""),
                "scopes": list(dangerous),
                "app": event.get("app_name", ""),
                "severity": "HIGH",
            })
    return alerts


def main():
    parser = argparse.ArgumentParser(description="OAuth token theft detection agent")
    parser.add_argument("--log-file", help="JSON file with sign-in events")
    parser.add_argument("--max-speed", type=int, default=900, help="Max travel speed km/h (default: 900)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] OAuth Token Theft Detection Agent")
    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "alerts": []}

    if args.log_file:
        with open(args.log_file) as f:
            sign_ins = json.load(f)
    else:
        sign_ins = [
            {"user": "alice@corp.com", "ip": "203.0.113.10", "lat": 40.7128, "lon": -74.0060,
             "timestamp": "2025-06-15T10:00:00Z", "device_id": "device-A"},
            {"user": "alice@corp.com", "ip": "198.51.100.50", "lat": 51.5074, "lon": -0.1278,
             "timestamp": "2025-06-15T10:30:00Z", "device_id": "device-B"},
            {"user": "bob@corp.com", "ip": "10.0.0.1", "lat": 37.7749, "lon": -122.4194,
             "timestamp": "2025-06-15T09:00:00Z", "device_id": "device-C",
             "scopes": ["Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All"]},
        ]
        print("[DEMO] Using sample sign-in events")

    report["alerts"].extend(detect_impossible_travel(sign_ins, args.max_speed))
    report["alerts"].extend(detect_token_replay(sign_ins))
    report["alerts"].extend(detect_new_device(sign_ins))
    report["alerts"].extend(detect_suspicious_scopes(sign_ins))

    by_type = collections.Counter(a["type"] for a in report["alerts"])
    print(f"[*] Total alerts: {len(report['alerts'])}")
    for alert_type, count in by_type.items():
        print(f"    {alert_type}: {count}")
    for a in report["alerts"]:
        print(f"  [{a['severity']}] {a['type']}: {a.get('user', '')} - {a.get('distance_km', a.get('ips', a.get('device', '')))}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
    print(json.dumps({"total_alerts": len(report["alerts"]), "by_type": dict(by_type)}, indent=2))


if __name__ == "__main__":
    main()
