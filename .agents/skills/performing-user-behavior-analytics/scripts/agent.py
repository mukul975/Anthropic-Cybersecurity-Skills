#!/usr/bin/env python3
"""User Behavior Analytics (UEBA) agent using elasticsearch-py."""

import sys
import json
import math
from datetime import datetime, timedelta

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("Install: pip install elasticsearch")
    sys.exit(1)


EARTH_RADIUS_KM = 6371


def get_es_client(host="https://localhost:9200", api_key=None):
    kwargs = {"hosts": [host], "verify_certs": False}
    if api_key:
        kwargs["api_key"] = api_key
    return Elasticsearch(**kwargs)


def haversine(lat1, lon1, lat2, lon2):
    """Calculate distance in km between two coordinates."""
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return EARTH_RADIUS_KM * 2 * math.asin(math.sqrt(a))


def build_user_baselines(es, index="logs-auth-*", days=30):
    """Build behavioral baselines from historical authentication data."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{days}d", "lt": "now-1d"}}},
                    {"term": {"event.outcome": "success"}},
                ]
            }
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "user.name", "size": 5000},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}},
                    "unique_countries": {"cardinality": {"field": "source.geo.country_name"}},
                    "login_hours": {"stats": {"script": "doc['@timestamp'].value.getHour()"}},
                    "daily_count": {
                        "date_histogram": {"field": "@timestamp", "calendar_interval": "day"},
                    },
                }
            }
        },
    }
    result = es.search(index=index, body=query)
    baselines = {}
    for bucket in result["aggregations"]["by_user"]["buckets"]:
        user = bucket["key"]
        daily_counts = [b["doc_count"] for b in bucket["daily_count"]["buckets"]]
        avg_daily = sum(daily_counts) / max(len(daily_counts), 1)
        baselines[user] = {
            "unique_ips": bucket["unique_ips"]["value"],
            "unique_countries": bucket["unique_countries"]["value"],
            "avg_login_hour": bucket["login_hours"]["avg"],
            "stdev_login_hour": bucket["login_hours"].get("std_deviation", 4),
            "avg_daily_logins": round(avg_daily, 1),
            "total_logins": bucket["doc_count"],
        }
    return baselines


def detect_impossible_travel(es, index="logs-auth-*", hours=24):
    """Detect logins from geographically distant locations within impossible timeframes."""
    query = {
        "size": 10000,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                    {"term": {"event.outcome": "success"}},
                    {"exists": {"field": "source.geo.location"}},
                ]
            }
        },
        "sort": [{"user.name": "asc"}, {"@timestamp": "asc"}],
    }
    result = es.search(index=index, body=query)
    events_by_user = {}
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        user = src.get("user", {}).get("name")
        if not user:
            continue
        events_by_user.setdefault(user, []).append({
            "timestamp": src.get("@timestamp"),
            "ip": src.get("source", {}).get("ip"),
            "lat": src.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "lon": src.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "city": src.get("source", {}).get("geo", {}).get("city_name"),
            "country": src.get("source", {}).get("geo", {}).get("country_name"),
        })
    alerts = []
    for user, events in events_by_user.items():
        for i in range(1, len(events)):
            prev, curr = events[i - 1], events[i]
            if not all([prev.get("lat"), prev.get("lon"), curr.get("lat"), curr.get("lon")]):
                continue
            dist = haversine(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            try:
                t1 = datetime.fromisoformat(prev["timestamp"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(curr["timestamp"].replace("Z", "+00:00"))
                hours_diff = (t2 - t1).total_seconds() / 3600
            except (ValueError, TypeError):
                continue
            if hours_diff <= 0:
                continue
            speed = dist / hours_diff
            if speed > 900 and dist > 500:
                alerts.append({
                    "user": user,
                    "from": f"{prev.get('city', '?')}, {prev.get('country', '?')}",
                    "to": f"{curr.get('city', '?')}, {curr.get('country', '?')}",
                    "distance_km": round(dist),
                    "time_hours": round(hours_diff, 2),
                    "speed_kmh": round(speed),
                    "prev_time": prev["timestamp"],
                    "curr_time": curr["timestamp"],
                })
    return alerts


def detect_off_hours_access(es, baselines, index="logs-auth-*", hours=168):
    """Detect logins outside user's normal working hours."""
    query = {
        "size": 5000,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                    {"term": {"event.outcome": "success"}},
                ]
            }
        },
    }
    result = es.search(index=index, body=query)
    alerts = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        user = src.get("user", {}).get("name")
        ts = src.get("@timestamp", "")
        if not user or user not in baselines:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        hour = dt.hour
        baseline = baselines[user]
        avg_hour = baseline.get("avg_login_hour", 12)
        stdev = baseline.get("stdev_login_hour", 4)
        if avg_hour and stdev:
            if hour < (avg_hour - 2 * stdev) or hour > (avg_hour + 2 * stdev):
                if hour < 6 or hour > 22 or dt.weekday() >= 5:
                    alerts.append({
                        "user": user,
                        "timestamp": ts,
                        "login_hour": hour,
                        "baseline_avg": round(avg_hour, 1),
                        "weekend": dt.weekday() >= 5,
                        "ip": src.get("source", {}).get("ip"),
                    })
    return alerts


def calculate_risk_scores(impossible_travel, off_hours, baselines):
    """Aggregate anomalies into composite risk scores per user."""
    scores = {}
    for alert in impossible_travel:
        user = alert["user"]
        scores.setdefault(user, {"risk": 0, "anomalies": []})
        scores[user]["risk"] += 40
        scores[user]["anomalies"].append(f"Impossible travel: {alert['from']} -> {alert['to']}")
    for alert in off_hours:
        user = alert["user"]
        scores.setdefault(user, {"risk": 0, "anomalies": []})
        scores[user]["risk"] += 20
        scores[user]["anomalies"].append(f"Off-hours login at {alert['login_hour']}:00")
    sorted_users = sorted(scores.items(), key=lambda x: -x[1]["risk"])
    return sorted_users


def print_report(travel_alerts, offhours_alerts, risk_scores):
    print("UEBA ANOMALY REPORT")
    print("=" * 50)
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Impossible Travel Alerts: {len(travel_alerts)}")
    print(f"Off-Hours Access Alerts:  {len(offhours_alerts)}")
    print(f"\nTOP RISK USERS:")
    for user, data in risk_scores[:10]:
        print(f"  {user:20s} Risk: {data['risk']:>5}")
        for a in data["anomalies"][:3]:
            print(f"    - {a}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:9200"
    es = get_es_client(host)
    baselines = build_user_baselines(es)
    travel = detect_impossible_travel(es)
    offhours = detect_off_hours_access(es, baselines)
    risk = calculate_risk_scores(travel, offhours, baselines)
    print_report(travel, offhours, risk)
