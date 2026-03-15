#!/usr/bin/env python3
"""UEBA Insider Threat Agent - builds behavioral baselines and scores anomalies using Elasticsearch."""

import json
import argparse
import logging
import math
from collections import defaultdict
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def connect_es(hosts, api_key=None):
    """Connect to Elasticsearch cluster."""
    kwargs = {"hosts": hosts, "verify_certs": False, "request_timeout": 30}
    if api_key:
        kwargs["api_key"] = api_key
    return Elasticsearch(**kwargs)


def build_user_baseline(es, index, user_field, hours=720):
    """Build 30-day behavioral baseline per user using ES aggregations."""
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    query = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "users": {
                "terms": {"field": user_field, "size": 5000},
                "aggs": {
                    "login_hours": {"histogram": {"field": "hour_of_day", "interval": 1}},
                    "daily_events": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}},
                    "unique_hosts": {"cardinality": {"field": "host.name"}},
                    "data_volume": {"sum": {"field": "bytes_transferred"}},
                    "unique_apps": {"cardinality": {"field": "application.name"}},
                }
            }
        }
    }
    result = es.search(index=index, body=query)
    baselines = {}
    for bucket in result["aggregations"]["users"]["buckets"]:
        user = bucket["key"]
        daily_counts = [d["doc_count"] for d in bucket["daily_events"]["buckets"]]
        avg_daily = sum(daily_counts) / max(len(daily_counts), 1)
        std_daily = math.sqrt(sum((x - avg_daily) ** 2 for x in daily_counts) / max(len(daily_counts), 1))
        baselines[user] = {
            "avg_daily_events": round(avg_daily, 1),
            "std_daily_events": round(std_daily, 1),
            "unique_hosts": bucket["unique_hosts"]["value"],
            "total_data_volume": bucket["data_volume"]["value"],
            "total_events": bucket["doc_count"],
        }
    return baselines


def score_current_activity(es, index, user_field, baselines, hours=24):
    """Score current activity against baselines to find anomalies."""
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    query = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "users": {
                "terms": {"field": user_field, "size": 5000},
                "aggs": {
                    "unique_hosts": {"cardinality": {"field": "host.name"}},
                    "data_volume": {"sum": {"field": "bytes_transferred"}},
                    "unique_apps": {"cardinality": {"field": "application.name"}},
                }
            }
        }
    }
    result = es.search(index=index, body=query)
    anomalies = []
    for bucket in result["aggregations"]["users"]["buckets"]:
        user = bucket["key"]
        baseline = baselines.get(user)
        if not baseline:
            anomalies.append({
                "user": user, "indicator": "new_user",
                "severity": "medium", "detail": "No baseline exists for this user",
                "risk_score": 50,
            })
            continue
        current_events = bucket["doc_count"]
        avg = baseline["avg_daily_events"]
        std = baseline["std_daily_events"]
        z_score = (current_events - avg) / max(std, 1)
        if z_score > 3:
            anomalies.append({
                "user": user, "indicator": "activity_spike",
                "severity": "high", "z_score": round(z_score, 2),
                "current": current_events, "baseline_avg": avg,
                "risk_score": min(int(z_score * 15), 100),
                "detail": f"Event count {current_events} is {z_score:.1f} std devs above baseline",
            })
        current_hosts = bucket["unique_hosts"]["value"]
        if current_hosts > baseline["unique_hosts"] * 2:
            anomalies.append({
                "user": user, "indicator": "new_host_access",
                "severity": "high",
                "current_hosts": current_hosts,
                "baseline_hosts": baseline["unique_hosts"],
                "risk_score": 70,
                "detail": f"Accessed {current_hosts} hosts vs baseline {baseline['unique_hosts']}",
            })
        current_volume = bucket["data_volume"]["value"]
        daily_avg_volume = baseline["total_data_volume"] / 30
        if current_volume > daily_avg_volume * 5 and current_volume > 100_000_000:
            anomalies.append({
                "user": user, "indicator": "data_exfiltration",
                "severity": "critical",
                "current_bytes": current_volume,
                "baseline_daily_avg": round(daily_avg_volume),
                "risk_score": 90,
                "detail": f"Transferred {current_volume / 1e6:.0f}MB vs daily avg {daily_avg_volume / 1e6:.1f}MB",
            })
    return sorted(anomalies, key=lambda x: x.get("risk_score", 0), reverse=True)


def peer_group_analysis(baselines, peer_groups):
    """Compare user activity against peer group averages."""
    findings = []
    group_stats = defaultdict(list)
    for user, baseline in baselines.items():
        group = peer_groups.get(user, "default")
        group_stats[group].append(baseline["avg_daily_events"])
    group_avgs = {g: sum(v) / len(v) for g, v in group_stats.items()}
    for user, baseline in baselines.items():
        group = peer_groups.get(user, "default")
        group_avg = group_avgs.get(group, 0)
        if group_avg > 0 and baseline["avg_daily_events"] > group_avg * 3:
            findings.append({
                "user": user, "peer_group": group,
                "user_avg": baseline["avg_daily_events"],
                "group_avg": round(group_avg, 1),
                "deviation_factor": round(baseline["avg_daily_events"] / group_avg, 1),
                "severity": "medium",
            })
    return findings


def generate_report(anomalies, peer_findings, baselines):
    critical = sum(1 for a in anomalies if a.get("severity") == "critical")
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "users_baselined": len(baselines),
        "anomalies_detected": len(anomalies),
        "critical_anomalies": critical,
        "top_risk_users": anomalies[:15],
        "peer_group_outliers": peer_findings[:10],
        "risk_level": "critical" if critical > 0 else "high" if anomalies else "low",
    }


def main():
    parser = argparse.ArgumentParser(description="UEBA Insider Threat Detection Agent")
    parser.add_argument("--es-hosts", default="https://localhost:9200", help="Elasticsearch hosts")
    parser.add_argument("--api-key", help="Elasticsearch API key")
    parser.add_argument("--index", default="logs-*", help="Log index pattern")
    parser.add_argument("--user-field", default="user.name", help="User identity field")
    parser.add_argument("--peer-groups", help="JSON file mapping users to peer groups")
    parser.add_argument("--lookback", type=int, default=24, help="Anomaly lookback hours")
    parser.add_argument("--output", default="ueba_insider_threat_report.json")
    args = parser.parse_args()

    es = connect_es(args.es_hosts.split(","), args.api_key)
    baselines = build_user_baseline(es, args.index, args.user_field)
    anomalies = score_current_activity(es, args.index, args.user_field, baselines, args.lookback)
    peer_groups = {}
    if args.peer_groups:
        with open(args.peer_groups) as f:
            peer_groups = json.load(f)
    peer_findings = peer_group_analysis(baselines, peer_groups)
    report = generate_report(anomalies, peer_findings, baselines)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("UEBA: %d users baselined, %d anomalies (%d critical)",
                len(baselines), len(anomalies), report["critical_anomalies"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
