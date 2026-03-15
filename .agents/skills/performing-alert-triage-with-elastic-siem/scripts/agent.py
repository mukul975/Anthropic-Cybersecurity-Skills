#!/usr/bin/env python3
"""Alert Triage with Elastic SIEM agent - queries Elasticsearch SIEM signals
index to retrieve, prioritize, and triage security alerts using
elasticsearch-py client."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("Install elasticsearch: pip install elasticsearch", file=sys.stderr)
    sys.exit(1)


SIEM_SIGNALS_INDEX = ".siem-signals-*"

SEVERITY_PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4}


def create_client(host: str, api_key: str = None, username: str = None,
                  password: str = None, verify_certs: bool = True) -> Elasticsearch:
    """Create Elasticsearch client."""
    kwargs = {"hosts": [host], "verify_certs": verify_certs}
    if api_key:
        kwargs["api_key"] = api_key
    elif username and password:
        kwargs["basic_auth"] = (username, password)
    return Elasticsearch(**kwargs)


def get_open_alerts(es: Elasticsearch, hours_back: int = 24,
                    severity: list[str] = None, size: int = 500) -> list[dict]:
    """Retrieve open SIEM alerts from the signals index."""
    must_clauses = [
        {"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
        {"term": {"signal.status": "open"}},
    ]
    if severity:
        must_clauses.append({"terms": {"signal.rule.severity": severity}})

    query = {"bool": {"must": must_clauses}}
    response = es.search(index=SIEM_SIGNALS_INDEX, query=query, size=size,
                         sort=[{"@timestamp": {"order": "desc"}}])
    alerts = []
    for hit in response["hits"]["hits"]:
        src = hit["_source"]
        signal = src.get("signal", {})
        rule = signal.get("rule", {})
        alerts.append({
            "alert_id": hit["_id"],
            "timestamp": src.get("@timestamp", ""),
            "rule_name": rule.get("name", ""),
            "rule_id": rule.get("id", ""),
            "severity": rule.get("severity", "unknown"),
            "risk_score": rule.get("risk_score", 0),
            "status": signal.get("status", ""),
            "source_ip": src.get("source", {}).get("ip", ""),
            "destination_ip": src.get("destination", {}).get("ip", ""),
            "user": src.get("user", {}).get("name", ""),
            "host": src.get("host", {}).get("name", ""),
            "process": src.get("process", {}).get("name", ""),
        })
    return alerts


def get_alert_aggregations(es: Elasticsearch, hours_back: int = 24) -> dict:
    """Aggregate alerts by rule, severity, and host."""
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                {"term": {"signal.status": "open"}},
            ]
        }
    }
    aggs = {
        "by_severity": {"terms": {"field": "signal.rule.severity", "size": 10}},
        "by_rule": {"terms": {"field": "signal.rule.name.keyword", "size": 20}},
        "by_host": {"terms": {"field": "host.name.keyword", "size": 20}},
        "by_user": {"terms": {"field": "user.name.keyword", "size": 20}},
    }
    response = es.search(index=SIEM_SIGNALS_INDEX, query=query, aggs=aggs, size=0)
    result = {}
    for agg_name, agg_data in response.get("aggregations", {}).items():
        result[agg_name] = [
            {"key": bucket["key"], "count": bucket["doc_count"]}
            for bucket in agg_data.get("buckets", [])
        ]
    return result


def prioritize_alerts(alerts: list[dict]) -> list[dict]:
    """Sort and prioritize alerts by severity and risk score."""
    return sorted(alerts, key=lambda a: (
        SEVERITY_PRIORITY.get(a.get("severity", "low"), 5),
        -a.get("risk_score", 0)
    ))


def identify_alert_clusters(alerts: list[dict]) -> list[dict]:
    """Group related alerts that may represent a single incident."""
    clusters = []
    by_host = {}
    for alert in alerts:
        host = alert.get("host", "unknown")
        if host not in by_host:
            by_host[host] = []
        by_host[host].append(alert)

    for host, host_alerts in by_host.items():
        if len(host_alerts) >= 3:
            rules = list(set(a["rule_name"] for a in host_alerts))
            max_severity = min(host_alerts, key=lambda a: SEVERITY_PRIORITY.get(a.get("severity", "low"), 5))
            clusters.append({
                "host": host,
                "alert_count": len(host_alerts),
                "unique_rules": len(rules),
                "rules": rules[:10],
                "max_severity": max_severity["severity"],
                "recommendation": "Investigate as potential incident - multiple alerts on same host",
            })
    return clusters


def generate_report(host: str, api_key: str = None, username: str = None,
                    password: str = None, hours_back: int = 24,
                    severity: list[str] = None) -> dict:
    """Run alert triage and build consolidated report."""
    es = create_client(host, api_key, username, password)
    alerts = get_open_alerts(es, hours_back, severity)
    prioritized = prioritize_alerts(alerts)
    aggregations = get_alert_aggregations(es, hours_back)
    clusters = identify_alert_clusters(alerts)

    severity_counts = Counter(a["severity"] for a in alerts)
    return {
        "report": "elastic_siem_alert_triage",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "time_window_hours": hours_back,
        "total_open_alerts": len(alerts),
        "severity_summary": dict(severity_counts),
        "alert_clusters": clusters,
        "aggregations": aggregations,
        "prioritized_alerts": prioritized[:50],
    }


def main():
    parser = argparse.ArgumentParser(description="Elastic SIEM Alert Triage Agent")
    parser.add_argument("--host", required=True, help="Elasticsearch URL")
    parser.add_argument("--api-key", help="Elasticsearch API key")
    parser.add_argument("--username", help="Elasticsearch username")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    parser.add_argument("--severity", nargs="+", help="Filter by severity levels")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.host, args.api_key, args.username,
                             args.password, args.hours, args.severity)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
