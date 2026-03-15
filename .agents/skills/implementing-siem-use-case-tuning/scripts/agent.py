#!/usr/bin/env python3
"""SIEM use case tuning agent - analyzes alert data to reduce false positives and optimize detection rules."""

import json
import csv
import math
import argparse
from collections import defaultdict
from datetime import datetime


def load_alert_data(filepath):
    """Load alert/notable event export (CSV with columns: rule_name, timestamp, disposition, source, user)."""
    alerts = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alerts.append({
                "rule_name": row.get("rule_name", row.get("search_name", "")),
                "timestamp": row.get("timestamp", row.get("_time", "")),
                "disposition": row.get("disposition", row.get("status", "unknown")),
                "source": row.get("source", row.get("src", "")),
                "user": row.get("user", row.get("dest_user", "")),
                "severity": row.get("severity", "medium"),
            })
    return alerts


def calculate_rule_metrics(alerts):
    """Calculate per-rule alert volume, FP rate, and disposition breakdown."""
    rule_stats = defaultdict(lambda: {"total": 0, "true_positive": 0, "false_positive": 0,
                                       "pending": 0, "sources": set(), "users": set()})
    for alert in alerts:
        rule = alert["rule_name"]
        rule_stats[rule]["total"] += 1
        disp = alert["disposition"].lower()
        if disp in ("true_positive", "tp", "confirmed", "escalated"):
            rule_stats[rule]["true_positive"] += 1
        elif disp in ("false_positive", "fp", "benign", "closed_fp"):
            rule_stats[rule]["false_positive"] += 1
        else:
            rule_stats[rule]["pending"] += 1
        if alert["source"]:
            rule_stats[rule]["sources"].add(alert["source"])
        if alert["user"]:
            rule_stats[rule]["users"].add(alert["user"])

    metrics = []
    for rule, stats in rule_stats.items():
        reviewed = stats["true_positive"] + stats["false_positive"]
        fp_rate = stats["false_positive"] / reviewed if reviewed > 0 else 0.0
        precision = stats["true_positive"] / reviewed if reviewed > 0 else 0.0
        metrics.append({
            "rule_name": rule,
            "total_alerts": stats["total"],
            "true_positives": stats["true_positive"],
            "false_positives": stats["false_positive"],
            "pending": stats["pending"],
            "fp_rate": round(fp_rate, 4),
            "precision": round(precision, 4),
            "unique_sources": len(stats["sources"]),
            "unique_users": len(stats["users"]),
            "top_sources": list(stats["sources"])[:10],
        })
    return sorted(metrics, key=lambda x: x["fp_rate"], reverse=True)


def identify_whitelist_candidates(alerts, fp_threshold=0.8):
    """Identify source/user pairs that consistently trigger FPs for a given rule."""
    rule_source_stats = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0}))
    for alert in alerts:
        disp = alert["disposition"].lower()
        key = alert["source"] or alert["user"]
        if not key:
            continue
        if disp in ("false_positive", "fp", "benign", "closed_fp"):
            rule_source_stats[alert["rule_name"]][key]["fp"] += 1
        elif disp in ("true_positive", "tp", "confirmed", "escalated"):
            rule_source_stats[alert["rule_name"]][key]["tp"] += 1

    candidates = []
    for rule, sources in rule_source_stats.items():
        for source, counts in sources.items():
            total = counts["tp"] + counts["fp"]
            if total >= 3 and counts["fp"] / total >= fp_threshold:
                candidates.append({
                    "rule_name": rule,
                    "entity": source,
                    "fp_count": counts["fp"],
                    "tp_count": counts["tp"],
                    "fp_ratio": round(counts["fp"] / total, 4),
                    "recommendation": "Add to whitelist" if counts["tp"] == 0 else "Review before whitelisting",
                })
    return sorted(candidates, key=lambda x: x["fp_count"], reverse=True)


def compute_threshold_recommendation(alerts, rule_name, field="total"):
    """Compute statistical threshold for a rule based on hourly alert distribution."""
    hourly_counts = defaultdict(int)
    for alert in alerts:
        if alert["rule_name"] != rule_name:
            continue
        try:
            dt = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
            hourly_counts[dt.strftime("%Y-%m-%d %H")] += 1
        except (ValueError, AttributeError):
            continue
    if not hourly_counts:
        return None
    values = list(hourly_counts.values())
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    stdev = math.sqrt(variance)
    return {
        "rule_name": rule_name,
        "hourly_mean": round(mean, 2),
        "hourly_stdev": round(stdev, 2),
        "suggested_threshold_2sd": round(mean + 2 * stdev, 0),
        "suggested_threshold_3sd": round(mean + 3 * stdev, 0),
        "sample_hours": len(hourly_counts),
    }


def generate_tuning_report(metrics, whitelist, thresholds):
    """Generate comprehensive tuning report with recommendations."""
    high_fp_rules = [m for m in metrics if m["fp_rate"] > 0.7]
    medium_fp_rules = [m for m in metrics if 0.3 < m["fp_rate"] <= 0.7]
    total_alerts = sum(m["total_alerts"] for m in metrics)
    total_fp = sum(m["false_positives"] for m in metrics)
    projected_reduction = sum(w["fp_count"] for w in whitelist)

    return {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_rules_analyzed": len(metrics),
            "total_alerts": total_alerts,
            "total_false_positives": total_fp,
            "overall_fp_rate": round(total_fp / total_alerts, 4) if total_alerts else 0,
            "high_fp_rules": len(high_fp_rules),
            "whitelist_candidates": len(whitelist),
            "projected_alert_reduction": projected_reduction,
        },
        "high_fp_rules": high_fp_rules,
        "medium_fp_rules": medium_fp_rules,
        "whitelist_recommendations": whitelist[:20],
        "threshold_recommendations": thresholds,
        "actions": [
            {"priority": "high", "action": f"Disable or rewrite {len(high_fp_rules)} rules with FP rate > 70%"},
            {"priority": "medium", "action": f"Add {len(whitelist)} whitelist entries to reduce {projected_reduction} FP alerts"},
            {"priority": "low", "action": f"Review {len(medium_fp_rules)} rules with FP rate 30-70%"},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="SIEM Use Case Tuning Agent")
    parser.add_argument("--alert-csv", required=True, help="CSV export of SIEM alerts with disposition data")
    parser.add_argument("--fp-threshold", type=float, default=0.8, help="FP ratio threshold for whitelist candidates")
    parser.add_argument("--top-rules", type=int, default=5, help="Number of top rules to compute thresholds for")
    parser.add_argument("--output", default="tuning_report.json", help="Output report path")
    args = parser.parse_args()

    alerts = load_alert_data(args.alert_csv)
    print(f"[+] Loaded {len(alerts)} alerts from {args.alert_csv}")

    metrics = calculate_rule_metrics(alerts)
    print(f"[+] Analyzed {len(metrics)} unique detection rules")

    whitelist = identify_whitelist_candidates(alerts, args.fp_threshold)
    print(f"[+] Found {len(whitelist)} whitelist candidates (FP ratio >= {args.fp_threshold})")

    thresholds = []
    for m in metrics[:args.top_rules]:
        t = compute_threshold_recommendation(alerts, m["rule_name"])
        if t:
            thresholds.append(t)

    report = generate_tuning_report(metrics, whitelist, thresholds)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Tuning report saved to {args.output}")
    print(f"[+] Overall FP rate: {report['summary']['overall_fp_rate']:.1%}")
    print(f"[+] Projected alert reduction from whitelisting: {report['summary']['projected_alert_reduction']}")


if __name__ == "__main__":
    main()
