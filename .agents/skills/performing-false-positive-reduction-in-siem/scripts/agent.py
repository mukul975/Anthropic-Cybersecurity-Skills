#!/usr/bin/env python3
"""Agent for performing false positive reduction analysis in SIEM environments."""

import json
import argparse
import csv
from datetime import datetime
from collections import Counter


def analyze_alerts(csv_file, threshold=5):
    """Analyze SIEM alert CSV to identify false positive patterns."""
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    alerts = []
    for row in rows:
        alerts.append({
            "rule": row.get("rule_name", row.get("Rule", row.get("alert_name", ""))),
            "source": row.get("src_ip", row.get("source_ip", row.get("Source", ""))),
            "dest": row.get("dst_ip", row.get("dest_ip", row.get("Destination", ""))),
            "severity": row.get("severity", row.get("Severity", "")),
            "status": row.get("status", row.get("Status", row.get("disposition", ""))).lower(),
            "timestamp": row.get("timestamp", row.get("Time", "")),
        })
    total = len(alerts)
    fp_alerts = [a for a in alerts if a["status"] in ("false_positive", "fp", "closed_fp", "benign")]
    fp_rate = len(fp_alerts) / total * 100 if total else 0
    rule_counts = Counter(a["rule"] for a in alerts)
    fp_by_rule = Counter(a["rule"] for a in fp_alerts)
    noisy_rules = []
    for rule, count in rule_counts.most_common():
        fp_count = fp_by_rule.get(rule, 0)
        rate = fp_count / count * 100 if count else 0
        if rate >= threshold or fp_count >= 10:
            noisy_rules.append({"rule": rule, "total": count, "false_positives": fp_count, "fp_rate": round(rate, 1)})
    source_fp = Counter(a["source"] for a in fp_alerts)
    top_fp_sources = [{"source": s, "fp_count": c} for s, c in source_fp.most_common(10)]
    return {
        "total_alerts": total,
        "false_positives": len(fp_alerts),
        "fp_rate_pct": round(fp_rate, 1),
        "noisy_rules": sorted(noisy_rules, key=lambda x: x["fp_rate"], reverse=True),
        "top_fp_sources": top_fp_sources,
    }


def generate_tuning_recommendations(csv_file):
    """Generate SIEM rule tuning recommendations from alert analysis."""
    analysis = analyze_alerts(csv_file)
    recommendations = []
    for rule in analysis["noisy_rules"]:
        if rule["fp_rate"] >= 90:
            action = "DISABLE"
            reason = f"FP rate {rule['fp_rate']}% — rule generates almost exclusively false positives"
        elif rule["fp_rate"] >= 70:
            action = "ADD_WHITELIST"
            reason = f"FP rate {rule['fp_rate']}% — add source/destination whitelists"
        elif rule["fp_rate"] >= 50:
            action = "TUNE_THRESHOLD"
            reason = f"FP rate {rule['fp_rate']}% — increase detection threshold or add conditions"
        else:
            action = "REVIEW"
            reason = f"FP rate {rule['fp_rate']}% with {rule['false_positives']} FPs — manual review needed"
        recommendations.append({"rule": rule["rule"], "action": action, "reason": reason, **rule})
    return {
        "generated": datetime.utcnow().isoformat(),
        "overall_fp_rate": analysis["fp_rate_pct"],
        "rules_to_tune": len(recommendations),
        "recommendations": recommendations,
        "top_fp_sources": analysis["top_fp_sources"],
    }


def simulate_tuning_impact(csv_file, rules_to_disable=None, sources_to_whitelist=None):
    """Simulate the impact of proposed tuning changes on alert volume."""
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    rules_to_disable = rules_to_disable or []
    sources_to_whitelist = sources_to_whitelist or []
    original = len(rows)
    remaining = []
    suppressed = {"by_rule": 0, "by_source": 0}
    for row in rows:
        rule = row.get("rule_name", row.get("Rule", row.get("alert_name", "")))
        source = row.get("src_ip", row.get("source_ip", row.get("Source", "")))
        if rule in rules_to_disable:
            suppressed["by_rule"] += 1
            continue
        if source in sources_to_whitelist:
            suppressed["by_source"] += 1
            continue
        remaining.append(row)
    reduction = (1 - len(remaining) / original) * 100 if original else 0
    fp_remaining = sum(1 for r in remaining if r.get("status", r.get("Status", "")).lower() in ("false_positive", "fp", "closed_fp", "benign"))
    new_fp_rate = fp_remaining / len(remaining) * 100 if remaining else 0
    return {
        "original_alerts": original,
        "remaining_alerts": len(remaining),
        "suppressed": suppressed,
        "reduction_pct": round(reduction, 1),
        "new_fp_rate_pct": round(new_fp_rate, 1),
    }


def main():
    parser = argparse.ArgumentParser(description="SIEM False Positive Reduction Agent")
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("analyze", help="Analyze alert false positive patterns")
    a.add_argument("--csv", required=True, help="SIEM alert export CSV")
    a.add_argument("--threshold", type=float, default=5, help="Min FP rate to flag")
    t = sub.add_parser("tune", help="Generate tuning recommendations")
    t.add_argument("--csv", required=True)
    s = sub.add_parser("simulate", help="Simulate tuning impact")
    s.add_argument("--csv", required=True)
    s.add_argument("--disable-rules", nargs="*", default=[])
    s.add_argument("--whitelist-sources", nargs="*", default=[])
    args = parser.parse_args()
    if args.command == "analyze":
        result = analyze_alerts(args.csv, args.threshold)
    elif args.command == "tune":
        result = generate_tuning_recommendations(args.csv)
    elif args.command == "simulate":
        result = simulate_tuning_impact(args.csv, args.disable_rules, args.whitelist_sources)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
