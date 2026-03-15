#!/usr/bin/env python3
"""Alert fatigue reduction agent for SOC operations using Splunk SDK."""

import json
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
except ImportError:
    print("Install splunk-sdk: pip install splunk-sdk")
    sys.exit(1)


def connect_splunk(host, port, username, password):
    """Connect to Splunk instance."""
    return splunk_client.connect(host=host, port=port,
                                username=username, password=password)


def get_alert_quality_metrics(service, days=90):
    """Query alert disposition data to measure alert quality."""
    query = f"""search index=notable earliest=-{days}d
    | stats count AS total_alerts,
        sum(eval(if(status_label="Resolved - True Positive", 1, 0))) AS tp,
        sum(eval(if(status_label="Resolved - False Positive", 1, 0))) AS fp,
        sum(eval(if(status_label="Resolved - Benign", 1, 0))) AS benign,
        sum(eval(if(status_label="New" OR status_label="In Progress", 1, 0))) AS unresolved
      by rule_name
    | eval fp_rate = round(fp / total_alerts * 100, 1)
    | eval tp_rate = round(tp / total_alerts * 100, 1)
    | eval snr = round(tp / (fp + 0.01), 2)
    | sort - total_alerts"""
    job = service.jobs.create(query)
    while not job.is_done():
        pass
    return [row for row in splunk_results.JSONResultsReader(job.results(output_mode="json"))]


def identify_noisy_rules(metrics, fp_threshold=70, volume_threshold=500):
    """Identify rules exceeding false positive or volume thresholds."""
    noisy = []
    for rule in metrics:
        fp_rate = float(rule.get("fp_rate", 0))
        total = int(rule.get("total_alerts", 0))
        if fp_rate > fp_threshold or total > volume_threshold:
            noisy.append({
                "rule_name": rule.get("rule_name", "unknown"),
                "total_alerts": total,
                "fp_rate": fp_rate,
                "tp_rate": float(rule.get("tp_rate", 0)),
                "signal_to_noise": float(rule.get("snr", 0)),
                "recommendation": "TUNE" if fp_rate > fp_threshold else "CONSOLIDATE"
            })
    return sorted(noisy, key=lambda x: -x["fp_rate"])


def calculate_analyst_capacity(service, num_analysts=6, days=30):
    """Calculate alerts per analyst per shift."""
    query = f"""search index=notable earliest=-{days}d
    | bin _time span=1d
    | stats count AS daily_alerts by _time
    | stats avg(daily_alerts) AS avg_daily, max(daily_alerts) AS peak_daily"""
    job = service.jobs.create(query)
    while not job.is_done():
        pass
    results = [r for r in splunk_results.JSONResultsReader(job.results(output_mode="json"))]
    if results:
        avg_daily = float(results[0].get("avg_daily", 0))
        peak_daily = float(results[0].get("peak_daily", 0))
        per_analyst = round(avg_daily / num_analysts)
        status = "CRITICAL" if per_analyst > 100 else "WARNING" if per_analyst > 50 else "HEALTHY"
        return {"avg_daily": avg_daily, "peak_daily": peak_daily,
                "per_analyst": per_analyst, "status": status}
    return None


def generate_rba_conversion_plan(noisy_rules):
    """Generate a plan to convert threshold alerts to risk-based alerting."""
    plan = []
    for rule in noisy_rules[:15]:
        plan.append({
            "rule_name": rule["rule_name"],
            "current_fp_rate": rule["fp_rate"],
            "action": "Convert to risk contribution",
            "risk_score_suggestion": 10 if rule["fp_rate"] > 90 else 20 if rule["fp_rate"] > 70 else 30,
            "estimated_alert_reduction": f"{int(rule['total_alerts'] * rule['fp_rate'] / 100)} alerts/period",
        })
    return plan


def generate_tuning_recommendations(noisy_rules):
    """Generate tuning recommendations for noisy rules."""
    recommendations = []
    for rule in noisy_rules:
        rec = {"rule_name": rule["rule_name"], "fp_rate": rule["fp_rate"], "actions": []}
        if rule["fp_rate"] > 90:
            rec["actions"].append("Disable rule and replace with risk contribution")
            rec["actions"].append("Investigate top FP sources for whitelist candidates")
        elif rule["fp_rate"] > 70:
            rec["actions"].append("Add exclusion list for known legitimate sources")
            rec["actions"].append("Narrow detection scope with additional filters")
        else:
            rec["actions"].append("Review and consolidate with related rules")
        recommendations.append(rec)
    return recommendations


def build_fatigue_report(service, num_analysts=6):
    """Build comprehensive alert fatigue reduction report."""
    print(f"\n{'='*60}")
    print(f"  ALERT FATIGUE REDUCTION ANALYSIS")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    metrics = get_alert_quality_metrics(service)
    noisy = identify_noisy_rules(metrics)
    capacity = calculate_analyst_capacity(service, num_analysts)

    if capacity:
        print(f"--- ANALYST CAPACITY ---")
        print(f"  Avg Daily Alerts:      {capacity['avg_daily']:.0f}")
        print(f"  Peak Daily Alerts:     {capacity['peak_daily']:.0f}")
        print(f"  Alerts/Analyst/Shift:  {capacity['per_analyst']}")
        print(f"  Status:                {capacity['status']}\n")

    print(f"--- TOP NOISY RULES ({len(noisy)} identified) ---")
    for r in noisy[:10]:
        print(f"  [{r['recommendation']}] {r['rule_name']}")
        print(f"    Volume: {r['total_alerts']}  FP Rate: {r['fp_rate']}%  SNR: {r['signal_to_noise']}")

    rba_plan = generate_rba_conversion_plan(noisy)
    print(f"\n--- RBA CONVERSION PLAN ({len(rba_plan)} rules) ---")
    total_reduction = 0
    for p in rba_plan:
        print(f"  {p['rule_name']}: risk_score={p['risk_score_suggestion']}, "
              f"reduction={p['estimated_alert_reduction']}")

    tuning = generate_tuning_recommendations(noisy)
    print(f"\n--- TUNING RECOMMENDATIONS ---")
    for t in tuning[:5]:
        print(f"  {t['rule_name']} (FP: {t['fp_rate']}%):")
        for a in t["actions"]:
            print(f"    -> {a}")

    print(f"\n{'='*60}\n")
    return {"metrics": metrics, "noisy_rules": noisy, "rba_plan": rba_plan, "tuning": tuning}


def main():
    parser = argparse.ArgumentParser(description="Alert Fatigue Reduction Agent")
    parser.add_argument("--host", default="localhost", help="Splunk host")
    parser.add_argument("--port", type=int, default=8089, help="Splunk management port")
    parser.add_argument("--username", default="admin", help="Splunk username")
    parser.add_argument("--password", required=True, help="Splunk password")
    parser.add_argument("--analysts", type=int, default=6, help="Number of SOC analysts per shift")
    parser.add_argument("--output", help="Save report JSON to file")
    args = parser.parse_args()

    service = connect_splunk(args.host, args.port, args.username, args.password)
    report = build_fatigue_report(service, args.analysts)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
