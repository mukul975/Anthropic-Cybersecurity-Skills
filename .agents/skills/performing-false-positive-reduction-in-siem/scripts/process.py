#!/usr/bin/env python3
"""
SIEM False Positive Reduction Analyzer

Analyzes alert data to identify false positive patterns,
recommend tuning actions, and track FP reduction metrics.
"""

import json
from datetime import datetime
from collections import Counter


class AlertAnalyzer:
    """Analyzes SIEM alerts for false positive patterns."""

    def __init__(self):
        self.alerts = []
        self.tuning_recommendations = []

    def add_alert(self, rule_name: str, classification: str, source: str,
                  severity: str, triage_time_sec: int):
        self.alerts.append({
            "rule_name": rule_name,
            "classification": classification,  # tp, fp, btp
            "source": source,
            "severity": severity,
            "triage_time_sec": triage_time_sec,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def get_fp_rates(self) -> list:
        rule_stats = {}
        for alert in self.alerts:
            rule = alert["rule_name"]
            if rule not in rule_stats:
                rule_stats[rule] = {"total": 0, "fp": 0, "tp": 0, "btp": 0, "triage_times": []}
            rule_stats[rule]["total"] += 1
            rule_stats[rule][alert["classification"]] += 1
            rule_stats[rule]["triage_times"].append(alert["triage_time_sec"])

        results = []
        for rule, stats in rule_stats.items():
            fp_rate = round(stats["fp"] / max(1, stats["total"]) * 100, 1)
            precision = round(stats["tp"] / max(1, stats["tp"] + stats["fp"]), 3)
            avg_triage = round(sum(stats["triage_times"]) / max(1, len(stats["triage_times"])), 1)
            results.append({
                "rule_name": rule,
                "total": stats["total"],
                "true_positives": stats["tp"],
                "false_positives": stats["fp"],
                "benign_true_positives": stats["btp"],
                "fp_rate": fp_rate,
                "precision": precision,
                "avg_triage_sec": avg_triage,
                "needs_tuning": fp_rate > 30,
            })
        return sorted(results, key=lambda x: x["fp_rate"], reverse=True)

    def get_fp_source_patterns(self) -> dict:
        fp_alerts = [a for a in self.alerts if a["classification"] == "fp"]
        source_counts = Counter(a["source"] for a in fp_alerts)
        rule_source = Counter((a["rule_name"], a["source"]) for a in fp_alerts)
        return {
            "top_fp_sources": source_counts.most_common(10),
            "top_rule_source_combos": rule_source.most_common(10),
        }

    def generate_recommendations(self) -> list:
        recommendations = []
        for rule_data in self.get_fp_rates():
            if rule_data["fp_rate"] > 50:
                recommendations.append({
                    "rule": rule_data["rule_name"],
                    "priority": "critical",
                    "action": "Rewrite or disable - FP rate above 50%",
                    "fp_rate": rule_data["fp_rate"],
                })
            elif rule_data["fp_rate"] > 30:
                recommendations.append({
                    "rule": rule_data["rule_name"],
                    "priority": "high",
                    "action": "Tune thresholds and add allowlists",
                    "fp_rate": rule_data["fp_rate"],
                })
            elif rule_data["avg_triage_sec"] > 600:
                recommendations.append({
                    "rule": rule_data["rule_name"],
                    "priority": "medium",
                    "action": "Add enrichment to reduce triage time",
                    "fp_rate": rule_data["fp_rate"],
                })
        return recommendations

    def get_overall_metrics(self) -> dict:
        total = len(self.alerts)
        fp = sum(1 for a in self.alerts if a["classification"] == "fp")
        tp = sum(1 for a in self.alerts if a["classification"] == "tp")
        times = [a["triage_time_sec"] for a in self.alerts]
        return {
            "total_alerts": total,
            "true_positives": tp,
            "false_positives": fp,
            "overall_fp_rate": round(fp / max(1, total) * 100, 1),
            "overall_precision": round(tp / max(1, tp + fp), 3),
            "avg_triage_time_sec": round(sum(times) / max(1, len(times)), 1),
            "total_analyst_hours_wasted_on_fp": round(sum(
                a["triage_time_sec"] for a in self.alerts if a["classification"] == "fp"
            ) / 3600, 1),
        }


if __name__ == "__main__":
    analyzer = AlertAnalyzer()

    # Simulate alert data
    import random
    rules = [
        ("Brute Force Detection", 0.15),
        ("Suspicious PowerShell", 0.35),
        ("Anomalous DNS Query", 0.55),
        ("Outbound Traffic Spike", 0.40),
        ("New Service Installation", 0.25),
    ]
    sources = ["10.0.0.50", "10.0.1.100", "scanner.internal", "build-server", "vpn-gateway"]

    for rule_name, fp_prob in rules:
        for _ in range(random.randint(20, 80)):
            classification = "fp" if random.random() < fp_prob else ("tp" if random.random() > 0.3 else "btp")
            analyzer.add_alert(
                rule_name, classification,
                random.choice(sources),
                random.choice(["low", "medium", "high"]),
                random.randint(60, 900),
            )

    print("=" * 70)
    print("FALSE POSITIVE REDUCTION ANALYSIS")
    print("=" * 70)

    metrics = analyzer.get_overall_metrics()
    print(f"\nOverall Metrics:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    print(f"\nPer-Rule FP Rates:")
    print(f"{'Rule':<35} {'Total':<8} {'FP':<6} {'TP':<6} {'FP Rate':<10} {'Precision':<10} {'Needs Tuning'}")
    print("-" * 90)
    for r in analyzer.get_fp_rates():
        flag = "*** YES ***" if r["needs_tuning"] else "No"
        print(f"{r['rule_name']:<35} {r['total']:<8} {r['false_positives']:<6} {r['true_positives']:<6} {r['fp_rate']:<10} {r['precision']:<10} {flag}")

    print(f"\nTuning Recommendations:")
    for rec in analyzer.generate_recommendations():
        print(f"  [{rec['priority'].upper()}] {rec['rule']}: {rec['action']} (FP: {rec['fp_rate']}%)")
