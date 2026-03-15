#!/usr/bin/env python3
"""Suricata IPS Agent - manages rules, analyzes alerts, and tunes Suricata intrusion prevention."""

import json
import argparse
import logging
import subprocess
import re
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EVE_LOG = "/var/log/suricata/eve.json"
RULES_DIR = "/etc/suricata/rules"


def parse_eve_alerts(log_path, limit=10000):
    """Parse Suricata EVE JSON log for alerts."""
    alerts = []
    try:
        with open(log_path) as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append({
                            "timestamp": event.get("timestamp", ""),
                            "src_ip": event.get("src_ip", ""),
                            "dest_ip": event.get("dest_ip", ""),
                            "src_port": event.get("src_port", 0),
                            "dest_port": event.get("dest_port", 0),
                            "proto": event.get("proto", ""),
                            "signature": event.get("alert", {}).get("signature", ""),
                            "signature_id": event.get("alert", {}).get("signature_id", 0),
                            "severity": event.get("alert", {}).get("severity", 0),
                            "category": event.get("alert", {}).get("category", ""),
                            "action": event.get("alert", {}).get("action", ""),
                        })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning("EVE log not found: %s", log_path)
    return alerts


def analyze_alert_distribution(alerts):
    """Analyze alert distribution by signature, severity, and source."""
    by_sig = defaultdict(int)
    by_severity = defaultdict(int)
    by_category = defaultdict(int)
    by_src = defaultdict(int)
    for alert in alerts:
        by_sig[alert["signature"]] += 1
        by_severity[alert["severity"]] += 1
        by_category[alert["category"]] += 1
        by_src[alert["src_ip"]] += 1
    return {
        "top_signatures": dict(sorted(by_sig.items(), key=lambda x: x[1], reverse=True)[:15]),
        "severity_distribution": dict(by_severity),
        "category_distribution": dict(sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_source_ips": dict(sorted(by_src.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


def identify_noisy_rules(alerts, threshold=500):
    """Identify rules that generate excessive alerts for tuning."""
    sig_counts = defaultdict(int)
    sig_info = {}
    for alert in alerts:
        sid = alert["signature_id"]
        sig_counts[sid] += 1
        if sid not in sig_info:
            sig_info[sid] = {"signature": alert["signature"], "category": alert["category"]}
    noisy = []
    for sid, count in sig_counts.items():
        if count >= threshold:
            noisy.append({"sid": sid, "count": count, **sig_info[sid]})
    return sorted(noisy, key=lambda x: x["count"], reverse=True)


def detect_attack_patterns(alerts):
    """Detect coordinated attack patterns from alert correlation."""
    src_dest_pairs = defaultdict(list)
    for alert in alerts:
        key = (alert["src_ip"], alert["dest_ip"])
        src_dest_pairs[key].append(alert)
    patterns = []
    for (src, dst), pair_alerts in src_dest_pairs.items():
        if len(pair_alerts) >= 20:
            sigs = list(set(a["signature_id"] for a in pair_alerts))
            patterns.append({
                "source": src, "target": dst,
                "alert_count": len(pair_alerts),
                "unique_signatures": len(sigs),
                "severity": "critical" if len(sigs) > 5 else "high",
                "pattern": "multi_stage_attack" if len(sigs) > 3 else "repeated_exploit",
            })
    return sorted(patterns, key=lambda x: x["alert_count"], reverse=True)


def check_suricata_status():
    """Check Suricata service status and configuration."""
    status_cmd = subprocess.run(["systemctl", "is-active", "suricata"], capture_output=True, text=True)
    rule_count_cmd = subprocess.run(["suricata", "--build-info"], capture_output=True, text=True)
    stats_cmd = subprocess.run(["suricatasc", "-c", "dump-counters"], capture_output=True, text=True)
    return {
        "service_active": status_cmd.stdout.strip() == "active",
        "build_info": rule_count_cmd.stdout[:200] if rule_count_cmd.returncode == 0 else "unavailable",
    }


def generate_report(alerts, status):
    distribution = analyze_alert_distribution(alerts)
    noisy = identify_noisy_rules(alerts)
    patterns = detect_attack_patterns(alerts)
    dropped = sum(1 for a in alerts if a["action"] == "blocked")
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "suricata_status": status,
        "total_alerts": len(alerts),
        "blocked_events": dropped,
        "block_rate": round(dropped / max(len(alerts), 1) * 100, 1),
        "alert_distribution": distribution,
        "noisy_rules_for_tuning": noisy[:10],
        "attack_patterns_detected": patterns[:10],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Suricata IPS Analysis Agent")
    parser.add_argument("--eve-log", default=EVE_LOG, help="Path to EVE JSON log")
    parser.add_argument("--limit", type=int, default=50000, help="Max log lines to parse")
    parser.add_argument("--noisy-threshold", type=int, default=500, help="Alert count threshold for noisy rules")
    parser.add_argument("--output", default="suricata_ips_report.json")
    args = parser.parse_args()

    status = check_suricata_status()
    alerts = parse_eve_alerts(args.eve_log, args.limit)
    report = generate_report(alerts, status)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Suricata: %d alerts, %.1f%% blocked, %d attack patterns",
                report["total_alerts"], report["block_rate"],
                len(report["attack_patterns_detected"]))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
