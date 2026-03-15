#!/usr/bin/env python3
"""Firewall Zone Segmentation Agent - audits zone-based firewall rules and inter-zone traffic policies."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def parse_firewall_config(config_file):
    with open(config_file) as f:
        return json.load(f)


def get_iptables_zones():
    cmd = ["iptables", "-L", "-n", "-v", "--line-numbers"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    chains = defaultdict(list)
    current_chain = ""
    for line in result.stdout.split("\n"):
        if line.startswith("Chain"):
            current_chain = line.split()[1]
        elif line.strip() and not line.startswith("num"):
            chains[current_chain].append(line.strip())
    return dict(chains)


def audit_zone_rules(config):
    findings = []
    rules = config.get("rules", [])
    for rule in rules:
        src_zone = rule.get("source_zone", "")
        dst_zone = rule.get("destination_zone", "")
        action = rule.get("action", "")
        service = rule.get("service", "any")
        if action == "allow" and service == "any":
            findings.append({"rule_id": rule.get("id", ""), "source_zone": src_zone, "dest_zone": dst_zone,
                           "issue": "Allows all services between zones", "severity": "high"})
        if action == "allow" and src_zone == "untrust" and dst_zone == "trust":
            findings.append({"rule_id": rule.get("id", ""), "issue": "Inbound from untrust to trust zone", "severity": "critical"})
        if rule.get("log") is False and action == "allow":
            findings.append({"rule_id": rule.get("id", ""), "issue": "Allow rule without logging", "severity": "medium"})
    return findings


def check_default_zone_policies(config):
    issues = []
    for zone in config.get("zones", []):
        if zone.get("default_action", "deny") != "deny":
            issues.append({"zone": zone.get("name"), "default_action": zone.get("default_action"),
                         "issue": "Default zone policy is not deny", "severity": "critical"})
    return issues


def analyze_rule_shadowing(rules):
    shadowed = []
    for i, rule in enumerate(rules):
        for j in range(i):
            prev = rules[j]
            if (prev.get("source_zone") == rule.get("source_zone") and
                prev.get("destination_zone") == rule.get("destination_zone") and
                prev.get("service") == "any" and prev.get("action") == "allow"):
                shadowed.append({"rule_id": rule.get("id"), "shadowed_by": prev.get("id"), "severity": "low"})
                break
    return shadowed


def generate_report(config, zone_findings, default_issues, shadowed):
    all_findings = zone_findings + default_issues + shadowed
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_zones": len(config.get("zones", [])),
        "total_rules": len(config.get("rules", [])),
        "zone_rule_findings": zone_findings,
        "default_policy_issues": default_issues,
        "shadowed_rules": shadowed,
        "total_findings": len(all_findings),
        "critical_findings": sum(1 for f in all_findings if f.get("severity") == "critical"),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Firewall Zone Segmentation Audit Agent")
    parser.add_argument("--config", required=True, help="Firewall zone config JSON file")
    parser.add_argument("--output", default="zone_segmentation_report.json")
    args = parser.parse_args()

    config = parse_firewall_config(args.config)
    zone_findings = audit_zone_rules(config)
    default_issues = check_default_zone_policies(config)
    shadowed = analyze_rule_shadowing(config.get("rules", []))
    report = generate_report(config, zone_findings, default_issues, shadowed)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Zone audit: %d zones, %d rules, %d findings", report["total_zones"], report["total_rules"], report["total_findings"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
