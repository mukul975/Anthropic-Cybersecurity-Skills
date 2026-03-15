#!/usr/bin/env python3
"""MITRE ATT&CK Coverage Mapping Agent - maps detection rules to ATT&CK techniques and identifies gaps."""

import json
import argparse
import logging
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ENTERPRISE_TACTICS = [
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
    "TA0011", "TA0040", "TA0042", "TA0043",
]

TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0010": "Exfiltration", "TA0011": "Command and Control",
    "TA0040": "Impact", "TA0042": "Resource Development", "TA0043": "Reconnaissance",
}


def load_detection_rules(filepath):
    """Load detection rules with ATT&CK mappings."""
    with open(filepath) as f:
        return json.load(f)


def load_attack_matrix(filepath):
    """Load ATT&CK enterprise matrix (techniques per tactic)."""
    with open(filepath) as f:
        return json.load(f)


def map_rules_to_techniques(rules):
    """Map detection rules to ATT&CK technique IDs."""
    technique_rules = defaultdict(list)
    unmapped = []
    for rule in rules:
        techniques = rule.get("mitre_attack", [])
        if not techniques:
            unmapped.append(rule.get("name", "unknown"))
            continue
        for tech in techniques:
            technique_rules[tech].append({
                "rule_name": rule.get("name", ""),
                "severity": rule.get("severity", "medium"),
                "data_source": rule.get("data_source", ""),
                "enabled": rule.get("enabled", True),
            })
    return dict(technique_rules), unmapped


def calculate_coverage(technique_rules, attack_matrix):
    """Calculate coverage percentage per tactic."""
    tactic_coverage = {}
    for tactic_id, tactic_name in TACTIC_NAMES.items():
        techniques_in_tactic = attack_matrix.get(tactic_id, [])
        total = len(techniques_in_tactic)
        covered = sum(1 for t in techniques_in_tactic if t in technique_rules)
        tactic_coverage[tactic_id] = {
            "tactic_name": tactic_name,
            "total_techniques": total,
            "covered": covered,
            "coverage_percent": round(covered / max(total, 1) * 100, 1),
            "gaps": [t for t in techniques_in_tactic if t not in technique_rules],
        }
    return tactic_coverage


def identify_priority_gaps(tactic_coverage, priority_techniques=None):
    """Identify high-priority coverage gaps."""
    gaps = []
    for tactic_id, data in tactic_coverage.items():
        for tech in data["gaps"]:
            priority = "high" if (priority_techniques and tech in priority_techniques) else "medium"
            gaps.append({
                "technique": tech,
                "tactic": data["tactic_name"],
                "tactic_id": tactic_id,
                "priority": priority,
            })
    return sorted(gaps, key=lambda x: (0 if x["priority"] == "high" else 1, x["tactic"]))


def calculate_detection_depth(technique_rules):
    """Assess detection depth per technique (number of rules covering it)."""
    depth = {}
    for tech, rules in technique_rules.items():
        enabled_rules = [r for r in rules if r["enabled"]]
        data_sources = list(set(r["data_source"] for r in enabled_rules if r["data_source"]))
        depth[tech] = {
            "total_rules": len(rules),
            "enabled_rules": len(enabled_rules),
            "data_sources": data_sources,
            "depth": "deep" if len(enabled_rules) >= 3 else "moderate" if len(enabled_rules) >= 2 else "shallow",
        }
    return depth


def generate_navigator_layer(technique_rules, tactic_coverage):
    """Generate ATT&CK Navigator layer JSON."""
    techniques = []
    for tech_id, rules in technique_rules.items():
        score = min(len(rules), 4)
        techniques.append({
            "techniqueID": tech_id,
            "score": score,
            "comment": f"{len(rules)} detection rules",
            "enabled": True,
        })
    layer = {
        "name": "Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#66b1ff", "#0044cc"], "minValue": 0, "maxValue": 4},
    }
    return layer


def generate_report(rules, technique_rules, unmapped, tactic_coverage, depth):
    total_techniques_covered = len(technique_rules)
    total_rules = len(rules)
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_detection_rules": total_rules,
        "mapped_rules": total_rules - len(unmapped),
        "unmapped_rules": len(unmapped),
        "techniques_covered": total_techniques_covered,
        "tactic_coverage": tactic_coverage,
        "detection_depth_summary": {
            "deep": sum(1 for d in depth.values() if d["depth"] == "deep"),
            "moderate": sum(1 for d in depth.values() if d["depth"] == "moderate"),
            "shallow": sum(1 for d in depth.values() if d["depth"] == "shallow"),
        },
        "priority_gaps": identify_priority_gaps(tactic_coverage)[:20],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Coverage Mapping Agent")
    parser.add_argument("--rules", required=True, help="JSON file with detection rules and ATT&CK mappings")
    parser.add_argument("--matrix", help="ATT&CK matrix JSON (techniques per tactic)")
    parser.add_argument("--navigator-output", help="Output ATT&CK Navigator layer JSON")
    parser.add_argument("--output", default="attack_coverage_report.json")
    args = parser.parse_args()

    rules = load_detection_rules(args.rules)
    attack_matrix = load_attack_matrix(args.matrix) if args.matrix else {t: [] for t in ENTERPRISE_TACTICS}

    technique_rules, unmapped = map_rules_to_techniques(rules)
    tactic_coverage = calculate_coverage(technique_rules, attack_matrix)
    depth = calculate_detection_depth(technique_rules)
    report = generate_report(rules, technique_rules, unmapped, tactic_coverage, depth)

    if args.navigator_output:
        layer = generate_navigator_layer(technique_rules, tactic_coverage)
        with open(args.navigator_output, "w") as f:
            json.dump(layer, f, indent=2)
        logger.info("Navigator layer saved to %s", args.navigator_output)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Coverage: %d techniques covered by %d rules", len(technique_rules), len(rules))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
