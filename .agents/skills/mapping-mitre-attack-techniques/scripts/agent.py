#!/usr/bin/env python3
"""
MITRE ATT&CK Technique Mapping Agent
Maps detection rules and security alerts to ATT&CK techniques using
the mitreattack-python library. Generates coverage heatmaps and identifies gaps.
"""

import json
import os
import sys
from datetime import datetime, timezone

from mitreattack.stix20 import MitreAttackData


def load_attack_data(stix_path: str = None) -> MitreAttackData:
    """Load MITRE ATT&CK STIX data bundle."""
    if stix_path and os.path.exists(stix_path):
        return MitreAttackData(stix_filepath=stix_path)
    return MitreAttackData(stix_filepath="enterprise-attack.json")


def get_all_techniques(attack_data: MitreAttackData) -> list[dict]:
    """Retrieve all Enterprise ATT&CK techniques with metadata.
    Returns list[AttackPattern] (STIX objects supporting dict-like access).
    """
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
    result = []
    for tech in techniques:
        # Use get_attack_id() to resolve STIX ID -> ATT&CK ID (e.g. T1059)
        tech_id = attack_data.get_attack_id(stix_id=tech.id) or ""

        platforms = tech.get("x_mitre_platforms", [])
        tactics = []
        for phase in tech.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        result.append({
            "id": tech_id,
            "name": tech.name,
            "tactics": tactics,
            "platforms": platforms,
            "is_subtechnique": tech.get("x_mitre_is_subtechnique", False),
        })

    return sorted(result, key=lambda x: x["id"])


def get_techniques_by_group(attack_data: MitreAttackData, group_name: str) -> list[str]:
    """Get techniques used by a specific threat group.
    Groups are IntrusionSet STIX objects; techniques retrieved via relationship query.
    """
    groups = attack_data.get_groups(remove_revoked_deprecated=True)
    target_group = None
    for group in groups:
        if group.name.lower() == group_name.lower():
            target_group = group
            break
        for alias in group.get("aliases", []):
            if alias.lower() == group_name.lower():
                target_group = group
                break

    if not target_group:
        return []

    # get_techniques_used_by_group returns list of RelationshipEntry dicts
    # Each entry has t["object"] = AttackPattern STIX object
    techniques = attack_data.get_techniques_used_by_group(target_group.id)
    tech_ids = []
    for t in techniques:
        technique = t["object"]
        attack_id = attack_data.get_attack_id(stix_id=technique.id)
        if attack_id:
            tech_ids.append(attack_id)

    return sorted(tech_ids)


def load_detection_rules(rules_file: str) -> list[dict]:
    """Load detection rules with ATT&CK technique tags."""
    if os.path.exists(rules_file):
        with open(rules_file, "r") as f:
            return json.load(f)
    return []


def calculate_coverage(all_techniques: list[dict], detected_technique_ids: set) -> dict:
    """Calculate ATT&CK coverage statistics by tactic."""
    tactic_coverage = {}

    for tech in all_techniques:
        if tech["is_subtechnique"]:
            continue
        for tactic in tech["tactics"]:
            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = {"total": 0, "covered": 0, "uncovered_techniques": []}
            tactic_coverage[tactic]["total"] += 1
            if tech["id"] in detected_technique_ids:
                tactic_coverage[tactic]["covered"] += 1
            else:
                tactic_coverage[tactic]["uncovered_techniques"].append(tech["id"])

    for tactic, data in tactic_coverage.items():
        data["coverage_pct"] = round(data["covered"] / max(data["total"], 1) * 100, 1)

    total_techniques = len([t for t in all_techniques if not t["is_subtechnique"]])
    covered = len(detected_technique_ids & {t["id"] for t in all_techniques if not t["is_subtechnique"]})

    return {
        "overall_coverage_pct": round(covered / max(total_techniques, 1) * 100, 1),
        "total_techniques": total_techniques,
        "covered_techniques": covered,
        "by_tactic": tactic_coverage,
    }


def generate_navigator_layer(techniques: list[dict], detected_ids: set, layer_name: str) -> dict:
    """Generate ATT&CK Navigator JSON layer for visualization."""
    tech_entries = []
    for tech in techniques:
        score = 1 if tech["id"] in detected_ids else 0
        color = "#31a354" if score == 1 else ""
        tech_entries.append({
            "techniqueID": tech["id"],
            "score": score,
            "color": color,
            "enabled": True,
        })

    return {
        "name": layer_name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Detection coverage layer generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "gradient": {"colors": ["#ff6666", "#31a354"], "minValue": 0, "maxValue": 1},
        "techniques": tech_entries,
    }


def identify_priority_gaps(coverage: dict, group_techniques: list[str]) -> list[dict]:
    """Identify high-priority coverage gaps based on threat group activity."""
    gaps = []
    all_uncovered = set()
    for tactic, data in coverage["by_tactic"].items():
        all_uncovered.update(data["uncovered_techniques"])

    for tech_id in group_techniques:
        if tech_id in all_uncovered:
            gaps.append({"technique_id": tech_id, "reason": "Used by target threat group, no detection"})

    return gaps


def generate_report(coverage: dict, gaps: list, group_name: str) -> str:
    """Generate ATT&CK mapping report."""
    lines = [
        "MITRE ATT&CK DETECTION COVERAGE REPORT",
        "=" * 50,
        f"Report Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Overall Coverage: {coverage['overall_coverage_pct']}%",
        f"  Techniques Covered: {coverage['covered_techniques']}/{coverage['total_techniques']}",
        "",
        "COVERAGE BY TACTIC:",
    ]
    for tactic, data in sorted(coverage["by_tactic"].items()):
        bar = "#" * int(data["coverage_pct"] / 5) + "." * (20 - int(data["coverage_pct"] / 5))
        lines.append(f"  {tactic:35s} [{bar}] {data['coverage_pct']}%")

    if gaps:
        lines.extend(["", f"PRIORITY GAPS (Threat Group: {group_name}):", "-" * 40])
        for gap in gaps[:15]:
            lines.append(f"  [GAP] {gap['technique_id']} - {gap['reason']}")

    return "\n".join(lines)


if __name__ == "__main__":
    stix_path = sys.argv[1] if len(sys.argv) > 1 else "enterprise-attack.json"
    rules_file = sys.argv[2] if len(sys.argv) > 2 else "detection_rules.json"
    group_name = sys.argv[3] if len(sys.argv) > 3 else "APT29"

    print("[*] Loading MITRE ATT&CK data...")
    attack_data = load_attack_data(stix_path)
    all_techniques = get_all_techniques(attack_data)
    print(f"[*] Loaded {len(all_techniques)} techniques")

    rules = load_detection_rules(rules_file)
    detected_ids = set()
    for rule in rules:
        detected_ids.update(rule.get("attack_ids", []))

    coverage = calculate_coverage(all_techniques, detected_ids)
    group_techs = get_techniques_by_group(attack_data, group_name)
    gaps = identify_priority_gaps(coverage, group_techs)

    report = generate_report(coverage, gaps, group_name)
    print(report)

    layer = generate_navigator_layer(all_techniques, detected_ids, "Detection Coverage")
    with open("attack_navigator_layer.json", "w") as f:
        json.dump(layer, f, indent=2)
    print(f"\n[*] Navigator layer saved to attack_navigator_layer.json")
