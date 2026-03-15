#!/usr/bin/env python3
"""Threat modeling agent using MITRE ATT&CK framework with attackcti."""

import json
import sys
import argparse
from datetime import datetime
from collections import Counter

try:
    from attackcti import attack_client
except ImportError:
    print("Install attackcti: pip install attackcti")
    sys.exit(1)


INDUSTRY_THREAT_ACTORS = {
    "financial": ["APT38", "FIN7", "Carbanak", "Lazarus Group", "FIN8"],
    "healthcare": ["APT41", "FIN12", "Wizard Spider"],
    "government": ["APT28", "APT29", "Turla", "Sandworm Team", "Mustang Panda"],
    "technology": ["APT41", "APT10", "Hafnium", "Nobelium"],
    "energy": ["Sandworm Team", "Dragonfly", "Berserk Bear", "APT33"],
    "defense": ["APT28", "APT29", "Turla", "Lazarus Group", "Kimsuky"],
    "retail": ["FIN6", "FIN7", "FIN8", "Magecart"],
}


def get_group_techniques(group_name):
    """Get all ATT&CK techniques used by a specific threat group."""
    client = attack_client()
    groups = client.get_groups()
    target = None
    for g in groups:
        aliases = [a.lower() for a in g.get("aliases", [])]
        if group_name.lower() in g["name"].lower() or group_name.lower() in aliases:
            target = g
            break
    if not target:
        return None
    techniques = client.get_techniques_used_by_group(target)
    return [{"id": t["external_references"][0]["external_id"],
             "name": t["name"],
             "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])]}
            for t in techniques]


def build_threat_profile(industry):
    """Build a threat profile for an industry based on relevant threat actors."""
    actors = INDUSTRY_THREAT_ACTORS.get(industry.lower(), [])
    if not actors:
        print(f"[!] Industry '{industry}' not found. Available: {list(INDUSTRY_THREAT_ACTORS.keys())}")
        return None

    profile = {"industry": industry, "threat_actors": [], "all_techniques": [],
               "tactic_coverage": Counter()}

    for actor_name in actors:
        techniques = get_group_techniques(actor_name)
        if techniques:
            profile["threat_actors"].append({
                "name": actor_name,
                "technique_count": len(techniques),
                "techniques": techniques,
            })
            for t in techniques:
                profile["all_techniques"].append(t["id"])
                for tac in t["tactics"]:
                    profile["tactic_coverage"][tac] += 1

    profile["unique_techniques"] = list(set(profile["all_techniques"]))
    profile["tactic_coverage"] = dict(profile["tactic_coverage"])
    return profile


def assess_detection_coverage(profile, existing_detections=None):
    """Assess detection coverage gaps against threat profile."""
    if existing_detections is None:
        existing_detections = []
    unique_techniques = set(profile.get("unique_techniques", []))
    covered = set(existing_detections)
    gaps = unique_techniques - covered
    coverage_pct = round(len(covered.intersection(unique_techniques)) /
                         max(len(unique_techniques), 1) * 100, 1)
    return {
        "total_threat_techniques": len(unique_techniques),
        "detected": len(covered.intersection(unique_techniques)),
        "gaps": sorted(gaps),
        "coverage_pct": coverage_pct,
        "priority_gaps": sorted(gaps)[:10],
    }


def generate_navigator_layer(profile, layer_name="Threat Model"):
    """Generate ATT&CK Navigator layer JSON for visualization."""
    technique_counts = Counter(profile.get("all_techniques", []))
    techniques = []
    for tech_id, count in technique_counts.items():
        color_map = {1: "#fcf3cf", 2: "#f9e79f", 3: "#f4d03f"}
        techniques.append({
            "techniqueID": tech_id,
            "score": count,
            "color": color_map.get(min(count, 3), "#f4d03f"),
            "comment": f"Used by {count} threat actor(s)",
            "enabled": True,
        })
    layer = {
        "name": layer_name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Threat model for {profile.get('industry', 'unknown')} industry",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#f4d03f", "#e74c3c"], "minValue": 0, "maxValue": 3},
        "legendItems": [
            {"label": "1 actor", "color": "#fcf3cf"},
            {"label": "2 actors", "color": "#f9e79f"},
            {"label": "3+ actors", "color": "#f4d03f"},
        ],
    }
    return layer


def prioritize_defenses(profile):
    """Prioritize defensive investments based on threat model."""
    technique_counts = Counter(profile.get("all_techniques", []))
    top_techniques = technique_counts.most_common(15)

    client = attack_client()
    all_techniques = {t["external_references"][0]["external_id"]: t
                      for t in client.get_techniques()
                      if t.get("external_references")}

    priorities = []
    for tech_id, count in top_techniques:
        tech_data = all_techniques.get(tech_id, {})
        priorities.append({
            "technique": tech_id,
            "name": tech_data.get("name", "Unknown"),
            "actor_count": count,
            "tactics": [p["phase_name"] for p in tech_data.get("kill_chain_phases", [])],
            "priority": "CRITICAL" if count >= 3 else "HIGH" if count >= 2 else "MEDIUM",
        })
    return priorities


def run_threat_model(industry, existing_detections=None):
    """Run full threat modeling exercise for an industry."""
    print(f"\n{'='*60}")
    print(f"  MITRE ATT&CK THREAT MODEL")
    print(f"  Industry: {industry}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    profile = build_threat_profile(industry)
    if not profile:
        return None

    print(f"--- THREAT ACTORS ({len(profile['threat_actors'])}) ---")
    for actor in profile["threat_actors"]:
        print(f"  {actor['name']}: {actor['technique_count']} techniques")

    print(f"\n--- TECHNIQUE SUMMARY ---")
    print(f"  Total technique usage: {len(profile['all_techniques'])}")
    print(f"  Unique techniques:     {len(profile['unique_techniques'])}")

    print(f"\n--- TACTIC DISTRIBUTION ---")
    for tac, count in sorted(profile["tactic_coverage"].items(), key=lambda x: -x[1]):
        bar = "#" * min(count, 30)
        print(f"  {tac:<30} {bar} ({count})")

    coverage = assess_detection_coverage(profile, existing_detections or [])
    print(f"\n--- DETECTION COVERAGE ---")
    print(f"  Coverage: {coverage['coverage_pct']}%")
    print(f"  Gaps: {len(coverage['gaps'])} techniques undetected")
    if coverage["priority_gaps"]:
        print(f"  Priority gaps: {', '.join(coverage['priority_gaps'][:5])}")

    priorities = prioritize_defenses(profile)
    print(f"\n--- DEFENSE PRIORITIES ---")
    for p in priorities[:10]:
        print(f"  [{p['priority']}] {p['technique']} {p['name']} (used by {p['actor_count']} actors)")

    print(f"\n{'='*60}\n")
    return {"profile": profile, "coverage": coverage, "priorities": priorities}


def main():
    parser = argparse.ArgumentParser(description="Threat Modeling with MITRE ATT&CK Agent")
    parser.add_argument("--industry", required=True,
                        choices=list(INDUSTRY_THREAT_ACTORS.keys()),
                        help="Industry for threat profile")
    parser.add_argument("--detections", nargs="*", help="List of detected technique IDs")
    parser.add_argument("--navigator", help="Export ATT&CK Navigator layer to JSON file")
    parser.add_argument("--output", help="Save full report to JSON")
    args = parser.parse_args()

    result = run_threat_model(args.industry, args.detections)
    if result and args.navigator:
        layer = generate_navigator_layer(result["profile"], f"{args.industry} Threat Model")
        with open(args.navigator, "w") as f:
            json.dump(layer, f, indent=2)
        print(f"[+] Navigator layer saved to {args.navigator}")
    if result and args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
