#!/usr/bin/env python3
"""APT group analysis agent using MITRE ATT&CK Navigator layers.

Queries ATT&CK data, maps APT techniques to Navigator layers,
performs detection gap analysis, and generates threat-informed reports.
"""

import json
import os
import sys
import hashlib
from collections import Counter

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

NAVIGATOR_LAYER_TEMPLATE = {
    "name": "",
    "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "",
    "filters": {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
    "sorting": 0,
    "layout": {"layout": "side", "aggregateFunction": "average", "showID": False,
                "showName": True, "showAggregateScores": False, "countUnscored": False},
    "hideDisabled": False,
    "techniques": [],
    "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False,
}


def load_attack_data(filepath=None):
    """Load ATT&CK STIX bundle from file or download."""
    if filepath and os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    if HAS_REQUESTS:
        print("[*] Downloading ATT&CK Enterprise data...")
        resp = requests.get(ATTACK_ENTERPRISE_URL, timeout=60)
        resp.raise_for_status()
        return resp.json()
    return None


def extract_groups(bundle):
    """Extract intrusion-set (APT group) objects from STIX bundle."""
    groups = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "intrusion-set":
            name = obj.get("name", "Unknown")
            aliases = obj.get("aliases", [])
            ext_refs = obj.get("external_references", [])
            attack_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id", "")
                    break
            groups[obj["id"]] = {
                "name": name, "id": attack_id, "aliases": aliases,
                "description": obj.get("description", "")[:200],
            }
    return groups


def extract_techniques(bundle):
    """Extract attack-pattern (technique) objects from STIX bundle."""
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            ext_refs = obj.get("external_references", [])
            attack_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id", "")
                    break
            if attack_id:
                tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
                techniques[obj["id"]] = {
                    "id": attack_id, "name": obj.get("name", ""),
                    "tactics": tactics, "platforms": obj.get("x_mitre_platforms", []),
                }
    return techniques


def map_group_techniques(bundle, group_stix_id, techniques):
    """Map techniques used by a specific group via relationship objects."""
    group_techniques = []
    for obj in bundle.get("objects", []):
        if (obj.get("type") == "relationship" and
                obj.get("relationship_type") == "uses" and
                obj.get("source_ref") == group_stix_id and
                obj.get("target_ref", "").startswith("attack-pattern--")):
            tech_id = obj["target_ref"]
            if tech_id in techniques:
                group_techniques.append(techniques[tech_id])
    return group_techniques


def build_navigator_layer(group_name, group_techniques, color="#ff6666", score=100):
    """Build ATT&CK Navigator JSON layer for a group's techniques."""
    layer = json.loads(json.dumps(NAVIGATOR_LAYER_TEMPLATE))
    layer["name"] = f"{group_name} - TTPs"
    layer["description"] = f"ATT&CK techniques attributed to {group_name}"
    for tech in group_techniques:
        entry = {
            "techniqueID": tech["id"],
            "tactic": tech["tactics"][0] if tech["tactics"] else "",
            "color": color,
            "comment": f"Used by {group_name}",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
            "score": score,
        }
        layer["techniques"].append(entry)
    return layer


def detection_gap_analysis(group_techniques, detection_rules):
    """Compare group TTPs against existing detection rules to find gaps."""
    covered = set()
    for rule in detection_rules:
        tech_id = rule.get("technique_id", "")
        if tech_id:
            covered.add(tech_id)
    gaps = []
    for tech in group_techniques:
        if tech["id"] not in covered:
            gaps.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactics": tech["tactics"],
                "status": "NO DETECTION",
            })
    coverage_pct = (len(covered & {t["id"] for t in group_techniques}) /
                    len(group_techniques) * 100) if group_techniques else 0
    return gaps, round(coverage_pct, 1)


def tactic_heatmap(group_techniques):
    """Generate tactic-level heatmap showing technique distribution."""
    tactic_counts = Counter()
    for tech in group_techniques:
        for tactic in tech["tactics"]:
            tactic_counts[tactic] += 1
    return dict(tactic_counts.most_common())


def compare_groups(group_a_techs, group_b_techs):
    """Compare two groups' technique sets for overlap analysis."""
    set_a = {t["id"] for t in group_a_techs}
    set_b = {t["id"] for t in group_b_techs}
    overlap = set_a & set_b
    only_a = set_a - set_b
    only_b = set_b - set_a
    jaccard = len(overlap) / len(set_a | set_b) if (set_a | set_b) else 0
    return {
        "overlap_count": len(overlap), "overlap_ids": sorted(overlap),
        "only_group_a": len(only_a), "only_group_b": len(only_b),
        "jaccard_similarity": round(jaccard, 4),
    }


def save_layer(layer, output_path):
    """Save Navigator layer to JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    print(f"[+] Layer saved: {output_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("APT Group Analysis Agent - MITRE ATT&CK Navigator")
    print("TTP mapping, detection gap analysis, group comparison")
    print("=" * 60)

    group_name = sys.argv[1] if len(sys.argv) > 1 else None
    attack_file = sys.argv[2] if len(sys.argv) > 2 else None

    bundle = load_attack_data(attack_file)
    if not bundle:
        print("\n[!] Cannot load ATT&CK data. Provide STIX bundle path or install requests.")
        print("[DEMO] Usage:")
        print("  python agent.py APT29 enterprise-attack.json")
        print("  python agent.py APT28   # downloads from GitHub")
        sys.exit(1)

    groups = extract_groups(bundle)
    techniques = extract_techniques(bundle)
    print(f"[*] Loaded {len(groups)} groups, {len(techniques)} techniques")

    if not group_name:
        print("\n--- Available APT Groups (sample) ---")
        for gid, g in list(groups.items())[:20]:
            print(f"  {g['id']:8s} {g['name']:30s} aliases={g['aliases'][:3]}")
        sys.exit(0)

    target_group = None
    for gid, g in groups.items():
        if (g["name"].lower() == group_name.lower() or
                g["id"].lower() == group_name.lower() or
                group_name.lower() in [a.lower() for a in g["aliases"]]):
            target_group = (gid, g)
            break

    if not target_group:
        print(f"[!] Group '{group_name}' not found")
        sys.exit(1)

    gid, ginfo = target_group
    print(f"\n[*] Group: {ginfo['name']} ({ginfo['id']})")
    print(f"    Aliases: {', '.join(ginfo['aliases'][:5])}")

    group_techs = map_group_techniques(bundle, gid, techniques)
    print(f"    Techniques: {len(group_techs)}")

    heatmap = tactic_heatmap(group_techs)
    print("\n--- Tactic Heatmap ---")
    for tactic, count in heatmap.items():
        bar = "#" * count
        print(f"  {tactic:35s} {count:3d} {bar}")

    layer = build_navigator_layer(ginfo["name"], group_techs)
    out_file = f"{ginfo['name'].replace(' ', '_')}_layer.json"
    save_layer(layer, out_file)

    sample_rules = [{"technique_id": t["id"]} for t in group_techs[:len(group_techs)//2]]
    gaps, coverage = detection_gap_analysis(group_techs, sample_rules)
    print(f"\n--- Detection Gap Analysis (demo: {coverage}% coverage) ---")
    for gap in gaps[:10]:
        print(f"  [GAP] {gap['technique_id']:12s} {gap['technique_name']}")
