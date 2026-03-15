#!/usr/bin/env python3
"""Threat actor profiling agent using MITRE ATT&CK STIX data and STIX2 library."""

import json
import sys
import os
from datetime import datetime

try:
    from stix2 import MemoryStore, Filter
    import requests
except ImportError:
    print("Install: pip install stix2 requests")
    sys.exit(1)

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def load_attack_data(cache_path="/tmp/enterprise-attack.json"):
    """Load MITRE ATT&CK STIX data from cache or download."""
    if os.path.exists(cache_path):
        with open(cache_path, "r") as f:
            data = json.load(f)
    else:
        resp = requests.get(ATTACK_STIX_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        with open(cache_path, "w") as f:
            json.dump(data, f)
    return MemoryStore(stix_data=data["objects"])


def list_threat_groups(src):
    """List all threat actor groups in ATT&CK."""
    groups = src.query([Filter("type", "=", "intrusion-set")])
    result = []
    for g in groups:
        aliases = getattr(g, "aliases", [])
        result.append({
            "id": g.id,
            "name": g.name,
            "aliases": aliases if aliases else [],
            "description": (g.description[:200] + "...") if hasattr(g, "description") and g.description else "",
            "created": str(g.created),
            "modified": str(g.modified),
        })
    return sorted(result, key=lambda x: x["name"])


def get_group_profile(src, group_name):
    """Build a comprehensive profile for a specific threat actor group."""
    groups = src.query([
        Filter("type", "=", "intrusion-set"),
        Filter("name", "=", group_name),
    ])
    if not groups:
        groups = src.query([Filter("type", "=", "intrusion-set")])
        groups = [g for g in groups if group_name.lower() in g.name.lower()
                  or any(group_name.lower() in a.lower() for a in getattr(g, "aliases", []))]
    if not groups:
        return {"error": f"Group '{group_name}' not found"}
    group = groups[0]
    profile = {
        "name": group.name,
        "id": group.id,
        "aliases": getattr(group, "aliases", []),
        "description": getattr(group, "description", ""),
        "created": str(group.created),
        "modified": str(group.modified),
        "external_references": [],
    }
    for ref in getattr(group, "external_references", []):
        if hasattr(ref, "source_name"):
            profile["external_references"].append({
                "source": ref.source_name,
                "url": getattr(ref, "url", ""),
                "external_id": getattr(ref, "external_id", ""),
            })
    relationships = src.query([
        Filter("type", "=", "relationship"),
        Filter("source_ref", "=", group.id),
    ])
    profile["techniques"] = []
    profile["software"] = []
    for rel in relationships:
        target = src.get(rel.target_ref)
        if target:
            if target.type == "attack-pattern":
                technique = {
                    "name": target.name,
                    "technique_id": "",
                    "description": rel.description[:200] if hasattr(rel, "description") and rel.description else "",
                }
                for ref in getattr(target, "external_references", []):
                    if hasattr(ref, "external_id") and ref.external_id.startswith("T"):
                        technique["technique_id"] = ref.external_id
                profile["techniques"].append(technique)
            elif target.type in ("malware", "tool"):
                profile["software"].append({
                    "name": target.name,
                    "type": target.type,
                    "description": (target.description[:200] + "...") if hasattr(target, "description") and target.description else "",
                })
    return profile


def get_group_techniques_by_tactic(src, group_name):
    """Map a group's techniques organized by ATT&CK tactic."""
    profile = get_group_profile(src, group_name)
    if "error" in profile:
        return profile
    tactic_map = {}
    techniques = src.query([Filter("type", "=", "attack-pattern")])
    tech_lookup = {}
    for t in techniques:
        for ref in getattr(t, "external_references", []):
            if hasattr(ref, "external_id") and ref.external_id.startswith("T"):
                tech_lookup[t.name] = {
                    "id": ref.external_id,
                    "tactics": [p["phase_name"] for p in getattr(t, "kill_chain_phases", [])],
                }
    for tech in profile["techniques"]:
        info = tech_lookup.get(tech["name"], {})
        for tactic in info.get("tactics", ["unknown"]):
            tactic_map.setdefault(tactic, []).append({
                "technique": tech["name"],
                "id": info.get("id", tech.get("technique_id", "")),
            })
    return {"group": group_name, "tactics": tactic_map}


def compare_groups(src, group_names):
    """Compare techniques and tools across multiple threat actor groups."""
    profiles = {}
    for name in group_names:
        p = get_group_profile(src, name)
        if "error" not in p:
            profiles[name] = p
    all_techniques = {}
    for name, profile in profiles.items():
        for tech in profile["techniques"]:
            tech_name = tech["name"]
            all_techniques.setdefault(tech_name, set()).add(name)
    shared = {t: list(g) for t, g in all_techniques.items() if len(g) > 1}
    return {
        "groups": list(profiles.keys()),
        "shared_techniques": shared,
        "technique_counts": {n: len(p["techniques"]) for n, p in profiles.items()},
        "software_counts": {n: len(p["software"]) for n, p in profiles.items()},
    }


def print_profile(profile):
    print(f"Threat Actor Profile: {profile['name']}")
    print("=" * 50)
    if profile.get("aliases"):
        print(f"Aliases: {', '.join(profile['aliases'])}")
    print(f"\nDescription:\n{profile.get('description', '')[:500]}")
    print(f"\nTechniques ({len(profile.get('techniques', []))}):")
    for t in profile.get("techniques", [])[:20]:
        print(f"  [{t.get('technique_id', 'N/A'):8s}] {t['name']}")
    print(f"\nSoftware ({len(profile.get('software', []))}):")
    for s in profile.get("software", []):
        print(f"  [{s['type']:7s}] {s['name']}")
    print(f"\nReferences:")
    for r in profile.get("external_references", [])[:5]:
        print(f"  {r['source']}: {r.get('url', r.get('external_id', ''))}")


if __name__ == "__main__":
    group_name = sys.argv[1] if len(sys.argv) > 1 else "APT29"
    print("Loading MITRE ATT&CK data...")
    src = load_attack_data()
    profile = get_group_profile(src, group_name)
    if "error" in profile:
        print(profile["error"])
        print("\nAvailable groups:")
        for g in list_threat_groups(src)[:20]:
            print(f"  {g['name']}: {', '.join(g['aliases'][:3])}")
    else:
        print_profile(profile)
