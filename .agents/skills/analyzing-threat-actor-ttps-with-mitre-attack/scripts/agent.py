#!/usr/bin/env python3
"""Threat actor TTP analysis agent using MITRE ATT&CK framework.

Maps threat actor behaviors to ATT&CK techniques, performs coverage analysis,
and generates detection gap reports.
"""

import os
import sys
import json
from collections import Counter, defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def load_attack_bundle(filepath=None):
    if filepath and os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    if HAS_REQUESTS:
        resp = requests.get(ATTACK_ENTERPRISE_URL, timeout=60)
        resp.raise_for_status()
        return resp.json()
    return None


def get_techniques(bundle):
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
            ext_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
            if ext_id:
                tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
                techniques[obj["id"]] = {
                    "id": ext_id, "name": obj.get("name", ""),
                    "tactics": tactics,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "detection": obj.get("x_mitre_detection", "")[:200],
                }
    return techniques


def get_groups(bundle):
    groups = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "intrusion-set":
            ext_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
            groups[obj["id"]] = {
                "id": ext_id, "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": obj.get("description", "")[:300],
            }
    return groups


def map_group_techniques(bundle, group_id, techniques):
    ttps = []
    for obj in bundle.get("objects", []):
        if (obj.get("type") == "relationship" and
                obj.get("relationship_type") == "uses" and
                obj.get("source_ref") == group_id):
            target = obj.get("target_ref", "")
            if target in techniques:
                ttps.append(techniques[target])
    return ttps


def tactic_coverage(ttps):
    tactic_map = defaultdict(list)
    for t in ttps:
        for tactic in t["tactics"]:
            tactic_map[tactic].append(t["id"])
    return {k: {"count": len(v), "techniques": v} for k, v in tactic_map.items()}


def detection_gaps(ttps, existing_detections):
    covered = set(existing_detections)
    gaps = [t for t in ttps if t["id"] not in covered]
    coverage = 1 - (len(gaps) / len(ttps)) if ttps else 0
    return gaps, round(coverage * 100, 1)


def find_group(groups, query):
    query_lower = query.lower()
    for gid, g in groups.items():
        if (g["name"].lower() == query_lower or
                g["id"].lower() == query_lower or
                query_lower in [a.lower() for a in g["aliases"]]):
            return gid, g
    return None, None


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Actor TTP Analysis Agent (MITRE ATT&CK)")
    print("TTP mapping, tactic coverage, detection gap analysis")
    print("=" * 60)

    group_query = sys.argv[1] if len(sys.argv) > 1 else None
    bundle_path = sys.argv[2] if len(sys.argv) > 2 else None

    bundle = load_attack_bundle(bundle_path)
    if not bundle:
        print("[!] Cannot load ATT&CK data")
        print("[DEMO] Usage: python agent.py APT29 [enterprise-attack.json]")
        sys.exit(1)

    techniques = get_techniques(bundle)
    groups = get_groups(bundle)
    print(f"[*] Loaded {len(techniques)} techniques, {len(groups)} groups")

    if not group_query:
        print("
--- Available Groups (sample) ---")
        for gid, g in list(groups.items())[:15]:
            print(f"  {g['id']:8s} {g['name']}")
        sys.exit(0)

    gid, ginfo = find_group(groups, group_query)
    if not ginfo:
        print(f"[!] Group not found: {group_query}")
        sys.exit(1)

    print(f"
[*] Group: {ginfo['name']} ({ginfo['id']})")
    print(f"    Aliases: {', '.join(ginfo['aliases'][:5])}")

    ttps = map_group_techniques(bundle, gid, techniques)
    print(f"    Techniques: {len(ttps)}")

    coverage = tactic_coverage(ttps)
    print("
--- Tactic Coverage ---")
    for tactic, info in sorted(coverage.items(), key=lambda x: -x[1]["count"]):
        bar = "#" * info["count"]
        print(f"  {tactic:35s} {info['count']:3d} {bar}")

    sample_detections = [t["id"] for t in ttps[:len(ttps)//2]]
    gaps, pct = detection_gaps(ttps, sample_detections)
    print(f"
--- Detection Gaps (demo: {pct}% coverage) ---")
    for g in gaps[:10]:
        print(f"  [GAP] {g['id']:12s} {g['name']}")
