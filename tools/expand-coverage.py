#!/usr/bin/env python3
"""Expand attack navigator layer with techniques referenced by skills but missing from the graph.

This script:
1. Parses all SKILL.md files for `mitre_attack` frontmatter
2. Compares against existing mappings/jsonld/attack-navigator-layer.json
3. Adds any missing technique IDs to the navigator layer (with score=0)
4. Updates the graph so the attack-scenario-generator can discover them
"""
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
NAV_LAYER_PATH = REPO_ROOT / "mappings" / "attack-navigator-layer.json"
TACTIC_MAPPING_PATH = REPO_ROOT / "mappings" / "jsonld" / "tactic-mapping.json"
TECHNIQUES_JSONLD = REPO_ROOT / "mappings" / "jsonld" / "techniques.jsonld"


def parse_frontmatter_techniques(text):
    """Extract technique IDs from a SKILL.md frontmatter block."""
    if not text.startswith("---"):
        return []
    end = text.find("\n---", 3)
    if end == -1:
        return []
    block = text[3:end]
    techs = []

    # Inline array: mitre_attack: [T1006, T1005]
    m = re.search(r'^mitre_attack:\s*\[(.+?)\]', block, re.MULTILINE | re.DOTALL)
    if m:
        techs = re.findall(r'T\d{4}(?:\.\d{3})?', m.group(1))

    # YAML list: mitre_attack:\n- T1006\n- T1005 (no indent)
    if not techs:
        m = re.search(r'^mitre_attack:\s*\n((?:- .+\n?)+)', block, re.MULTILINE)
        if m:
            techs = re.findall(r'-\s*(T\d{4}(?:\.\d{3})?)', m.group(1))

    return techs


def find_tactic(mapping, tech_id):
    """Resolve tactic ID for a given ATT&CK technique using the mapping file."""
    try:
        data = json.loads(TACTIC_MAPPING_PATH.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if tech_id in data.get("techniques", []):
        pass
    for tid, info in data.items():
        if tech_id in info.get("techniques", []):
            return tid
    if tech_id.startswith("T"):
        prefix = tech_id.upper()
        for tid, info in data.items():
            if any(t.replace("T", "").startswith(prefix[1:4]) for t in info.get("techniques", [])):
                return tid
    return ""


def main():
    # Load navigator layer
    nav = json.loads(NAV_LAYER_PATH.read_text(encoding="utf-8"))
    existing_ids = {t["techniqueID"] for t in nav.get("techniques", [])}

    # Load tactic mapping for name lookup
    mapping = json.loads(TACTIC_MAPPING_PATH.read_text(encoding="utf-8"))
    tactic_names = {tid: info.get("name", tid) for tid, info in mapping.items()}

    # Also load techniques.jsonld for names
    techniques_json = {}
    if TECHNIQUES_JSONLD.exists():
        for t in json.loads(TECHNIQUES_JSONLD.read_text(encoding="utf-8")):
            techniques_json[t["@id"].split(":", 1)[1]] = t.get("name", t["framework_id"])

    # Scan all skills
    new_techs = []
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        text = skill_md.read_text(encoding="utf-8")
        techs = parse_frontmatter_techniques(text)
        for tech_id in techs:
            if tech_id not in existing_ids:
                # Find tactic
                tactic_id = find_tactic(mapping, tech_id)
                tactic_name = tactic_names.get(tactic_id, "")

                # Find name from jsonld or build from ID
                name = techniques_json.get(tech_id, tech_id)

                new_techs.append({
                    "techniqueID": tech_id,
                    "score": 0,
                    "comment": f"{name} - Added from skill frontmatter",
                    "enabled": True,
                    "tactic": tactic_name,
                    "metadata": [
                        {"name": "skill_count", "value": "0"},
                        {"name": "skills", "value": skill_dir.name},
                        {"name": "tactic", "value": tactic_id},
                    ],
                })
                existing_ids.add(tech_id)

    # Append new techniques
    nav["techniques"].extend(new_techs)
    nav["metadata"] = nav.get("metadata", [])
    if isinstance(nav["metadata"], list):
        nav["metadata"].append({"name": "last_expanded", "value": "2026-06-07"})
    else:
        nav["metadata"]["last_expanded"] = "2026-06-07"

    # Write expanded layer
    NAV_LAYER_PATH.write_text(json.dumps(nav, indent=2), encoding="utf-8")
    print(f"Added {len(new_techs)} missing techniques to navigator layer")
    print(f"Total techniques in layer: {len(nav['techniques'])}")

    # Show tactic distribution of new additions
    from collections import Counter
    tac_count = Counter()
    for t in new_techs:
        tac_count[t.get("tactic", "Unknown")] += 1
    print("New technique tactic distribution:")
    for t, c in sorted(tac_count.items(), key=lambda x: x[1], reverse=True):
        print(f"  {t}: {c}")


if __name__ == "__main__":
    main()
