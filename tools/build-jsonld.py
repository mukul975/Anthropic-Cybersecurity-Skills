#!/usr/bin/env python3
"""Build JSON-LD knowledge graph from skill frontmatter and framework mappings.

Usage:
    python tools/build-jsonld.py [--output-dir mappings/jsonld]
"""
import json
import os
import re
import sys
from pathlib import Path

# Configuration
REPO_ROOT = Path(__file__).parent.parent
INDEX_FILE = REPO_ROOT / "index.json"
SKILLS_DIR = REPO_ROOT / "skills"
ATTACK_NAVIGATOR = REPO_ROOT / "mappings" / "attack-navigator-layer.json"
OUTPUT_DIR = REPO_ROOT / "mappings" / "jsonld"
TACTIC_MAPPING_PATH = REPO_ROOT / "mappings" / "jsonld" / "tactic-mapping.json"

# JSON-LD context URL
CONTEXT_URL = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills/knowledge-graph/context.jsonld"


def parse_frontmatter(text):
    """Extract YAML frontmatter as a dict (stdlib-only parser)."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    block = text[3:end].strip()
    data = {}
    current_key = None
    list_values = []
    in_folded = False
    folded_lines = []

    for line in block.split("\n"):
        stripped = line.strip()

        # Flush folded scalar on next top-level key
        if in_folded and stripped and not line.startswith((" ", "\t")):
            if current_key and folded_lines:
                data[current_key] = " ".join(folded_lines)
            in_folded = False
            folded_lines = []
            current_key = None

        if in_folded:
            if stripped:
                folded_lines.append(stripped)
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # List items
        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list(list_values)
            continue

        # Inline list
        m = re.match(r"^(\w[\w_-]*):\s*\[(.+)\]\s*$", stripped)
        if m:
            current_key = m.group(1)
            items = [i.strip().strip('"').strip("'") for i in m.group(2).split(",")]
            data[current_key] = items
            list_values = list(items)
            continue

        # Folded scalar start
        m = re.match(r"^(\w[\w_-]*):\s*>[-|]?\s*$", stripped)
        if m:
            current_key = m.group(1)
            list_values = []
            in_folded = True
            folded_lines = []
            continue

        # Scalar key
        m = re.match(r"^(\w[\w_-]*):\s*(.*)$", stripped)
        if m:
            current_key = m.group(1)
            val = m.group(2).strip().strip('"').strip("'")
            list_values = []
            if val:
                data[current_key] = val

    if in_folded and current_key and folded_lines:
        data[current_key] = " ".join(folded_lines)

    return data


def load_index_json():
    """Load the bundled skill index."""
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_attack_navigator():
    """Load ATT&CK Navigator layer for technique-skill relationships."""
    with open(ATTACK_NAVIGATOR, "r", encoding="utf-8") as f:
        return json.load(f)


def build_skills_jsonld(index_data):
    """Build list of skill entities in JSON-LD format."""
    skills = []
    for skill_entry in index_data.get("skills", []):
        skill_path = REPO_ROOT / skill_entry["path"]
        skill_md = skill_path / "SKILL.md"

        if not skill_md.exists():
            continue

        with open(skill_md, "r", encoding="utf-8") as f:
            frontmatter = parse_frontmatter(f.read())

        if not frontmatter:
            continue

        skill_id = f"skill:{skill_entry['name']}"
        entity = {
            "@context": CONTEXT_URL,
            "@id": skill_id,
            "@type": "Skill",
            "name": skill_entry["name"],
            "description": skill_entry["description"],
            "domain": skill_entry.get("domain", "cybersecurity"),
            "subdomain": frontmatter.get("subdomain", ""),
            "tags": frontmatter.get("tags", []),
            "version": frontmatter.get("version", "1.0.0"),
            "author": frontmatter.get("author", ""),
            "license": frontmatter.get("license", "Apache-2.0"),
        }

        # Add framework relationships
        relationships = []
        for fw_key in ["mitre_attack", "nist_csf", "atlas_techniques"]:
            fw_values = frontmatter.get(fw_key, [])
            for val in fw_values:
                if fw_key == "mitre_attack":
                    relationships.append(f"technique:{val}")
                elif fw_key == "nist_csf":
                    relationships.append(f"category:{val}")
                elif fw_key == "atlas_techniques":
                    relationships.append(f"technique:{val}")
            if fw_values:
                entity[fw_key] = fw_values

        if relationships:
            entity["references"] = relationships

        skills.append(entity)

    return skills


def build_techniques_jsonld(index_data, attack_data):
    """Build list of technique entities in JSON-LD format."""
    techniques = {}

    tactic_mapping = {}
    try:
        for tactic_id, data in json.loads(Path(TACTIC_MAPPING_PATH).read_text(encoding="utf-8")).items():
            for tech_id in data.get("techniques", []):
                tactic_mapping[tech_id] = tactic_id
    except Exception:
        pass

    def find_tactic_for_technique(tech_id):
        if tech_id in tactic_mapping:
            return tactic_mapping[tech_id]
        if tech_id.startswith("T"):
            prefix = tech_id.upper()
            for tactic_id, data in json.loads(Path(TACTIC_MAPPING_PATH).read_text(encoding="utf-8")).items():
                techniques_list = data.get("techniques", [])
                if techniques_list and any(t.replace("T", "").startswith(prefix[1:4]) for t in techniques_list):
                    return tactic_id
        return ""

    # Process ATT&CK Navigator layer
    for tech in attack_data.get("techniques", []):
        tech_id = tech["techniqueID"]
        technique_key = f"technique:{tech_id}"

        # Extract skills from metadata
        skill_list = []
        for meta in tech.get("metadata", []):
            if meta.get("name") == "skills":
                skills_value = meta.get("value", "")
                for match in skills_value.split(", "):
                    match = match.strip()
                    if match and "(+" not in match:
                        skill_list.append(f"skill:{match}")

        techniques[technique_key] = {
            "@context": CONTEXT_URL,
            "@id": technique_key,
            "@type": "Technique",
            "name": tech.get("comment", "").split(" - ")[0] if " - " in tech.get("comment", "") else tech.get("techniqueID"),
            "framework": "mitre-attack",
            "framework_id": tech_id,
            "tactic": find_tactic_for_technique(tech_id),
            "skills": skill_list,
            "score": tech.get("score", 0),
        }

    return list(techniques.values())


def build_owasp_entities():
    """Parse OWASP references and create entities from mappings/owasp/README.md."""
    owasp_path = REPO_ROOT / "mappings" / "owasp" / "README.md"
    if not owasp_path.exists():
        return []
    
    with open(owasp_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    owasp_entities = []
    # Parse OWASP Top 10 entries from README - match "### A##:2025 -- Category Name"
    pattern = r"### (A\d{2}):2025 -- (.+?)\n\n(.+?)(?=\n\n|\n###)"
    for match in re.finditer(pattern, content, re.DOTALL):
        category_id = match.group(1)  # e.g., "A01"
        category_name = match.group(2).strip()  # e.g., "Broken Access Control"
        description = match.group(3).strip()
        
        owasp_entities.append({
            "@context": CONTEXT_URL,
            "@id": f"category:OWASP-{category_id}",
            "@type": "Category",
            "name": f"OWASP {category_id} - {category_name}",
            "description": description[:200] + "..." if len(description) > 200 else description,
            "framework": "owasp",
            "framework_id": category_id,
        })
    
    return owasp_entities


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Load data sources
    index_data = load_index_json()
    attack_data = load_attack_navigator()

    # Build JSON-LD entities
    skills = build_skills_jsonld(index_data)
    techniques = build_techniques_jsonld(index_data, attack_data)
    owasp_categories = build_owasp_entities()

    # Write bundled skills.jsonld
    with open(OUTPUT_DIR / "skills.jsonld", "w", encoding="utf-8") as f:
        json.dump(skills, f, indent=2)

    # Write bundled techniques.jsonld
    with open(OUTPUT_DIR / "techniques.jsonld", "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)

    # Write OWASP categories
    if owasp_categories:
        with open(OUTPUT_DIR / "owasp.jsonld", "w", encoding="utf-8") as f:
            json.dump(owasp_categories, f, indent=2)

    print(f"Generated {len(skills)} skill entities")
    print(f"Generated {len(techniques)} technique entities")
    print(f"Generated {len(owasp_categories)} OWASP category entities")
    print(f"Output written to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()