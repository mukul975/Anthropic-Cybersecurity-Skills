#!/usr/bin/env python3
"""Aggregate SKILL.md frontmatter + ATT&CK mappings into docs/data.json.

Run from repo root:
    python3 tools/build-browser-data.py

Produces docs/data.json consumed by the static skill browser at docs/index.html.
"""
import json
import os
import re
import sys
from collections import defaultdict

SKILLS_DIR = "skills"
NAVIGATOR_LAYER = "mappings/attack-navigator-layer.json"
OUTPUT = "docs/data.json"


def parse_frontmatter(text: str) -> dict:
    """Minimal YAML frontmatter parser — same shape as tools/validate-skill.py."""
    if not text.startswith("---"):
        return {}
    end = text.find("---", 3)
    if end == -1:
        return {}
    block = text[3:end].strip()
    data: dict = {}
    current_key = None
    list_values: list = []

    for raw_line in block.split("\n"):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list(list_values)
            continue

        m = re.match(r"^(\w[\w_-]*):\s*\[(.+)\]\s*$", stripped)
        if m:
            current_key = m.group(1)
            items = [i.strip().strip('"').strip("'") for i in m.group(2).split(",")]
            data[current_key] = items
            list_values = list(items)
            continue

        m = re.match(r"^(\w[\w_-]*):\s*(.*)$", stripped)
        if m:
            current_key = m.group(1)
            val = m.group(2).strip().strip('"').strip("'")
            list_values = []
            if val:
                data[current_key] = val
            continue

    return data


def load_attack_mapping() -> dict:
    """Return {skill_name: [technique_ids]} by inverting the Navigator layer."""
    if not os.path.isfile(NAVIGATOR_LAYER):
        return {}
    with open(NAVIGATOR_LAYER, encoding="utf-8") as f:
        layer = json.load(f)

    skill_to_techniques: dict = defaultdict(list)
    for tech in layer.get("techniques", []):
        tid = tech.get("techniqueID")
        if not tid:
            continue
        # The Navigator layer stores skills as a comma-joined string with truncation
        # marker "(+N more)". We parse what's present; full list still derivable
        # from the per-skill SKILL.md frontmatter if we ever add it.
        for meta in tech.get("metadata", []):
            if meta.get("name") == "skills":
                names = re.split(r",\s*", meta.get("value", ""))
                for name in names:
                    cleaned = re.sub(r"\s*\(\+\d+\s+more\)\s*", "", name).strip()
                    if cleaned:
                        skill_to_techniques[cleaned].append(tid)
    return dict(skill_to_techniques)


def extract_first_section(content: str, heading: str) -> str:
    """Pull the body of a markdown section by heading (e.g. 'When to Use')."""
    pattern = rf"^##\s+{re.escape(heading)}\s*\n(.*?)(?=^##\s|\Z)"
    m = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    return m.group(1).strip() if m else ""


def build():
    if not os.path.isdir(SKILLS_DIR):
        print(f"ERROR: '{SKILLS_DIR}/' not found. Run from repo root.", file=sys.stderr)
        sys.exit(1)

    attack_map = load_attack_mapping()
    skills = []

    for name in sorted(os.listdir(SKILLS_DIR)):
        skill_md = os.path.join(SKILLS_DIR, name, "SKILL.md")
        if not os.path.isfile(skill_md):
            continue
        with open(skill_md, encoding="utf-8") as f:
            content = f.read()

        fm = parse_frontmatter(content)
        if not fm:
            continue

        tags = fm.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        skills.append({
            "name": fm.get("name", name),
            "description": fm.get("description", ""),
            "subdomain": fm.get("subdomain", ""),
            "tags": tags,
            "version": fm.get("version", ""),
            "author": fm.get("author", ""),
            "nist_csf": fm.get("nist_csf", []) if isinstance(fm.get("nist_csf"), list) else [],
            "owasp": fm.get("owasp", []) if isinstance(fm.get("owasp"), list) else [],
            "attack": sorted(set(attack_map.get(name, []))),
            "when_to_use": extract_first_section(content, "When to Use"),
            "path": f"skills/{name}/SKILL.md",
        })

    subdomain_counts = defaultdict(int)
    tag_counts = defaultdict(int)
    for s in skills:
        if s["subdomain"]:
            subdomain_counts[s["subdomain"]] += 1
        for t in s["tags"]:
            tag_counts[t] += 1

    output = {
        "total": len(skills),
        "subdomains": dict(sorted(subdomain_counts.items(), key=lambda x: -x[1])),
        "top_tags": dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:50]),
        "skills": skills,
    }

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(output, f, separators=(",", ":"))

    size_kb = os.path.getsize(OUTPUT) / 1024
    print(f"Wrote {OUTPUT}: {len(skills)} skills, {len(subdomain_counts)} subdomains, {size_kb:.1f} KB")


if __name__ == "__main__":
    build()
