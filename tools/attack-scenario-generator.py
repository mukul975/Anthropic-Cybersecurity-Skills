#!/usr/bin/env python3
"""Attack Scenario Generator - generates realistic attack simulations from LanceDB knowledge graph."""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / ".codegraph" / "knowledge_graph.lance"
TACTIC_MAPPING_PATH = REPO_ROOT / "mappings" / "jsonld" / "tactic-mapping.json"
TEMPLATE_PATH = REPO_ROOT / "tools" / "templates" / "scenario-template.md"
JSONLD_DIR = REPO_ROOT / "mappings" / "jsonld"

OBJECTIVE_MAPPING = {
    "domain-dominance": ["T1069", "T1078", "T1059", "T1552", "T1003", "T1041", "T1070"],
    "data-exfiltration": ["T1041", "T1005", "T1039", "T1020", "T1048", "T1567"],
    "persistence": ["T1053", "T1547", "T1546", "T1574", "T1136", "T1098"],
    "credential-theft": ["T1003", "T1110", "T1552", "T1555", "T1056", "T1606"],
}

TACTIC_SEQUENCE = [
    "TA0043",
    "TA0042",
    "TA0001",
    "TA0002",
    "TA0003",
    "TA0004",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008",
    "TA0009",
    "TA0011",
    "TA0010",
    "TA0012",
]


def init_lancedb():
    import lancedb

    if not DB_PATH.exists():
        raise RuntimeError("Knowledge graph not found. Run tools/build-lancedb.py first.")
    return lancedb.connect(str(DB_PATH))


def get_node(db, node_id):
    if not node_id:
        return None
    if not node_id.startswith(("skill:", "technique:", "category:")) and node_id.startswith(
        "T"
    ):
        node_id = f"technique:{node_id}"
    s = db.open_table("nodes").search().where(f"id = '{node_id}'").to_list()
    return s[0] if s else None


def get_tactic_for_technique(tech_id, db=None):
    node = None
    if db and tech_id:
        node = get_node(db, tech_id)
    if node and node.get("tactic"):
        return node["tactic"]
    try:
        mapping = json.loads(Path(TACTIC_MAPPING_PATH).read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Cannot load tactic mapping: {exc}")
    for tactic_id, data in mapping.items():
        if tech_id in data.get("techniques", []):
            return tactic_id
    if tech_id.startswith("T"):
        prefix = tech_id.upper()
        for tactic_id in TACTIC_SEQUENCE:
            data = mapping.get(tactic_id, {})
            if data.get("techniques", []) and any(
                t.replace("T", "").startswith(prefix[1:4])
                for t in data.get("techniques", [])
            ):
                return tactic_id
    return ""


def load_tactics():
    try:
        return json.loads(Path(TACTIC_MAPPING_PATH).read_text(encoding="utf-8"))
    except Exception:
        return {}


def select_techniques_for_tactic(tactic_id, tactics_data, db, depth=1):
    if tactic_id not in tactics_data:
        return []
    tech_ids = tactics_data[tactic_id].get("techniques", [])
    scored = []
    rels_table = db.open_table("relationships")
    for tech_id in tech_ids:
        node = get_node(db, tech_id)
        if not node:
            continue
        score = node.get("score", 0)
        covered_rels = rels_table.search().where(
            f"source = 'technique:{tech_id}'"
        ).to_list()
        skill_count = sum(
            1 for r in covered_rels if r.get("predicate") == "coveredBy"
        )
        scored.append(
            {
                "technique_id": tech_id,
                "score": score,
                "skill_count": skill_count,
                "node": node,
            }
        )
    scored.sort(key=lambda x: (x["skill_count"], x["score"]), reverse=True)
    return scored[: max(1, depth)]


def find_skills_for_technique(tech_id, db, top_k=3):
    tech_full = (
        f"technique:{tech_id}"
        if not tech_id.startswith("technique:")
        else tech_id
    )
    rels = (
        db.open_table("relationships")
        .search()
        .where(f"source = '{tech_full}' AND predicate = 'coveredBy'")
        .to_list()
    )
    scored = []
    for rel in rels:
        skill_id = rel.get("target", "")
        if not skill_id.startswith("skill:"):
            continue
        skill_node = get_node(db, skill_id)
        if not skill_node:
            continue
        scored.append(
            {
                "id": skill_id,
                "name": skill_node.get("name", skill_id),
                "description": skill_node.get("description", ""),
                "predicate": "coveredBy",
                "score": rel.get("weight", 0),
            }
        )
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_k]


def describe_technique(tech_node):
    return tech_node.get("description", "") or tech_node.get("name", "")


def build_markdown(scenario, template_path=None):
    template_path = template_path or TEMPLATE_PATH
    if not template_path.exists():
        return fallback_markdown(scenario)
    text = template_path.read_text(encoding="utf-8")
    try:
        from jinja2 import Template

        return Template(text).render(**scenario)
    except Exception:
        return fallback_markdown(scenario)


def fallback_markdown(scenario):
    out = []
    out.append(f"# Attack Scenario: {scenario.get('scenario_name', 'Unknown')}\n")
    out.append(f"**Generated**: {scenario.get('timestamp', '')}")
    out.append(
        f"**Entry Technique**: {scenario.get('entry_technique_id', '')}"
    )
    out.append(f"**Depth**: {scenario.get('depth', '')}")
    out.append("")
    out.append("## Attack Chain\n")
    for step in scenario.get("steps", []):
        out.append(f"### Step {step.get('number', '')}")
        out.append(
            f"**Technique**: {step.get('technique_id', '')} - {step.get('technique_name', '')}"
        )
        out.append(
            f"**Tactic**: {step.get('tactic_id', '')} - {step.get('tactic_name', '')}"
        )
        out.append(f"**Score**: {step.get('score', '')}/100")
        out.append("")
        out.append(f"_{step.get('description', '')}_")
        out.append("")
        if step.get("skills"):
            out.append("#### Mapped Skills")
            for s in step["skills"]:
                out.append(
                    f"- {s.get('name', s.get('id', ''))} ({s.get('predicate', '')})"
                )
            out.append("")
    return "\n".join(out)


def generate_scenario(entry_technique, depth, objective=None, db=None):
    db = db or init_lancedb()
    tactics_data = load_tactics()
    entry_tactic = get_tactic_for_technique(entry_technique)
    if not entry_tactic:
        print(
            f"Warning: Unknown tactic for technique {entry_technique}",
            file=sys.stderr,
        )
        entry_tactic = ""
    technique_idx = (
        TACTIC_SEQUENCE.index(entry_tactic)
        if entry_tactic in TACTIC_SEQUENCE
        else 0
    )
    steps = []
    current_tech = entry_technique
    seen_techniques = set()
    max_steps = max(1, min(depth, len(TACTIC_SEQUENCE) - max(technique_idx, 0)))
    for i in range(max_steps):
        tactic_idx = max(technique_idx + i, 0)
        tactic_id = (
            TACTIC_SEQUENCE[tactic_idx]
            if tactic_idx < len(TACTIC_SEQUENCE)
            else TACTIC_SEQUENCE[-1]
        )
        node = get_node(db, current_tech)
        if not node:
            candidates = select_techniques_for_tactic(
                tactic_id, tactics_data, db, depth=1
            )
            if not candidates:
                alt_idx = min(tactic_idx + 1, len(TACTIC_SEQUENCE) - 1)
                tactic_id = TACTIC_SEQUENCE[alt_idx]
                candidates = select_techniques_for_tactic(
                    tactic_id, tactics_data, db, depth=1
                )
            if not candidates:
                continue
            current_tech = candidates[0]["technique_id"]
            node = get_node(db, current_tech)
        name = node.get("name", current_tech)
        description = describe_technique(node)
        skills = find_skills_for_technique(current_tech, db, top_k=3)
        if current_tech in seen_techniques and len(steps) > 1:
            candidates = select_techniques_for_tactic(
                tactic_id, tactics_data, db, depth=3
            )
            for ct in candidates:
                if ct["technique_id"] not in seen_techniques:
                    current_tech = ct["technique_id"]
                    node = get_node(db, current_tech)
                    name = node.get("name", current_tech)
                    description = describe_technique(node)
                    skills = find_skills_for_technique(current_tech, db, top_k=3)
                    break
        seen_techniques.add(current_tech)
        steps.append(
            {
                "number": len(steps) + 1,
                "technique_id": current_tech,
                "technique_name": name,
                "tactic_id": tactic_id,
                "tactic_name": tactics_data.get(tactic_id, {}).get(
                    "name", tactic_id
                ),
                "description": description,
                "score": node.get("score", 0) if node else 0,
                "skills": skills,
                "path_length": len(steps) + 1,
            }
        )
        if i + 1 < max_steps:
            next_idx = min(tactic_idx + 1, len(TACTIC_SEQUENCE) - 1)
            next_tactic = TACTIC_SEQUENCE[next_idx]
            next_candidates = select_techniques_for_tactic(
                next_tactic, tactics_data, db, depth=3
            )
            current_tech = (
                next_candidates[0]["technique_id"]
                if next_candidates
                else current_tech
            )
    skill_coverage = defaultdict(int)
    for step in steps:
        for skill in step.get("skills", []):
            skill_coverage[skill.get("id", "")] += 1
    objective_label = objective or "custom"
    scenario_name = (
        f"{entry_technique} -> {' -> '.join(s['technique_id'] for s in steps)}"
    )
    return {
        "scenario_name": scenario_name,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "entry_technique_id": entry_technique,
        "entry_technique_name": (
            get_node(db, entry_technique).get("name", entry_technique)
            if get_node(db, entry_technique)
            else ""
        ),
        "entry_tactic_id": entry_tactic,
        "entry_tactic_name": tactics_data.get(entry_tactic, {}).get(
            "name", entry_tactic
        )
        if entry_tactic
        else "",
        "depth": depth,
        "objective": objective_label,
        "total_steps": len(steps),
        "unique_techniques": len({s["technique_id"] for s in steps}),
        "total_skills": sum(len(s["skills"]) for s in steps),
        "steps": steps,
        "skill_coverage": dict(skill_coverage),
        "skill_coverage_table": "\n".join(
            f"| {k} | {v} technique(s) |"
            for k, v in sorted(skill_coverage.items())
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate MITRE ATT&CK attack scenarios from knowledge graph"
    )
    parser.add_argument(
        "--entry", "-e", required=True, help="Entry technique ID (e.g., T1566.001)"
    )
    parser.add_argument(
        "--depth", "-d", type=int, default=5, help="Scenario depth (default: 5)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json", "yaml"],
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--objective", "-o", help="Scenario objective preset (e.g., domain-dominance)"
    )
    parser.add_argument(
        "--output", help="Write to file instead of stdout"
    )
    parser.add_argument("--template", help="Custom template path")
    args = parser.parse_args()
    try:
        scenario = generate_scenario(
            args.entry, args.depth, objective=args.objective
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if args.format == "json":
        out = json.dumps(
            {
                k: v
                for k, v in scenario.items()
                if k != "skill_coverage_table"
            },
            indent=2,
        )
    elif args.format == "yaml":
        try:
            import yaml

            out = yaml.dump(
                {
                    k: v
                    for k, v in scenario.items()
                    if k != "skill_coverage_table"
                },
                default_flow_style=False,
            )
        except ImportError:
            print(
                "PyYAML required for YAML output. Install with: pip install pyyaml",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        out = build_markdown(
            scenario,
            template_path=Path(args.template) if args.template else None,
        )
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Scenario written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
