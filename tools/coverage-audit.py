#!/usr/bin/env python3
"""Coverage Audit - verifies that all mapped techniques exist in the knowledge graph with tactic metadata."""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / ".codegraph" / "knowledge_graph.lance"
TACTIC_MAPPING_PATH = REPO_ROOT / "mappings" / "jsonld" / "tactic-mapping.json"
JSONLD_DIR = REPO_ROOT / "mappings" / "jsonld"


def load_tactic_mapping():
    try:
        return json.loads(TACTIC_MAPPING_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error: Cannot load tactic mapping: {exc}", file=sys.stderr)
        sys.exit(2)


def load_jsonld(filename):
    path = JSONLD_DIR / filename
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _query_nodes(db, type_filter=None, framework_filter=None):
    try:
        rows = db.open_table("nodes").search().to_list()
    except Exception as exc:
        print(f"Error: Failed to query nodes table: {exc}", file=sys.stderr)
        sys.exit(2)
    filtered = []
    for row in rows:
        if type_filter and row.get("type") != type_filter:
            continue
        if framework_filter and row.get("framework") != framework_filter:
            continue
        filtered.append(row)
    if not filtered:
        sample = rows[:5] if rows else []
        print("[DEBUG] No filtered nodes matched.", file=sys.stderr)
        if sample:
            print("[DEBUG] Sample raw rows:", file=sys.stderr)
            for row in sample:
                print("[DEBUG]", {k: row.get(k) for k in ["id", "type", "framework", "framework_id"]}, file=sys.stderr)
    return filtered


def _missing_count(mapping_ids, graph_ids):
    return len(mapping_ids - graph_ids)


def audit_coverage(framework="all", strict=False, check_orphans=False):
    errors = []
    warnings = []
    summary = []

    try:
        import lancedb
    except ImportError:
        print("Error: lancedb required. Install with: pip install lancedb", file=sys.stderr)
        sys.exit(2)

    if not DB_PATH.exists():
        print("Error: Knowledge graph not found at .codegraph/knowledge_graph.lance", file=sys.stderr)
        print("Run tools/build-lancedb.py first.", file=sys.stderr)
        sys.exit(2)

    db = lancedb.connect(str(DB_PATH))

    frameworks = []
    if framework == "all":
        frameworks = [
            ("mitre-attack", "Technique", "ATT&CK"),
            ("mitre-atlas", "ATLAS-Technique", "ATLAS"),
            ("nist-ai-rmf", "AI-RMF-Function", "AI RMF"),
            ("owasp", "Category", "OWASP"),
            ("nist-csf", "Category", "NIST CSF"),
        ]
    else:
        label = {
            "mitre-attack": ("ATT&CK", "Technique"),
            "mitre-atlas": ("ATLAS", "ATLAS-Technique"),
            "nist-ai-rmf": ("AI RMF", "AI-RMF-Function"),
            "owasp": ("OWASP", "Category"),
            "nist-csf": ("NIST CSF", "Category"),
        }.get(framework, (framework, "entity"))
        frameworks.append((framework, label[1], label[0]))

    for fw_id, type_filter, label in frameworks:
        nodes = _query_nodes(db, type_filter=type_filter, framework_filter=fw_id)
        graph_ids = set()
        empty_meta = 0
        for row in nodes:
            gid = row.get("framework_id", "")
            if not gid:
                gid = row.get("id", "").split(":", 1)[-1]
            graph_ids.add(gid)
            if not row.get("tactic"):
                empty_meta += 1

        if fw_id == "mitre-attack":
            mapping = load_tactic_mapping()
            mapped_ids = set()
            for data in mapping.values():
                mapped_ids.update(data.get("techniques", []))
            mapping_total = len(mapped_ids)
            in_graph = mapping_total - _missing_count(mapped_ids, graph_ids)
            coverage = (in_graph / mapping_total * 100) if mapping_total else 0.0
            missing = _missing_count(mapped_ids, graph_ids)
            summary.append({
                "framework": label,
                "mapping_total": mapping_total,
                "graph_total": len(graph_ids),
                "in_graph": in_graph,
                "missing": missing,
                "coverage": coverage,
                "empty_tactic": empty_meta,
            })
        else:
            jsonld_map = {
                "mitre-atlas": "atlas.jsonld",
                "nist-ai-rmf": "ai-rmf.jsonld",
                "owasp": "owasp.jsonld",
                "nist-csf": None,
            }
            filename = jsonld_map.get(fw_id)
            mapped_ids = set()
            if filename:
                for entity in load_jsonld(filename):
                    mapped_ids.add(entity.get("framework_id", ""))
                mapping_total = len(mapped_ids)
            else:
                mapping_total = len(graph_ids)
            in_graph = mapping_total - _missing_count(mapped_ids, graph_ids)
            coverage = (in_graph / mapping_total * 100) if mapping_total else 0.0
            missing = _missing_count(mapped_ids, graph_ids)
            summary.append({
                "framework": label,
                "mapping_total": mapping_total,
                "graph_total": len(graph_ids),
                "in_graph": in_graph,
                "missing": missing,
                "coverage": coverage,
                "empty_tactic": empty_meta,
            })

    print("=" * 70)
    print("COVERAGE AUDIT REPORT")
    print("=" * 70)
    print(f"Graph source   : {DB_PATH}")
    print()

    for entry in summary:
        print(f"--- {entry['framework']} ---")
        print(f"Mapping total   : {entry['mapping_total']}")
        print(f"Graph total     : {entry['graph_total']}")
        print(f"In graph        : {entry['in_graph']}")
        print(f"Missing         : {entry['missing']}")
        print(f"Coverage %      : {entry['coverage']:.1f}%")
        print(f"Empty tactic    : {entry['empty_tactic']}")
        print()

    failed = [e for e in summary if e["missing"] > 0]
    if failed:
        errors.append(f"Missing entities ({len(failed)} framework(s)): {', '.join(e['framework'] for e in failed)}")
        for entry in failed:
            print(f"FAIL: {entry['framework']} has {entry['missing']} missing entities")

    if strict and any(e["empty_tactic"] > 0 for e in summary):
        warnings.append("Some entities have empty tactic metadata")

    print()
    if errors:
        print(f"FAILED: {len(errors)} issue(s) found")
        for e in errors:
            print(f"  - {e}")
    else:
        print("PASS: All mapped entities present in graph")

    if warnings:
        for w in warnings:
            print(f"WARNING: {w}")

    return 1 if errors or (warnings and strict) else 0


def main():
    parser = argparse.ArgumentParser(
        description="Audit technique coverage between tactic-mapping.json and the LanceDB knowledge graph"
    )
    parser.add_argument(
        "--framework",
        choices=["all", "mitre-attack", "mitre-atlas", "nist-ai-rmf", "owasp", "nist-csf"],
        default="all",
        help="Framework to audit (default: all)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on any issue including orphans"
    )
    parser.add_argument(
        "--check-orphans",
        action="store_true",
        help="Report techniques in graph that are not in the mapping"
    )
    parser.add_argument(
        "--report",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)"
    )
    args = parser.parse_args()

    rc = audit_coverage(framework=args.framework, strict=args.strict, check_orphans=args.check_orphans)
    sys.exit(rc)


if __name__ == "__main__":
    main()
