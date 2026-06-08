#!/usr/bin/env python3
"""Coverage Audit - verifies that all mapped techniques exist in the knowledge graph with tactic metadata."""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / ".codegraph" / "knowledge_graph.lance"
TACTIC_MAPPING_PATH = REPO_ROOT / "mappings" / "jsonld" / "tactic-mapping.json"


def load_tactic_mapping():
    try:
        return json.loads(TACTIC_MAPPING_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error: Cannot load tactic mapping: {exc}", file=sys.stderr)
        sys.exit(2)


def audit_coverage(strict=False, check_orphans=False):
    errors = []
    warnings = []
    stats = {
        "mapping_total": 0,
        "graph_total": 0,
        "in_graph": 0,
        "missing": 0,
        "tactic_empty": 0,
        "orphaned": 0,
    }

    mapping = load_tactic_mapping()

    mapping_techniques = set()
    for tactic_id, data in mapping.items():
        for tech_id in data.get("techniques", []):
            mapping_techniques.add(tech_id)
    stats["mapping_total"] = len(mapping_techniques)

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
    nodes_table = db.open_table("nodes")

    # Load all technique nodes
    all_technique_ids = set()
    empty_tactic_techniques = []
    try:
        # Query all Technique nodes
        results = nodes_table.search().where("type = 'Technique'").to_list()
        for row in results:
            tech_id = row.get("framework_id", "")
            if not tech_id:
                # Fallback: strip prefix from id
                raw_id = row.get("id", "")
                if raw_id.startswith("technique:"):
                    tech_id = raw_id[len("technique:"):]
            all_technique_ids.add(tech_id)
            tactic = row.get("tactic", "")
            if not tactic:
                empty_tactic_techniques.append(tech_id)
    except Exception as exc:
        print(f"Error: Failed to query nodes table: {exc}", file=sys.stderr)
        sys.exit(2)

    stats["graph_total"] = len(all_technique_ids)

    # Check mapping techniques against graph
    missing_techniques = []
    for tech_id in sorted(mapping_techniques):
        if tech_id in all_technique_ids:
            stats["in_graph"] += 1
        else:
            missing_techniques.append(tech_id)
            stats["missing"] += 1

    stats["tactic_empty"] = len(empty_tactic_techniques)

    # Tactic coverage percentage (techniques in graph with non-empty tactic)
    tactic_coverage = 0.0
    if stats["in_graph"] > 0:
        tactic_coverage = ((stats["in_graph"] - stats["tactic_empty"]) / stats["in_graph"]) * 100

    # Orphaned techniques (in graph but not in mapping) - optional
    orphaned_techniques = []
    if check_orphans:
        orphaned_techniques = sorted(
            t for t in all_technique_ids
            if t not in mapping_techniques and t
        )
        stats["orphaned"] = len(orphaned_techniques)

    # Report
    print("=" * 60)
    print("COVERAGE AUDIT REPORT")
    print("=" * 60)
    print(f"Mapping source  : {TACTIC_MAPPING_PATH}")
    print(f"Graph source    : {DB_PATH}")
    print(f"Mapping total   : {stats['mapping_total']} techniques")
    print(f"Graph total     : {stats['graph_total']} techniques")
    print(f"In graph        : {stats['in_graph']}")
    print(f"Missing         : {stats['missing']}")
    print(f"Tactic metadata : {stats['tactic_empty']} with empty tactic")
    print(f"Coverage %      : {tactic_coverage:.1f}%")
    if check_orphans:
        print(f"Orphaned        : {stats['orphaned']}")
    print()

    if missing_techniques:
        errors.append(f"Missing techniques ({len(missing_techniques)}): in mapping but absent from graph")
        if strict or len(missing_techniques) <= 20:
            for t in missing_techniques[:20]:
                print(f"  MISSING: {t}")
            if len(missing_techniques) > 20:
                print(f"  ... and {len(missing_techniques) - 20} more")
        else:
            print(f"  (strict mode off; showing first 20 of {len(missing_techniques)})")
            for t in missing_techniques[:20]:
                print(f"  MISSING: {t}")

    if empty_tactic_techniques:
        errors.append(f"Empty tactic metadata ({len(empty_tactic_techniques)}): techniques in graph but tactic is unset")
        if strict or len(empty_tactic_techniques) <= 20:
            for t in empty_tactic_techniques[:20]:
                print(f"  EMPTY TACTIC: {t}")
            if len(empty_tactic_techniques) > 20:
                print(f"  ... and {len(empty_tactic_techniques) - 20} more")
        else:
            print(f"  (strict mode off; showing first 20 of {len(empty_tactic_techniques)})")
            for t in empty_tactic_techniques[:20]:
                print(f"  EMPTY TACTIC: {t}")

    if orphaned_techniques:
        warnings.append(f"Orphaned techniques ({len(orphaned_techniques)}): in graph but not in mapping")

    print()
    if errors:
        print(f"FAILED: {len(errors)} issue(s) found")
        for e in errors:
            print(f"  - {e}")
    else:
        print("PASS: All mapped techniques present in graph with valid tactic metadata")

    if warnings:
        for w in warnings:
            print(f"WARNING: {w}")

    # Exit non-zero on failure (or strict missing/tactic failures)
    if errors:
        return 1
    elif warnings and strict:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Audit technique coverage between tactic-mapping.json and the LanceDB knowledge graph"
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

    rc = audit_coverage(strict=args.strict, check_orphans=args.check_orphans)
    sys.exit(rc)


if __name__ == "__main__":
    main()
