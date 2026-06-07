#!/usr/bin/env python3
"""Query LanceDB knowledge graph for skills, techniques, and relationships.

Usage:
    python tools/query-graph.py --query "detect credential dumping" --top-k 5
    python tools/query-graph.py --walk T1071 --depth 2
    python tools/query-graph.py --framework mitre-attack
    python tools/query-graph.py --impact "analyzing-indicators-of-compromise"
"""
import argparse
import json
import sys
from pathlib import Path

import lancedb
import numpy as np

REPO_ROOT = Path(__file__).parent.parent
DB_PATH = REPO_ROOT / ".codegraph" / "knowledge_graph.lance"


def get_embedding_provider():
    """Return embedding model/provider based on env config."""
    import os
    provider = os.environ.get("EMBEDDING_PROVIDER", "local")

    if provider == "openai":
        try:
            import openai
            client = openai.OpenAI()
            return lambda texts: [e.embedding for e in client.embeddings.create(
                model="text-embedding-3-small", input=texts
            ).data]
        except Exception:
            provider = "local"

    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        return model.encode
    except ImportError:
        # Zero-dependency fallback
        return None


def semantic_search(query, top_k=5):
    """Perform vector similarity search on nodes."""
    if not DB_PATH.exists():
        print("Error: Knowledge graph not found. Run build-lancedb.py first.")
        return []

    db = lancedb.connect(str(DB_PATH))
    table = db.open_table("nodes")

    embed = get_embedding_provider()
    if embed:
        query_vec = embed([query])[0]
    else:
        # Fallback: use BM25-style full-text search on name/description
        results = table.search().where(f"name LIKE '%{query}%' OR description LIKE '%{query}%'").limit(top_k).to_list()
        return results

    results = table.search(query_vec).metric("cosine").limit(top_k).to_list()
    return results


def walk_graph(entity_id, depth=2, predicate_filter=None):
    """Traverse graph relationships starting from an entity."""
    if not DB_PATH.exists():
        print("Error: Knowledge graph not found. Run build-lancedb.py first.")
        return []

    db = lancedb.connect(str(DB_PATH))
    nodes = db.open_table("nodes")
    relationships = db.open_table("relationships")

    # Normalize entity_id
    if not entity_id.startswith(("skill:", "technique:", "category:")):
        entity_id = f"technique:{entity_id}"

    visited = set()
    results = []
    current_ids = {entity_id}

    for _ in range(depth):
        if not current_ids:
            break

        # Get relationships for current level
        rel_results = []
        for eid in current_ids:
            rels = relationships.search().where(f"source = '{eid}' OR target = '{eid}'").to_list()
            rel_results.extend(rels)

        next_ids = set()
        for rel in rel_results:
            if predicate_filter and rel["predicate"] != predicate_filter:
                continue
            next_ids.add(rel["target"])
            next_ids.add(rel["source"])

        # Get node details
        for node_id in next_ids - visited:
            node_results = nodes.search().where(f"id = '{node_id}'").to_list()
            results.extend(node_results)

        visited.update(current_ids)
        current_ids = next_ids - visited

    return results


def filter_by_framework(framework):
    """List all entities for a specific framework."""
    if not DB_PATH.exists():
        print("Error: Knowledge graph not found. Run build-lancedb.py first.")
        return []

    db = lancedb.connect(str(DB_PATH))
    table = db.open_table("nodes")

    results = table.search().where(f"framework = '{framework}'").to_list()
    return results


def impact_analysis(skill_id):
    """Find related techniques and other skills through shared techniques."""
    if not DB_PATH.exists():
        print("Error: Knowledge graph not found. Run build-lancedb.py first.")
        return []

    db = lancedb.connect(str(DB_PATH))
    nodes = db.open_table("nodes")
    relationships = db.open_table("relationships")

    # Normalize skill_id
    if not skill_id.startswith("skill:"):
        skill_id = f"skill:{skill_id}"

    # Find all techniques this skill references
    rels = relationships.search().where(f"source = '{skill_id}'").to_list()
    related_techniques = [r["target"] for r in rels]

    # Find other skills that share these techniques
    results = {"techniques": [], "related_skill_ids": []}
    for tech_id in related_techniques:
        tech_results = nodes.search().where(f"id = '{tech_id}'").to_list()
        results["techniques"].extend(tech_results)

        shared_skills = relationships.search().where(f"target = '{tech_id}'").to_list()
        for r in shared_skills:
            if r["source"] != skill_id:
                results["related_skill_ids"].append(r["source"])

    # Get details of related skills (deduplicated)
    seen = set()
    for skill in results["related_skill_ids"]:
        if skill in seen:
            continue
        seen.add(skill)
        skill_results = nodes.search().where(f"id = '{skill}'").to_list()
        for sr in skill_results:
            results.setdefault("related_skills", []).append(sr)

    return results


def main():
    parser = argparse.ArgumentParser(description="Query the cybersecurity knowledge graph")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", "-q", help="Semantic search query")
    group.add_argument("--walk", "-w", help="Graph traversal from entity ID (e.g., T1071, skill-name)")
    group.add_argument("--framework", "-f", help="Filter entities by framework")
    group.add_argument("--impact", "-i", help="Impact analysis: find related skills through shared techniques")

    parser.add_argument("--top-k", "-k", type=int, default=5, help="Top k results for semantic search (default: 5)")
    parser.add_argument("--depth", "-d", type=int, default=2, help="Traversal depth (default: 2)")
    parser.add_argument("--predicate", "-p", help="Filter relationships by predicate")

    args = parser.parse_args()

    if args.query:
        results = semantic_search(args.query, args.top_k)
        for r in results:
            print(f"[{r['type']}] {r['id']}: {r['name']}")
            print(f"    {r['description'][:100]}..." if len(r.get('description', '')) > 100 else f"    {r.get('description', '')}")

    elif args.walk:
        results = walk_graph(args.walk, args.depth, args.predicate)
        for r in results:
            print(f"[{r['type']}] {r['id']}: {r['name']}")

    elif args.framework:
        results = filter_by_framework(args.framework)
        for r in results:
            print(f"[{r['type']}] {r['id']}: {r['name']}")

    elif args.impact:
        results = impact_analysis(args.impact)
        if isinstance(results, dict):
            print("Techniques:")
            for t in results.get("techniques", []):
                if isinstance(t, dict):
                    print(f"  {t['id']}: {t['name']}")
            seen_skills = {}
            print("Related Skills:")
            for s in results.get("related_skills", []):
                if isinstance(s, dict) and s.get("id") and s.get("id") not in seen_skills:
                    print(f"  {s['id']}: {s['name']}")
                    seen_skills[s["id"]] = True
        else:
            for r in results:
                print(f"[{r['type']}] {r['id']}: {r['name']}")


if __name__ == "__main__":
    main()