#!/usr/bin/env python3
"""Build LanceDB knowledge graph from JSON-LD entities.

Usage:
    python tools/build-lancedb.py [--output .codegraph/knowledge_graph.lance]

Environment variables for embedding:
    EMBEDDING_PROVIDER: "local" (default) or "openai"
    OPENAI_API_KEY: Required if EMBEDDING_PROVIDER=openai
"""
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import lancedb
import pyarrow as pa

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / ".codegraph" / "knowledge_graph.lance"
JSONLD_DIR = REPO_ROOT / "mappings" / "jsonld"

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 output dimension


def get_embedding_provider():
    """Return embedding model/provider based on env config."""
    provider = os.environ.get("EMBEDDING_PROVIDER", "local")
    if provider == "openai":
        try:
            import openai
            client = openai.OpenAI()
            return lambda texts: [e.embedding for e in client.embeddings.create(
                model="text-embedding-3-small", input=texts
            ).data]
        except Exception as e:
            print(f"OpenAI embedding failed, falling back to local: {e}")
            provider = "local"

    # Local sentence-transformers
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        return model.encode
    except ImportError:
        # Fallback to random embeddings for zero-dependency mode
        import random
        return lambda texts: [[random.random() for _ in range(EMBEDDING_DIM)] for _ in texts]


def build_nodes_table(skills, techniques, owasp_categories=None, atlas_entities=None, ai_rmf_entities=None):
    """Create nodes table with entity data and embeddings."""
    rows = []
    embed = get_embedding_provider()

    # Process skills
    for skill in skills:
        text_for_embedding = f"{skill['name']} {skill.get('description', '')} {' '.join(skill.get('tags', []))}"
        vector = embed([text_for_embedding])[0]

        rows.append({
            "id": skill["@id"],
            "type": "Skill",
            "name": skill["name"],
            "description": skill.get("description", ""),
            "framework": skill.get("framework", "mitre-attack"),
            "framework_id": skill.get("framework_id", "N/A"),
            "tags": skill.get("tags", []),
            "relationships": json.dumps(skill.get("references", [])),
            "tactic": "",
            "score": 0,
            "vector": vector,
        })

    # Process techniques
    for tech in techniques:
        text_for_embedding = f"{tech['name']} {tech.get('description', '')}"
        vector = embed([text_for_embedding])[0]

        rows.append({
            "id": tech["@id"],
            "type": "Technique",
            "name": tech.get("name", tech["framework_id"]),
            "description": tech.get("description", ""),
            "framework": tech.get("framework", "mitre-attack"),
            "framework_id": tech["framework_id"],
            "tags": [],
            "relationships": json.dumps(tech.get("skills", [])),
            "tactic": tech.get("tactic", ""),
            "score": tech.get("score", 0),
            "vector": vector,
        })

    # Process NIST CSF categories from skill relationships
    csf_categories = set()
    for skill in skills:
        for csf_id in skill.get("nist_csf", []):
            csf_categories.add(csf_id)

    for csf_id in csf_categories:
        text_for_embedding = f"NIST CSF {csf_id}"
        vector = embed([text_for_embedding])[0]
        rows.append({
            "id": f"category:{csf_id}",
            "type": "Category",
            "name": f"NIST CSF {csf_id}",
            "description": "",
            "framework": "nist-csf",
            "framework_id": csf_id,
            "tags": [],
            "relationships": json.dumps([]),
            "tactic": "",
            "score": 0,
            "vector": vector,
        })

    # Process OWASP categories if present
    for cat in (owasp_categories or []):
        text_for_embedding = f"{cat['name']} {cat.get('description', '')}"
        vector = embed([text_for_embedding])[0]
        rows.append({
            "id": cat["@id"],
            "type": "Category",
            "name": cat["name"],
            "description": cat.get("description", ""),
            "framework": "owasp",
            "framework_id": cat.get("framework_id", ""),
            "tags": [],
            "relationships": json.dumps([]),
            "tactic": "",
            "score": 0,
            "vector": vector,
        })

    # Process ATLAS techniques
    for tech in (atlas_entities or []):
        text_for_embedding = f"{tech.get('name', tech['framework_id'])} {tech.get('description', '')}"
        vector = embed([text_for_embedding])[0]
        rows.append({
            "id": tech["@id"],
            "type": "ATLAS-Technique",
            "name": tech.get("name", tech["framework_id"]),
            "description": tech.get("description", ""),
            "framework": tech.get("framework", "mitre-atlas"),
            "framework_id": tech["framework_id"],
            "tags": [],
            "relationships": json.dumps([]),
            "tactic": tech.get("tactic", ""),
            "score": 0,
            "vector": vector,
        })

    # Process NIST AI RMF entities
    for entity in (ai_rmf_entities or []):
        text_for_embedding = f"{entity.get('name', entity['framework_id'])} {entity.get('description', '')}"
        vector = embed([text_for_embedding])[0]
        rows.append({
            "id": entity["@id"],
            "type": "AI-RMF-Function",
            "name": entity.get("name", entity["framework_id"]),
            "description": entity.get("description", ""),
            "framework": entity.get("framework", "nist-ai-rmf"),
            "framework_id": entity["framework_id"],
            "tags": [],
            "relationships": json.dumps([]),
            "tactic": entity.get("tactic", ""),
            "score": 0,
            "vector": vector,
        })

    schema = pa.schema([
        pa.field("id", pa.string()),
        pa.field("type", pa.string()),
        pa.field("name", pa.string()),
        pa.field("description", pa.string()),
        pa.field("framework", pa.string()),
        pa.field("framework_id", pa.string()),
        pa.field("tags", pa.list_(pa.string())),
        pa.field("relationships", pa.string()),
        pa.field("tactic", pa.string()),
        pa.field("score", pa.int64()),
        pa.field("vector", pa.list_(pa.float32(), 384)),
    ])
    return pa.Table.from_pylist(rows, schema=schema)


def build_relationships_table(skills, techniques, atlas_entities=None, ai_rmf_entities=None):
    """Create relationships (edges) table from entity references."""
    rows = []

    # Extract relationships from skill frontmatter
    for skill in skills:
        skill_id = skill["@id"]
        for fw_key, predicate in [
            ("mitre_attack", "implements"),
            ("nist_csf", "alignedWith"),
            ("atlas_techniques", "mitigates"),
            ("nist_ai_rmf", "alignedWith"),
        ]:
            for fw_id in skill.get(fw_key, []):
                if fw_key == "nist_ai_rmf":
                    target = f"ai-rmf:{fw_id}"
                elif fw_key == "atlas_techniques":
                    target = f"atlas:{fw_id}"
                elif fw_key != "nist_csf":
                    target = f"technique:{fw_id}"
                else:
                    target = f"category:{fw_id}"
                rows.append({
                    "source": skill_id,
                    "target": target,
                    "predicate": predicate,
                    "weight": 1.0,
                })

    # Extract relationships from ATT&CK Navigator layer
    for tech in techniques:
        tech_id = tech["@id"]
        for skill_ref in tech.get("skills", []):
            rows.append({
                "source": tech_id,
                "target": skill_ref,
                "predicate": "coveredBy",
                "weight": tech.get("score", 0) / 100.0,
            })

    # Cross-framework inferred edges
    skill_atlas = defaultdict(list)
    skill_attack = defaultdict(list)
    skill_ai = defaultdict(list)
    for skill in skills:
        sid = skill["@id"]
        for val in skill.get("mitre_attack", []):
            skill_attack[sid].append(val)
        for val in skill.get("atlas_techniques", []):
            skill_atlas[sid].append(val)
        for val in skill.get("nist_ai_rmf", []):
            skill_ai[sid].append(val)

    for sid, attack_ids in skill_attack.items():
        for attack_id in attack_ids:
            for atlas_id in skill_atlas.get(sid, []):
                rows.append({
                    "source": f"technique:{attack_id}",
                    "target": f"atlas:{atlas_id}",
                    "predicate": "atlasesEquivalentTo",
                    "weight": 1.0,
                })
            for ai_id in skill_ai.get(sid, []):
                rows.append({
                    "source": f"technique:{attack_id}",
                    "target": f"ai-rmf:{ai_id}",
                    "predicate": "governedBy",
                    "weight": 1.0,
                })

    return pa.Table.from_pylist(rows)


def main():
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Load JSON-LD entities
    skills_file = JSONLD_DIR / "skills.jsonld"
    techniques_file = JSONLD_DIR / "techniques.jsonld"
    owasp_file = JSONLD_DIR / "owasp.jsonld"
    atlas_file = JSONLD_DIR / "atlas.jsonld"
    ai_rmf_file = JSONLD_DIR / "ai-rmf.jsonld"

    if not skills_file.exists():
        print("Error: skills.jsonld not found. Run build-jsonld.py first.")
        sys.exit(1)

    with open(skills_file, "r", encoding="utf-8") as f:
        skills = json.load(f)

    with open(techniques_file, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    owasp_categories = []
    if owasp_file.exists():
        with open(owasp_file, "r", encoding="utf-8") as f:
            owasp_categories = json.load(f)

    atlas_entities = []
    if atlas_file.exists():
        with open(atlas_file, "r", encoding="utf-8") as f:
            atlas_entities = json.load(f)

    ai_rmf_entities = []
    if ai_rmf_file.exists():
        with open(ai_rmf_file, "r", encoding="utf-8") as f:
            ai_rmf_entities = json.load(f)

    # Connect to LanceDB
    db = lancedb.connect(str(OUTPUT_DIR))

    # Build and write nodes table
    nodes_table = build_nodes_table(skills, techniques, owasp_categories, atlas_entities, ai_rmf_entities)
    db.create_table("nodes", nodes_table, mode="overwrite")
    print(f"Created 'nodes' table with {len(nodes_table)} entities")

    # Build and write relationships table
    edges_table = build_relationships_table(skills, techniques, atlas_entities, ai_rmf_entities)
    db.create_table("relationships", edges_table, mode="overwrite")
    print(f"Created 'relationships' table with {len(edges_table)} relationships")

    print(f"Knowledge graph stored at {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
