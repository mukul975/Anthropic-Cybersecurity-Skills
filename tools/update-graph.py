#!/usr/bin/env python3
"""Incremental update script for LanceDB knowledge graph.

Usage:
    python tools/update-graph.py --skill skills/analyzing-indicators-of-compromise/SKILL.md
    python tools/update-graph.py --all  # Rebuild entire graph
    python tools/update-graph.py --detect-changes  # Auto-detect changed skills via git

Environment variables for embedding:
    EMBEDDING_PROVIDER: "local" (default) or "openai"
    OPENAI_API_KEY: Required if EMBEDDING_PROVIDER=openai
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import lancedb
import numpy as np
import pyarrow as pa

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / ".codegraph" / "knowledge_graph.lance"
JSONLD_DIR = REPO_ROOT / "mappings" / "jsonld"
INDEX_FILE = REPO_ROOT / "index.json"
STATE_FILE = REPO_ROOT / ".codegraph" / ".ingest-state.json"

EMBEDDING_DIM = 384


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

        m = re.match(r"^(\w[\w_-]*):\s*>[-|]?\s*$", stripped)
        if m:
            current_key = m.group(1)
            list_values = []
            in_folded = True
            folded_lines = []
            continue

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
        except Exception:
            provider = "local"

    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        return model.encode
    except ImportError:
        return None


def load_ingest_state():
    """Load or initialize ingest state tracking."""
    default_state = {
        "last_run": None,
        "processed_skills": [],
        "graph_version": "1.0.0"
    }
    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
            state.setdefault("last_run", None)
            state.setdefault("processed_skills", [])
            state.setdefault("graph_version", "1.0.0")
            return state
    return default_state


def save_ingest_state(state):
    """Save ingest state to tracking file."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def build_skill_node(skill_path, index_data):
    """Build a single skill node from SKILL.md."""
    skill_md_path = Path(skill_path)
    if not skill_md_path.is_absolute():
        skill_md_path = REPO_ROOT / skill_path

    skill_name = skill_md_path.parent.name
    skill_entry = None
    for entry in index_data.get("skills", []):
        if entry["name"] == skill_name:
            skill_entry = entry
            break

    if not skill_entry:
        return None

    with open(skill_md_path, "r", encoding="utf-8") as f:
        frontmatter = parse_frontmatter(f.read())

    if not frontmatter:
        return None

    skill_id = f"skill:{skill_name}"
    text_for_embedding = f"{skill_name} {skill_entry.get('description', '')} {' '.join(frontmatter.get('tags', []))}"

    embed = get_embedding_provider()
    if embed:
        vector = embed([text_for_embedding])[0]
    else:
        np.random.seed(abs(hash(skill_name)) % 2**32)
        vector = list(np.random.random(EMBEDDING_DIM).astype(np.float32))

    return {
        "id": skill_id,
        "type": "Skill",
        "name": skill_name,
        "description": skill_entry.get("description", ""),
        "framework": "mitre-attack",
        "framework_id": frontmatter.get("mitre_attack", [""])[0] if frontmatter.get("mitre_attack") else "N/A",
        "tags": frontmatter.get("tags", []),
        "relationships": json.dumps([f"technique:{t}" for t in frontmatter.get("mitre_attack", [])] +
                                    [f"category:{c}" for c in frontmatter.get("nist_csf", [])]),
        "vector": vector,
    }


def update_skill(skill_path):
    """Update a single skill in the LanceDB graph."""
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
        index_data = json.load(f)

    node = build_skill_node(skill_path, index_data)
    if not node:
        print(f"Warning: Could not build node for {skill_path}")
        return False

    db = lancedb.connect(str(OUTPUT_DIR))
    table = db.open_table("nodes")

    # Update or insert the node
    existing = table.search().where(f"id = '{node['id']}'").to_list()
    if existing:
        table.delete(f"id = '{node['id']}'")
    table.add([node])

    print(f"Updated skill: {node['id']}")
    return True


def detect_changed_skills():
    """Detect changed skills via git diff since last ingest."""
    state = load_ingest_state()
    last_run = state.get("last_run")

    if not last_run:
        # First run: process all skills
        result = subprocess.run(
            ["git", "ls-files", "skills/*/SKILL.md"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True
        )
        return result.stdout.strip().split("\n") if result.stdout.strip() else []

    # Get changed files since last run
    result = subprocess.run(
        ["git", "diff", "--name-only", f"--since={last_run}", "skills/*/SKILL.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True
    )
    return result.stdout.strip().split("\n") if result.stdout.strip() else []


def main():
    parser = argparse.ArgumentParser(description="Incremental knowledge graph update")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--skill", "-s", help="Single skill path to update (e.g., skills/name/SKILL.md)")
    group.add_argument("--all", "-a", action="store_true", help="Rebuild entire graph")
    group.add_argument("--detect-changes", "-d", action="store_true", help="Auto-detect changed skills via git")

    args = parser.parse_args()

    if args.all:
        # Full rebuild via build-lancedb.py
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_lancedb", REPO_ROOT / "tools" / "build-lancedb.py")
        build_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build_module)
        build_module.main()

        state = load_ingest_state()
        state["last_run"] = datetime.utcnow().isoformat() + "Z"
        state["graph_version"] = "1.1.0"
        save_ingest_state(state)
        return

    if args.skill:
        updated = update_skill(args.skill)
        if updated:
            state = load_ingest_state()
            state["last_run"] = datetime.utcnow().isoformat() + "Z"
            if args.skill not in state["processed_skills"]:
                state["processed_skills"].append(args.skill)
            save_ingest_state(state)
        return

    if args.detect_changes:
        changed = detect_changed_skills()
        if not changed:
            print("No changes detected since last run")
            return

        print(f"Processing {len(changed)} changed skills...")
        for skill_path in changed:
            if skill_path:
                update_skill(skill_path)

        state = load_ingest_state()
        state["last_run"] = datetime.utcnow().isoformat() + "Z"
        for sp in changed:
            if sp and sp not in state["processed_skills"]:
                state["processed_skills"].append(sp)
        save_ingest_state(state)


if __name__ == "__main__":
    main()