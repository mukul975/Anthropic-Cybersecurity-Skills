#!/usr/bin/env python3
"""
build_index.py — One-time embedding builder for the cybersecurity skills library.

Run this once after cloning, and again after updating skills/:
    python3 build_index.py

Outputs:
    data/skill_meta.json    — skill metadata (slug, name, description, subdomain, tags, mitre_attack)
    data/embeddings.npy     — float32 array of shape (N, embedding_dim)

Requires: sentence-transformers (pip3 install sentence-transformers)
"""

import json
import re
import sys
import time
from pathlib import Path

# ── Ensure project root is on path ────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from cyberagent.config import SKILLS_DIR, DATA_DIR, SKILL_META_FILE, EMBEDDINGS_FILE, EMBED_MODEL_NAME
from cyberagent.retrieval import _parse_frontmatter, _body_snippet

# ── Check dependency ───────────────────────────────────────────────────────
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
except ImportError:
    print("ERROR: Missing dependencies. Run:")
    print("  python3 -m pip install sentence-transformers numpy --break-system-packages")
    sys.exit(1)


def build():
    DATA_DIR.mkdir(exist_ok=True)

    # ── Scan skills ────────────────────────────────────────────────────────
    print(f"Scanning {SKILLS_DIR} ...")
    skill_mds = sorted(SKILLS_DIR.glob("*/SKILL.md"))
    total = len(skill_mds)
    print(f"Found {total} skills.")

    skills = []
    embed_texts = []

    for skill_md in skill_mds:
        slug = skill_md.parent.name
        try:
            content = skill_md.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  WARN: could not read {skill_md}: {e}")
            continue

        meta = _parse_frontmatter(content)
        body = _body_snippet(content, max_chars=400)

        record = {
            "slug": slug,
            "name": meta.get("name", slug),
            "description": meta.get("description", ""),
            "subdomain": meta.get("subdomain", ""),
            "tags": meta.get("tags", []),
            "mitre_attack": meta.get("mitre_attack", []),
            "path": str(skill_md.parent),
        }
        skills.append(record)

        # Embedding text = name + description + subdomain + tags + body snippet
        embed_text = " ".join([
            record["name"],
            record["description"],
            record["subdomain"],
            " ".join(record["tags"]),
            body,
        ])
        embed_texts.append(embed_text)

    # ── Save metadata ──────────────────────────────────────────────────────
    with open(SKILL_META_FILE, "w", encoding="utf-8") as f:
        json.dump(skills, f, indent=2)
    print(f"Saved metadata → {SKILL_META_FILE}")

    # ── Build embeddings ───────────────────────────────────────────────────
    print(f"\nLoading embedding model: {EMBED_MODEL_NAME}")
    print("(First run downloads ~84MB — subsequent runs load from cache)\n")
    t0 = time.time()
    model = SentenceTransformer(EMBED_MODEL_NAME)

    print(f"Embedding {len(embed_texts)} skills ...")
    embeddings = model.encode(
        embed_texts,
        show_progress_bar=True,
        batch_size=64,
        normalize_embeddings=True,  # pre-normalised → dot product = cosine sim
    ).astype("float32")

    elapsed = time.time() - t0
    shape_str = f"{embeddings.shape[0]}×{embeddings.shape[1]}"

    np.save(str(EMBEDDINGS_FILE), embeddings)
    size_mb = EMBEDDINGS_FILE.stat().st_size / 1_048_576
    print(f"\nSaved embeddings ({shape_str}, {size_mb:.1f} MB) → {EMBEDDINGS_FILE}")
    print(f"Total time: {elapsed:.1f}s")
    print("\nIndex built. Run python3 run_agent.py to start the agent.")


if __name__ == "__main__":
    build()
