"""
cyberagent/retrieval.py — Hybrid semantic + keyword skill retrieval.

On first import, loads cached embeddings from data/embeddings.npy.
Falls back to keyword scoring if sentence-transformers is not installed
or if the index hasn't been built yet (run build_index.py first).
"""

import re
import json
import logging
import os
from pathlib import Path
from typing import Optional

import numpy as np

from .config import (
    SKILLS_DIR, SKILL_META_FILE, EMBEDDINGS_FILE,
    EMBED_MODEL_NAME, MAX_SKILLS, SEMANTIC_THRESHOLD,
)

log = logging.getLogger(__name__)

os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_VERBOSITY", "error")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

# ---------------------------------------------------------------------------
# Frontmatter parser (no yaml dependency for speed)
# ---------------------------------------------------------------------------

def _parse_frontmatter(text: str) -> dict:
    """Extract key/value pairs from YAML-style --- frontmatter."""
    meta: dict = {}
    m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return meta
    block = m.group(1)

    # Simple scalar fields
    for line in block.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("-"):
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip().strip("'\"")
            if v and k not in ("tags", "nist_csf", "mitre_attack", "d3fend", "atlas"):
                meta[k] = v

    # tags list
    tags_m = re.search(r"^tags:\n((?:\s*-\s*.+\n?)*)", block + "\n", re.MULTILINE)
    if tags_m:
        meta["tags"] = re.findall(r"-\s+(.+)", tags_m.group(1))

    # mitre_attack list
    att_m = re.search(r"^mitre_attack:\n((?:\s*-\s*.+\n?)*)", block + "\n", re.MULTILINE)
    if att_m:
        meta["mitre_attack"] = re.findall(r"-\s+(.+)", att_m.group(1))

    return meta


def _body_snippet(text: str, max_chars: int = 300) -> str:
    """Return the first `max_chars` chars of the body (after frontmatter)."""
    m = re.match(r"^---\n.*?\n---\n", text, re.DOTALL)
    start = m.end() if m else 0
    return text[start:start + max_chars].strip()


# ---------------------------------------------------------------------------
# SkillIndex
# ---------------------------------------------------------------------------

class SkillIndex:
    """
    In-memory index of all 754 skills.

    At construction:
      1. Loads skill_meta.json from cache (fast path).
      2. Falls back to scanning skills/ directory (slower, no embeddings).
      3. If embeddings.npy exists, enables semantic search.
      4. Otherwise, falls back to keyword scoring.
    """

    def __init__(self):
        self.skills: list[dict] = []
        self.embeddings: Optional[np.ndarray] = None
        self._model = None
        self._semantic_enabled = False
        self._load()

    # ── Loading ────────────────────────────────────────────────────────────

    def _load(self):
        # Step 1: metadata
        if SKILL_META_FILE.exists():
            with open(SKILL_META_FILE, encoding="utf-8") as f:
                self.skills = json.load(f)
            log.debug("Loaded %d skills from cache: %s", len(self.skills), SKILL_META_FILE)
        else:
            log.warning("skill_meta.json not found — scanning skills/ directory (run build_index.py for full semantic search)")
            self._scan_skills_dir()

        # Step 2: embeddings
        if EMBEDDINGS_FILE.exists():
            try:
                self.embeddings = np.load(str(EMBEDDINGS_FILE)).astype(np.float32)
                if self.embeddings.shape[0] == len(self.skills):
                    self._semantic_enabled = True
                    log.debug("Semantic search enabled (%d×%d embeddings)", *self.embeddings.shape)
                else:
                    log.warning(
                        "Embedding count (%d) ≠ skill count (%d) — rebuild index",
                        self.embeddings.shape[0], len(self.skills)
                    )
                    self._semantic_enabled = False
            except Exception as e:
                log.warning("Could not load embeddings: %s — using keyword search", e)

        # Step 3: keyword blob for fallback
        for s in self.skills:
            s["_blob"] = " ".join([
                s.get("slug", ""),
                s.get("name", ""),
                s.get("description", ""),
                s.get("subdomain", ""),
                " ".join(s.get("tags", [])),
            ]).lower()

    def _scan_skills_dir(self):
        """Scan SKILL.md files and build minimal metadata without embeddings."""
        for skill_md in sorted(SKILLS_DIR.glob("*/SKILL.md")):
            slug = skill_md.parent.name
            try:
                content = skill_md.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            meta = _parse_frontmatter(content)
            self.skills.append({
                "slug": slug,
                "name": meta.get("name", slug),
                "description": meta.get("description", ""),
                "subdomain": meta.get("subdomain", ""),
                "tags": meta.get("tags", []),
                "mitre_attack": meta.get("mitre_attack", []),
                "path": str(skill_md.parent),
            })

    # ── Model lazy-load ────────────────────────────────────────────────────

    def _get_embed_model(self):
        if self._model is None:
            try:
                from transformers.utils import logging as transformers_logging
                from sentence_transformers import SentenceTransformer
                transformers_logging.set_verbosity_error()
                transformers_logging.disable_progress_bar()
                self._model = SentenceTransformer(EMBED_MODEL_NAME)
            except ImportError:
                raise ImportError(
                    "sentence-transformers not installed. "
                    "Run: pip3 install sentence-transformers"
                )
        return self._model

    def embed(self, texts: list[str]) -> np.ndarray:
        """Embed a list of texts. Used by build_index.py."""
        model = self._get_embed_model()
        return model.encode(texts, show_progress_bar=True, batch_size=64).astype(np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        """Embed a single query string (no progress bar)."""
        model = self._get_embed_model()
        return model.encode([query], show_progress_bar=False).astype(np.float32)[0]

    # ── Search ─────────────────────────────────────────────────────────────

    def search(self, query: str, top_k: int = MAX_SKILLS) -> list[dict]:
        """Return top-k skills most relevant to `query`."""
        if self._semantic_enabled:
            return self._hybrid_search(query, top_k)
        return self._keyword_search(query, top_k)

    def _hybrid_search(self, query: str, top_k: int) -> list[dict]:
        """Cosine similarity + keyword/ATT&CK boost."""
        q_vec = self.embed_query(query)

        # Cosine similarity (vectorised)
        norms = np.linalg.norm(self.embeddings, axis=1) * np.linalg.norm(q_vec)
        norms = np.where(norms == 0, 1e-10, norms)
        similarities = (self.embeddings @ q_vec) / norms  # shape (N,)

        # Keyword boost
        query_lower = query.lower()
        tokens = set(re.findall(r"[a-z0-9]+", query_lower))
        boosts = np.zeros(len(self.skills), dtype=np.float32)

        for i, s in enumerate(self.skills):
            slug = s.get("slug", "")
            # Tool-name / keyword match in slug
            for tok in tokens:
                if len(tok) > 3 and tok in slug:
                    boosts[i] += 0.12
            # ATT&CK technique ID match
            att_ids = [t.lower() for t in s.get("mitre_attack", [])]
            for tid in att_ids:
                if tid in query_lower:
                    boosts[i] += 0.20

        scores = similarities + boosts
        top_indices = np.argsort(scores)[-top_k * 2:][::-1]  # over-fetch then filter
        results = [
            self.skills[i] for i in top_indices
            if scores[i] >= SEMANTIC_THRESHOLD
        ]
        return results[:top_k]

    def _keyword_search(self, query: str, top_k: int) -> list[dict]:
        """Pure token-overlap scoring (fallback when embeddings unavailable)."""
        stop = {
            "a", "an", "the", "is", "are", "how", "do", "i", "to", "for",
            "in", "of", "and", "or", "with", "can", "you", "what", "this",
            "that", "it", "on", "at", "from", "by", "as", "be", "was",
            "not", "get", "me", "my", "we", "our",
        }
        tokens = set(re.findall(r"[a-z0-9]+", query.lower())) - stop

        scored = []
        for skill in self.skills:
            blob = skill.get("_blob", "")
            score = 0
            for tok in tokens:
                score += len(re.findall(r"\b" + re.escape(tok) + r"\b", blob)) * 2
                if tok in blob:
                    score += 1
            if score > 0:
                scored.append((score, skill))

        scored.sort(reverse=True)
        return [s for _, s in scored[:top_k]]

    # ── Utilities ──────────────────────────────────────────────────────────

    def get_by_slug(self, slug: str) -> Optional[dict]:
        """Return skill metadata dict by exact slug."""
        for s in self.skills:
            if s["slug"] == slug:
                return s
        return None

    def list_by_subdomain(self, subdomain: str) -> list[dict]:
        """Return all skills in a given subdomain."""
        return [s for s in self.skills if s.get("subdomain", "") == subdomain]

    def all_subdomains(self) -> dict[str, int]:
        """Return {subdomain: count} mapping."""
        counts: dict[str, int] = {}
        for s in self.skills:
            sd = s.get("subdomain", "unknown")
            counts[sd] = counts.get(sd, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    @property
    def count(self) -> int:
        return len(self.skills)

    @property
    def semantic_enabled(self) -> bool:
        return self._semantic_enabled


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init on first use)
# ---------------------------------------------------------------------------

_index: Optional[SkillIndex] = None


def get_index() -> SkillIndex:
    """Return the module-level SkillIndex singleton."""
    global _index
    if _index is None:
        _index = SkillIndex()
    return _index
