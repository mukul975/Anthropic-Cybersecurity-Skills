"""
cyberagent/skill_loader.py — Load full skill content for context injection.

Priority order per skill:
  1. SKILL.md            (always loaded)
  2. references/workflows.md
  3. references/api-reference.md
  4. assets/template.md
  5. references/standards.md  (only if query mentions compliance/standard/regulation)

Context budget: if total chars would exceed MAX_CONTEXT_CHARS, drop lowest-priority
files first, never drop SKILL.md.
"""

import re
from pathlib import Path
from typing import Optional

from .config import SKILLS_DIR, MAX_CONTEXT_CHARS


# ── File priority list (index = priority; lower = higher priority) ─────────

_REF_FILES = [
    "SKILL.md",
    "references/workflows.md",
    "references/api-reference.md",
    "assets/template.md",
    "references/standards.md",
]

_COMPLIANCE_KEYWORDS = {
    "compliance", "standard", "regulation", "pci", "hipaa", "soc2",
    "nist", "gdpr", "iso", "cis", "cmmc", "audit",
}


def _skill_dir(skill: dict) -> Path:
    """Return the skill's directory as a Path."""
    p = skill.get("path")
    if p:
        path = Path(p)
        if path.exists():
            return path
    return SKILLS_DIR / skill["slug"]


def _is_compliance_query(query: str) -> bool:
    q = query.lower()
    return any(kw in q for kw in _COMPLIANCE_KEYWORDS)


def load_skill(skill: dict, query: str = "") -> str:
    """
    Load and concatenate all available files for a skill, respecting
    the context budget. Returns a formatted string ready for injection.
    """
    skill_dir = _skill_dir(skill)
    slug = skill["slug"]

    # Determine which files to attempt
    files_to_load = list(_REF_FILES)
    if not _is_compliance_query(query):
        files_to_load.remove("references/standards.md")

    # Read files that exist
    loaded: list[tuple[str, str]] = []  # (filename, content)
    for rel_path in files_to_load:
        full_path = skill_dir / rel_path
        if full_path.exists():
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                loaded.append((rel_path, content))
            except Exception:
                pass

    # Budget management: drop lowest-priority files until under budget
    # SKILL.md (index 0) is never dropped
    while len(loaded) > 1:
        total = sum(len(c) for _, c in loaded)
        if total <= MAX_CONTEXT_CHARS:
            break
        # Drop the last (lowest-priority) file
        removed = loaded.pop()
        _ = removed  # discard

    # Format the output
    parts = [f"### Skill: `{slug}`\n"]
    for rel_path, content in loaded:
        if rel_path != "SKILL.md":
            label = Path(rel_path).stem.replace("-", " ").title()
            parts.append(f"\n#### {label}\n")
        parts.append(content.strip())
        parts.append("\n")

    return "\n".join(parts)


def load_skills_block(skills: list[dict], query: str = "") -> str:
    """
    Load multiple skills and wrap in a <SKILLS> block for system injection.
    Returns empty string if no skills.
    """
    if not skills:
        return ""

    parts = ["<SKILLS>", ""]
    for i, skill in enumerate(skills):
        parts.append(load_skill(skill, query))
        if i < len(skills) - 1:
            parts.append("\n---\n")
    parts.append("</SKILLS>")

    return "\n".join(parts)


def skill_summary(skill: dict) -> str:
    """One-line summary of a skill for display/logging."""
    return f"[{skill.get('subdomain', '?')}] {skill['slug']}"
