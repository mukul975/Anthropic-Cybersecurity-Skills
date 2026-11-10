#!/usr/bin/env python3
"""Write the current skill count into README.md and the plugin manifests.

Previously an inline heredoc in .github/workflows/update-index.yml. It lives
here so it can be run and tested outside CI, and counts skills with the same
iter_skill_dirs() that generate-index.py uses, so the two can never disagree.

Usage:
    python tools/sync-skill-count.py
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_frontmatter import iter_skill_dirs

README = "README.md"
MANIFESTS = (".claude-plugin/marketplace.json", ".claude-plugin/plugin.json")

# Every place README.md states the count, as (pattern, replacement-prefix).
# The number itself is always the part matched by \d+.
README_PATTERNS = (
    r"(badge/skills-)\d+",
    r"()\b\d+(?=\s+production-grade cybersecurity skills)",
    r"()\b\d+(?=\s+structured cybersecurity skills)",
    r"(all\s+)\d+(?=\s+skills)",
    r"(Scans\s+)\d+(?=\s+skill\b)",
    r"(contains\s+\*\*)\d+(?=\s+skills\*\*)",
    r"(\{)\d+(?=\s+structured cybersecurity skills)",
)
MANIFEST_PATTERN = r"()\b\d+(?=\s+cybersecurity skills)"


def _apply(text: str, patterns, count: int) -> str:
    for pattern in patterns:
        text = re.sub(pattern, rf"\g<1>{count}", text)
    return text


def _rewrite(path: str, patterns, count: int, validate=None) -> None:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    text = _apply(text, patterns, count)
    if validate:
        validate(text)  # fail loudly before writing if a regex broke the file
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def main() -> int:
    if not os.path.isdir("skills"):
        print("ERROR: 'skills' not found. Run from the repository root.")
        return 1

    count = sum(1 for _ in iter_skill_dirs("skills"))
    _rewrite(README, README_PATTERNS, count)
    for path in MANIFESTS:
        _rewrite(path, (MANIFEST_PATTERN,), count, validate=json.loads)

    print(f"Synced skill count {count} into {README}, " + ", ".join(MANIFESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
