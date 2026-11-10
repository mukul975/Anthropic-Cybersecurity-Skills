#!/usr/bin/env python3
"""Generate index.json from the SKILL.md files under skills/.

Previously this logic lived as an inline heredoc inside
.github/workflows/update-index.yml with a hand-rolled regex YAML parser that
truncated 604 of 817 descriptions. It lives here now so it is testable outside
CI and shares one PyYAML-backed parser with every other tool.

Usage:
    python tools/generate-index.py            # write index.json
    python tools/generate-index.py --check    # verify index.json is current (CI)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_frontmatter import description_of, iter_skill_dirs, load_frontmatter, FrontmatterError

INDEX_VERSION = "1.1.0"
REPOSITORY = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills"
DEFAULT_DOMAIN = "cybersecurity"


def build_index(skills_dir: str = "skills") -> tuple[dict, list[str]]:
    """Build the index payload. Returns (index, errors)."""
    skills = []
    errors = []

    for slug, skill_dir in iter_skill_dirs(skills_dir):
        try:
            frontmatter = load_frontmatter(os.path.join(skill_dir, "SKILL.md"))
        except FrontmatterError as exc:
            errors.append(f"{slug}: {exc}")
            continue

        description = description_of(frontmatter)
        if not description:
            errors.append(f"{slug}: empty description")

        skills.append({
            "name": slug,
            "description": description,
            "domain": frontmatter.get("domain") or DEFAULT_DOMAIN,
            "path": f"{skills_dir}/{slug}",
        })

    index = {
        "version": INDEX_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": REPOSITORY,
        "domain": DEFAULT_DOMAIN,
        "total_skills": len(skills),
        "skills": skills,
    }
    return index, errors


def _comparable(index: dict) -> str:
    """Serialize an index ignoring generated_at, so --check tolerates a re-run."""
    return json.dumps({k: v for k, v in index.items() if k != "generated_at"}, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="verify index.json matches the skills tree; do not write")
    parser.add_argument("--skills-dir", default="skills")
    parser.add_argument("--out", default="index.json")
    args = parser.parse_args()

    if not os.path.isdir(args.skills_dir):
        print(f"ERROR: '{args.skills_dir}' not found. Run from the repository root.")
        return 1

    index, errors = build_index(args.skills_dir)

    for error in errors:
        print(f"ERROR {error}")
    if errors:
        print(f"\n{len(errors)} skill(s) could not be indexed.")
        return 1

    current = None
    if os.path.isfile(args.out):
        with open(args.out, encoding="utf-8") as handle:
            current = json.load(handle)
    up_to_date = current is not None and _comparable(current) == _comparable(index)

    if up_to_date:
        # Leave the file alone: rewriting only generated_at would produce a
        # no-op commit on every run of the sync workflow.
        print(f"OK: {args.out} is up to date ({index['total_skills']} skills)")
        return 0

    if args.check:
        state = "missing" if current is None else "out of date"
        print(f"ERROR: {args.out} is {state}. Run: python tools/generate-index.py")
        return 1

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(index, handle, separators=(",", ":"))

    print(f"Updated {args.out}: {index['total_skills']} skills")
    return 0


if __name__ == "__main__":
    sys.exit(main())
