#!/usr/bin/env python3
"""Skill metadata validation script for Anthropic-Cybersecurity-Skills.

Validates SKILL.md YAML frontmatter against the repository schema.

Usage:
    python tools/validate-skill.py skills/my-skill/      # validate one skill
    python tools/validate-skill.py --all                  # validate all skills
"""

import os
import re
import sys

# ── Constants ──────────────────────────────────────────────────────────────

REQUIRED_FIELDS = ["name", "description", "domain", "subdomain", "tags"]

KEBAB_CASE_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

ALLOWED_SUBDOMAINS = {
    "web-application-security",
    "network-security",
    "penetration-testing",
    "red-teaming",
    "digital-forensics",
    "malware-analysis",
    "threat-intelligence",
    "cloud-security",
    "container-security",
    "identity-access-management",
    "cryptography",
    "vulnerability-management",
    "compliance-governance",
    "zero-trust-architecture",
    "ot-ics-security",
    "devsecops",
    "threat-hunting",
    "soc-operations",
    "incident-response",
    "endpoint-security",
    "phishing-defense",
    "api-security",
    "mobile-security",
    "ransomware-defense",
}

# ── ANSI colours ───────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def pass_msg(skill: str) -> str:
    return f"  {GREEN}✔ PASS{RESET}  {skill}"


def fail_msg(skill: str, reason: str) -> str:
    return f"  {RED}✘ FAIL{RESET}  {skill}: {reason}"


# ── Minimal YAML frontmatter parser (stdlib only) ─────────────────────────

def parse_frontmatter(text: str) -> dict | None:
    """Extract YAML frontmatter between --- markers and parse key-value pairs.

    Handles scalar values and simple inline lists like [a, b, c].
    Returns None if no valid frontmatter found.
    """
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return None

    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return None

    data: dict = {}
    for line in lines[1:end]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()

        # Inline list: [item1, item2, ...]
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1]
            items = [v.strip().strip('"').strip("'") for v in inner.split(",") if v.strip()]
            data[key] = items
        else:
            # Strip surrounding quotes
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            data[key] = value

    return data


# ── Validation ─────────────────────────────────────────────────────────────

def validate_skill(skill_dir: str) -> list[str]:
    """Validate a single skill directory. Returns list of error strings (empty = pass)."""
    errors: list[str] = []
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        errors.append("SKILL.md not found")
        return errors

    with open(skill_md, "r", encoding="utf-8") as f:
        content = f.read()

    meta = parse_frontmatter(content)
    if meta is None:
        errors.append("No valid YAML frontmatter (missing --- markers)")
        return errors

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in meta:
            errors.append(f"Missing required field: {field}")

    # If missing fields, remaining checks may not apply
    if errors:
        return errors

    # name: kebab-case, 1-64 chars
    name = meta["name"]
    if not isinstance(name, str) or not KEBAB_CASE_RE.match(name) or len(name) > 64:
        errors.append(
            f"name '{name}' must be kebab-case (a-z0-9 and hyphens), 1-64 chars"
        )

    # description: 20-500 chars
    desc = meta["description"]
    if not isinstance(desc, str) or not (20 <= len(desc) <= 500):
        length = len(desc) if isinstance(desc, str) else 0
        errors.append(f"description length {length} not in 20-500 range")

    # domain == cybersecurity
    domain = meta["domain"]
    if domain != "cybersecurity":
        errors.append(f"domain must be 'cybersecurity', got '{domain}'")

    # subdomain in allowed list
    subdomain = meta["subdomain"]
    if subdomain not in ALLOWED_SUBDOMAINS:
        errors.append(f"subdomain '{subdomain}' not in allowed list")

    # tags: list with >= 2 items
    tags = meta["tags"]
    if not isinstance(tags, list) or len(tags) < 2:
        count = len(tags) if isinstance(tags, list) else 0
        errors.append(f"tags must be a list with >= 2 items (got {count})")

    return errors


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <skill-dir> | --all")
        sys.exit(2)

    # Determine repo root (for --all)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    skills_root = os.path.join(repo_root, "skills")

    if sys.argv[1] == "--all":
        if not os.path.isdir(skills_root):
            print(f"{RED}skills/ directory not found at {skills_root}{RESET}")
            sys.exit(2)
        skill_dirs = sorted(
            os.path.join(skills_root, d)
            for d in os.listdir(skills_root)
            if os.path.isdir(os.path.join(skills_root, d))
        )
    else:
        skill_dirs = [sys.argv[1].rstrip("/")]

    passed = 0
    failed = 0

    print(f"\n{BOLD}Validating {len(skill_dirs)} skill(s)…{RESET}\n")

    for skill_dir in skill_dirs:
        skill_name = os.path.basename(skill_dir)
        errors = validate_skill(skill_dir)
        if not errors:
            print(pass_msg(skill_name))
            passed += 1
        else:
            for err in errors:
                print(fail_msg(skill_name, err))
            failed += 1

    print(f"\n{BOLD}Summary:{RESET} {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET} out of {passed + failed} skill(s).\n")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
