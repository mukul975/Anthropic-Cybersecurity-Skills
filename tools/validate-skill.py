#!/usr/bin/env python3
"""Validate SKILL.md metadata for the Anthropic-Cybersecurity-Skills repository.

Usage:
    python tools/validate-skill.py skills/my-skill/
    python tools/validate-skill.py --all
"""
import os
import re
import sys
import glob

REQUIRED_FIELDS = ["name", "description", "domain", "subdomain", "tags"]

ALLOWED_SUBDOMAINS = {
    "web-application-security", "network-security", "penetration-testing",
    "red-teaming", "digital-forensics", "malware-analysis", "threat-intelligence",
    "cloud-security", "container-security", "identity-access-management",
    "cryptography", "vulnerability-management", "compliance-governance",
    "zero-trust-architecture", "ot-ics-security", "devsecops", "threat-hunting",
    "soc-operations", "incident-response", "endpoint-security", "phishing-defense",
    "api-security", "mobile-security", "ransomware-defense",
}

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def parse_frontmatter(text):
    """Extract YAML frontmatter as a dict (simple parser, stdlib only)."""
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end == -1:
        return None
    block = text[3:end].strip()
    data = {}
    current_key = None
    list_values = []
    for line in block.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Handle list items
        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list_values
            continue
        # Handle inline list: tags: [a, b, c]
        match = re.match(r"^(\w[\w_-]*):\s*\[(.+)\]\s*$", stripped)
        if match:
            current_key = match.group(1)
            items = [i.strip().strip('"').strip("'") for i in match.group(2).split(",")]
            data[current_key] = items
            list_values = items
            continue
        # Handle key: value
        match = re.match(r'^(\w[\w_-]*):\s*(.*)$', stripped)
        if match:
            current_key = match.group(1)
            val = match.group(2).strip().strip('"').strip("'")
            if val:
                data[current_key] = val
                list_values = []
            else:
                list_values = []
            continue
    return data


def validate_skill(skill_dir):
    """Validate a single skill directory. Returns list of errors."""
    errors = []
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"SKILL.md not found in {skill_dir}"]

    with open(skill_md, encoding="utf-8") as f:
        content = f.read()

    fm = parse_frontmatter(content)
    if fm is None:
        return [f"No valid YAML frontmatter found (must start with ---)"]

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in fm:
            errors.append(f"Missing required field: {field}")

    # Validate name
    name = fm.get("name", "")
    if name:
        if not KEBAB_RE.match(name):
            errors.append(f"Name '{name}' is not valid kebab-case (lowercase, hyphens only)")
        if len(name) > 64:
            errors.append(f"Name too long ({len(name)} chars, max 64)")

    # Validate description
    desc = fm.get("description", "")
    if isinstance(desc, str):
        if len(desc) < 20:
            errors.append(f"Description too short ({len(desc)} chars, min 20)")
        if len(desc) > 500:
            errors.append(f"Description too long ({len(desc)} chars, max 500)")

    # Validate domain
    domain = fm.get("domain", "")
    if domain and domain != "cybersecurity":
        errors.append(f"Domain must be 'cybersecurity', got '{domain}'")

    # Validate subdomain
    subdomain = fm.get("subdomain", "")
    if subdomain and subdomain not in ALLOWED_SUBDOMAINS:
        errors.append(f"Unknown subdomain '{subdomain}'. Allowed: {', '.join(sorted(ALLOWED_SUBDOMAINS))}")

    # Validate tags
    tags = fm.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]
    if len(tags) < 2:
        errors.append(f"Need at least 2 tags, got {len(tags)}")

    return errors


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <skill-dir> | --all")
        sys.exit(1)

    if sys.argv[1] == "--all":
        skill_dirs = sorted(glob.glob("skills/*/"))
    else:
        skill_dirs = [sys.argv[1].rstrip("/") + "/"]

    total = 0
    passed = 0
    failed = 0

    for skill_dir in skill_dirs:
        if not os.path.isdir(skill_dir.rstrip("/")):
            print(f"{RED}SKIP{RESET} {skill_dir} — not a directory")
            continue

        total += 1
        errors = validate_skill(skill_dir.rstrip("/"))

        name = os.path.basename(skill_dir.rstrip("/"))
        if errors:
            failed += 1
            print(f"{RED}FAIL{RESET} {name}")
            for e in errors:
                print(f"      {YELLOW}→ {e}{RESET}")
        else:
            passed += 1
            print(f"{GREEN}PASS{RESET} {name}")

    print(f"\n{'='*50}")
    print(f"Total: {total}  {GREEN}Passed: {passed}{RESET}  {RED}Failed: {failed}{RESET}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
