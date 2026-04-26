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

# Canonical subdomain → set of accepted aliases (including canonical itself).
# When a skill uses an alias, the validator accepts it but the canonical form
# is the first entry in each group below.  New skills should use the canonical.
_SUBDOMAIN_ALIASES = {
    # identity
    "identity-access-management": {"identity-access-management", "identity-and-access-management", "identity-security"},
    # zero-trust
    "zero-trust-architecture": {"zero-trust-architecture", "zero-trust"},
    # OT/ICS
    "ot-ics-security": {"ot-ics-security", "ot-security"},
    # SOC / security ops
    "soc-operations": {"soc-operations", "security-operations"},
    # red team
    "red-teaming": {"red-teaming", "red-team"},
    # standalone (no aliases)
    "web-application-security": {"web-application-security", "application-security"},
    "network-security": {"network-security"},
    "penetration-testing": {"penetration-testing", "offensive-security"},
    "digital-forensics": {"digital-forensics"},
    "malware-analysis": {"malware-analysis"},
    "threat-intelligence": {"threat-intelligence"},
    "cloud-security": {"cloud-security"},
    "container-security": {"container-security"},
    "cryptography": {"cryptography"},
    "vulnerability-management": {"vulnerability-management"},
    "compliance-governance": {"compliance-governance", "governance-risk-compliance"},
    "devsecops": {"devsecops"},
    "threat-hunting": {"threat-hunting"},
    "incident-response": {"incident-response"},
    "endpoint-security": {"endpoint-security"},
    "phishing-defense": {"phishing-defense", "social-engineering-defense"},
    "api-security": {"api-security"},
    "mobile-security": {"mobile-security"},
    "ransomware-defense": {"ransomware-defense"},
    "threat-detection": {"threat-detection"},
    "blockchain-security": {"blockchain-security"},
    "data-protection": {"data-protection"},
    "deception-technology": {"deception-technology"},
    "firmware-analysis": {"firmware-analysis", "firmware-security"},
    "privacy-compliance": {"privacy-compliance"},
    "purple-team": {"purple-team"},
    "supply-chain-security": {"supply-chain-security"},
    "wireless-security": {"wireless-security"},
    "ai-security": {"ai-security"},
}

# Flat set of all accepted subdomain values (canonical + aliases).
ALLOWED_SUBDOMAINS: set = {v for group in _SUBDOMAIN_ALIASES.values() for v in group}

# Reverse map: alias → canonical (for warning messages).
_ALIAS_TO_CANONICAL: dict = {}
for canonical, aliases in _SUBDOMAIN_ALIASES.items():
    for alias in aliases:
        _ALIAS_TO_CANONICAL[alias] = canonical

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Minimum description length.  Other repo tooling uses 50 chars; align here.
DESCRIPTION_MIN_CHARS = 50

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def parse_frontmatter(text):
    """Extract YAML frontmatter as a dict (simple stdlib-only parser).

    Handles the common SKILL.md patterns:
    - key: scalar value
    - key: [inline, list]
    - key:\n  - list\n  - items
    - key: >-  (folded scalar — content on following indented lines)

    Edge case note: ``list_values`` is reset to ``[]`` whenever a new key
    with a scalar value is encountered, so a list from a prior block cannot
    leak into an unrelated key.  The only remaining theoretical edge case is
    a key with *no* value that is immediately followed by non-list, non-empty
    lines that look like scalars — those lines are currently ignored (the key
    is treated as having no value).  This is acceptable for well-formed SKILL.md
    files and matches the behaviour contributors expect.
    """
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end == -1:
        return None
    block = text[3:end].strip()
    data = {}
    current_key = None
    list_values: list = []
    in_folded = False  # True when we are collecting a YAML >- / > folded scalar
    folded_lines: list = []

    for line in block.split("\n"):
        stripped = line.strip()

        # Flush a completed folded scalar when we hit the next top-level key.
        if in_folded and stripped and not line.startswith(" ") and not line.startswith("\t"):
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

        # Handle list items (must come before key: value to avoid misparse).
        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list(list_values)  # copy so future mutations don't leak
            continue

        # Handle inline list: tags: [a, b, c]
        m = re.match(r"^(\w[\w_-]*):\s*\[(.+)\]\s*$", stripped)
        if m:
            current_key = m.group(1)
            items = [i.strip().strip('"').strip("'") for i in m.group(2).split(",")]
            data[current_key] = items
            list_values = list(items)
            continue

        # Handle key: >- or key: > (folded scalar start)
        m = re.match(r"^(\w[\w_-]*):\s*>[-|]?\s*$", stripped)
        if m:
            current_key = m.group(1)
            list_values = []
            in_folded = True
            folded_lines = []
            continue

        # Handle key: value (plain scalar)
        m = re.match(r'^(\w[\w_-]*):\s*(.*)$', stripped)
        if m:
            current_key = m.group(1)
            val = m.group(2).strip().strip('"').strip("'")
            list_values = []  # reset; new scalar key cannot inherit a prior list
            if val:
                data[current_key] = val
            # If val is empty the key is present but value-less (e.g. start of block list)
            continue

    # Flush any trailing folded scalar.
    if in_folded and current_key and folded_lines:
        data[current_key] = " ".join(folded_lines)

    return data


def validate_skill(skill_dir):
    """Validate a single skill directory. Returns list of error strings."""
    errors = []
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"SKILL.md not found in {skill_dir}"]

    try:
        with open(skill_md, encoding="utf-8") as f:
            content = f.read()
    except IOError as e:
        return [f"Could not read SKILL.md: {e}"]
    except UnicodeDecodeError as e:
        return [f"Encoding error in SKILL.md (not valid UTF-8): {e}"]

    fm = parse_frontmatter(content)
    if fm is None:
        return ["No valid YAML frontmatter found (must start with ---)"]

    # Check required fields.
    for field in REQUIRED_FIELDS:
        if field not in fm:
            errors.append(f"Missing required field: {field}")

    # Validate name.
    name = fm.get("name", "")
    if name:
        if not KEBAB_RE.match(name):
            errors.append(
                f"Name '{name}' is not valid kebab-case (lowercase letters, digits, hyphens only)"
            )
        if len(name) > 64:
            errors.append(f"Name too long ({len(name)} chars, max 64)")

    # Validate description.
    desc = fm.get("description", "")
    if isinstance(desc, list):
        errors.append("Description must be a string value, not a list")
    elif isinstance(desc, str):
        if len(desc) < DESCRIPTION_MIN_CHARS:
            errors.append(
                f"Description too short ({len(desc)} chars, min {DESCRIPTION_MIN_CHARS})"
            )
        # No hard upper-limit enforced; multi-line folded scalars (>-) produce
        # long strings that are valid and common in this repo.

    # Validate domain.
    domain = fm.get("domain", "")
    if domain and domain != "cybersecurity":
        errors.append(f"Domain must be 'cybersecurity', got '{domain}'")

    # Validate subdomain.
    subdomain = fm.get("subdomain", "")
    if subdomain:
        if subdomain not in ALLOWED_SUBDOMAINS:
            errors.append(
                f"Unknown subdomain '{subdomain}'. Allowed: {', '.join(sorted(ALLOWED_SUBDOMAINS))}"
            )
        else:
            canonical = _ALIAS_TO_CANONICAL.get(subdomain, subdomain)
            if subdomain != canonical:
                # Warn (non-blocking) — alias is accepted but canonical is preferred
                print(
                    f"{YELLOW}WARN{RESET} subdomain '{subdomain}' is an alias;"
                    f" canonical form is '{canonical}'"
                )

    # Validate tags.
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
        if not skill_dirs:
            print("ERROR: No skill directories found. Run from the repository root.")
            sys.exit(1)
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
