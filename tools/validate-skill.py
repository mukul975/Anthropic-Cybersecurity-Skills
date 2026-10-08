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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from skill_frontmatter import load_frontmatter, FrontmatterError

# Kept in sync with the CI workflow (.github/workflows/validate-skills.yml),
# which now delegates to this script so there is a single source of truth.
REQUIRED_FIELDS = ["name", "description", "domain", "subdomain", "tags",
                   "version", "author", "license"]

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
    "hardware-firmware-security": {"hardware-firmware-security", "firmware-analysis", "firmware-security"},
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


def validate_skill(skill_dir):
    """Validate a single skill directory. Returns list of error strings."""
    errors = []
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"SKILL.md not found in {skill_dir}"]

    try:
        fm = load_frontmatter(skill_md)
    except FrontmatterError as e:
        return [str(e)]
    except IOError as e:
        return [f"Could not read SKILL.md: {e}"]

    # Check required fields.
    for field in REQUIRED_FIELDS:
        if field not in fm:
            errors.append(f"Missing required field: {field}")

    # Validate name.
    name = fm.get("name", "")
    if not isinstance(name, str):
        errors.append("Name must be a string")
    elif name:
        if not KEBAB_RE.match(name):
            errors.append(
                f"Name '{name}' is not valid kebab-case (lowercase letters, digits, hyphens only)"
            )
        if len(name) > 64:
            errors.append(f"Name too long ({len(name)} chars, max 64)")

    # Validate description. Multi-line descriptions are valid, so only a
    # minimum length is enforced here.
    desc = fm.get("description", "")
    if not isinstance(desc, str):
        errors.append("Description must be a string")
    elif len(desc) < DESCRIPTION_MIN_CHARS:
        errors.append(
            f"Description too short ({len(desc)} chars, min {DESCRIPTION_MIN_CHARS})"
        )

    # Validate domain.
    domain = fm.get("domain", "")
    if not isinstance(domain, str):
        errors.append("Domain must be a string")
    elif domain and domain != "cybersecurity":
        errors.append(f"Domain must be 'cybersecurity', got '{domain}'")

    # Validate subdomain.
    subdomain = fm.get("subdomain", "")
    if not isinstance(subdomain, str):
        errors.append("Subdomain must be a string")
    elif subdomain:
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
    if not isinstance(tags, list):
        errors.append("Tags must be a list")
    elif any(not isinstance(tag, str) for tag in tags):
        errors.append("Tags must contain only strings")
    elif len(tags) < 2:
        errors.append(f"Need at least 2 tags, got {len(tags)}")

    return errors


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <skill-dir> | --all")
        sys.exit(1)

    if sys.argv[1] == "--all":
        # Skip .bak backup directories — they are stale copies without a SKILL.md.
        # glob may return OS-native separators, so normalize before checking.
        skill_dirs = sorted(
            d for d in glob.glob("skills/*/")
            if not d.rstrip("/\\").endswith(".bak")
        )
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
