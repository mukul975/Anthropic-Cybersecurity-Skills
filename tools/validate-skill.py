#!/usr/bin/env python3
"""Enhanced skill quality validator for the Anthropic-Cybersecurity-Skills repository.

Extends tools/validate-skill.py with four additional quality checks requested in
issue #86:

  1. Tag quality       — flags generic stop-words / filename-split tags
  2. Workflow body     — verifies presence of key sections (When to Use,
                         Prerequisites, Workflow/Instructions/Steps, Output)
  3. Prerequisite      — checks that libraries/tools listed in Prerequisites
                         actually appear in the workflow body
  4. Safety gates      — flags high-risk skills (red team, pentest, malware,
                         credential access, phishing, C2, exploit) that lack
                         authorization / scope / legal-notice language

Usage:
    python tools/validate-skill.py skills/my-skill/
    python tools/validate-skill.py --all
    python tools/validate-skill.py --all --check body,prereqs,safety

The --check flag selects which checks to run (comma-separated). Default: all.
Frontmatter checks (name, description, domain, subdomain, tags) always run.

Exit codes:
    0 = all checked skills pass
    1 = one or more skills have errors
    2 = usage / runtime error

Python 3.8+ (stdlib only, no external dependencies).
"""
import argparse
import os
import re
import sys
import glob

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Kept in sync with the CI workflow (.github/workflows/validate-skills.yml),
# which now delegates to this script so there is a single source of truth.
REQUIRED_FIELDS = ["name", "description", "domain", "subdomain", "tags",
                   "version", "author", "license"]

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
DESCRIPTION_MIN_CHARS = 50

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ---------------------------------------------------------------------------
# Subdomain definitions (mirrors tools/validate-skill.py)
# ---------------------------------------------------------------------------

_SUBDOMAIN_ALIASES = {
    "identity-access-management": {"identity-access-management", "identity-and-access-management", "identity-security"},
    "zero-trust-architecture": {"zero-trust-architecture", "zero-trust"},
    "ot-ics-security": {"ot-ics-security", "ot-security"},
    "soc-operations": {"soc-operations", "security-operations"},
    "red-teaming": {"red-teaming", "red-team"},
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

ALLOWED_SUBDOMAINS: set = {v for group in _SUBDOMAIN_ALIASES.values() for v in group}
_ALIAS_TO_CANONICAL: dict = {}
for _canon, _aliases in _SUBDOMAIN_ALIASES.items():
    for _alias in _aliases:
        _ALIAS_TO_CANONICAL[_alias] = _canon

# ---------------------------------------------------------------------------
# New: Tag-quality check
# ---------------------------------------------------------------------------

# Generic words that are filename-split artifacts or stop-words with no
# cybersecurity routing value.  These match the bugs identified in issue #49.
_WEAK_TAGS = {
    # filename-split words
    "analyzing", "performing", "detecting", "implementing", "building",
    "configuring", "conducting", "securing", "auditing", "scanning",
    "collecting", "investigating", "recovering", "remediating", "testing",
    "integrating", "managing", "mapping", "monitoring", "profiling",
    "prioritizing", "processing", "reverse", "engineering", "bypassing",
    "deobfuscating", "deploying", "tracking", "triaging", "validating",
    "correlating", "acquiring", "achieving", "bypassing",
    # stop-words / generic connectors
    "with", "and", "for", "the", "of", "in", "on", "to", "a", "an",
    "using", "use", "via", "through", "by",
    # vague generic terms
    "block", "logs", "activity", "script", "memory", "forensics",
    "security", "tool", "tools", "system", "systems", "network",
    "data", "analysis", "assessment", "report",
}

# Tags that are weak ONLY in certain contexts (too generic alone, but
# acceptable as part of a compound tag).  We flag single-word generic tags
# that match nothing domain-specific.
_GENERIC_TAGS = {
    "security", "tool", "tools", "system", "systems", "network",
    "data", "analysis", "assessment", "report", "logs", "activity",
    "script", "memory", "forensics",
}

# ---------------------------------------------------------------------------
# New: Workflow completeness check
# ---------------------------------------------------------------------------

# Section headers we look for (case-insensitive, prefix-matched).
# A skill should have at least an instructions/workflow section and an output section.
# A skill must have a workflow / instructions section.
_REQUIRED_SECTIONS = {
    "workflow": [r"^workflow$", r"^instructions$", r"^steps$",
                 r"^procedure$", r"^how\s+to", r"^phase\s+\d",
                 r"^tool\s+suite\s+components"],
}

_RECOMMENDED_SECTIONS = {
    "when_to_use": [r"^when\s+to\s+use", r"^use\s+cases",
                    r"^overview"],
    "prerequisites": [r"^prerequisites", r"^requirements",
                      r"^pre-?reqs"],
    "output": [r"^output", r"^expected\s+output",
               r"^results", r"^example", r"^examples",
               r"^example\s+output"],
}

# ---------------------------------------------------------------------------
# New: Prerequisite consistency check
# ---------------------------------------------------------------------------

# Common Python libraries that contributors list in Prerequisites.  We check
# whether the library name (or its import alias) appears somewhere in the
# workflow body.
_LIB_ALIASES = {
    "boto3": ["boto3"],
    "sslyze": ["sslyze"],
    "msal": ["msal"],
    "requests": ["requests", "request"],
    "python-evtx": ["python_evtx", "python-evtx", "Evtx"],
    "lxml": ["lxml"],
    "volatility": ["volatility", "vol"],
    "volatility3": ["volatility3", "vol3"],
    "scapy": ["scapy"],
    "yara": ["yara"],
    "impacket": ["impacket"],
    "pyshark": ["pyshark"],
    "netmiko": ["netmiko"],
    "paramiko": ["paramiko"],
    "dnspython": ["dnspython", "dns.resolver"],
    "python-whois": ["whois", "python-whois"],
    "shodan": ["shodan"],
    "censys": ["censys"],
    "virustotal": ["virustotal", "vt"],
    "pandas": ["pandas"],
    "numpy": ["numpy"],
    "matplotlib": ["matplotlib"],
    "pyelftools": ["pyelftools", "elftools"],
    "pefile": ["pefile"],
    "capstone": ["capstone"],
    "frida": ["frida"],
    "objection": ["objection"],
    "mobsf": ["mobsf"],
    "ghidra": ["ghidra"],
    "apktool": ["apktool"],
    "jadx": ["jadx"],
    "bloodhound": ["bloodhound", "bloodhound-ce"],
    "sharphound": ["sharphound"],
    "evil-winrm": ["evil-winrm", "evilwinrm"],
    "crackmapexec": ["crackmapexec", "cme", "netexec", "nxc"],
    "impacket-secretsdump": ["secretsdump", "impacket"],
    "hashcat": ["hashcat"],
    "john": ["john", "johntheripper"],
}

# ---------------------------------------------------------------------------
# New: Safety gate check
# ---------------------------------------------------------------------------

# Subdomains / tag keywords that indicate a high-risk skill requiring
# authorization / scope / legal-notice language.
_HIGH_RISK_SUBDOMAINS = {
    "red-teaming", "penetration-testing", "purple-team",
}

_HIGH_RISK_KEYWORDS = {
    "red-team", "red-teaming", "pentest", "penetration-test",
    "exploit", "exploitation", "malware", "ransomware",
    "credential-access", "credential-dumping", "kerberoasting",
    "phishing-simulation", "spearphishing", "social-engineering",
    "c2", "command-and-control", "beacon", "cobalt-strike",
    "sliver", "havoc", "metasploit", "evilginx",
    "brute-force", "hash-cracking", "privilege-escalation",
    "lateral-movement", "exfiltration", "man-in-the-middle",
    "sql-injection", "xss", "ssrf", "csrf",
}

# Phrases that satisfy the authorization/scope requirement.
_AUTH_PHRASES = [
    "authorization", "authorized", "written permission", "written consent",
    "rules of engagement", "scope", "legal notice", "legal disclaimer",
    "for authorized", "for educational", "for training",
    "lab environment", "test environment", "owned systems",
    "explicit permission", "prior approval", "engagement letter",
    "consent", "compliance with", "permissible",
    "do not own", "illegal", "unauthorized use",
    "contractual", "signed", "approved",
]


# ---------------------------------------------------------------------------
# Frontmatter parser (same as base validator)
# ---------------------------------------------------------------------------

def parse_frontmatter(text):
    """Extract YAML frontmatter as a dict (simple stdlib-only parser)."""
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end == -1:
        return None
    block = text[3:end].strip()
    data = {}
    current_key = None
    list_values: list = []
    in_folded = False
    folded_lines: list = []

    for line in block.split("\n"):
        stripped = line.strip()

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

        # Only process top-level (indent=0) lines as frontmatter fields.
        # Indented lines belong to nested YAML structures (e.g. mitre_f3:)
        # which we don't parse — skip them entirely to avoid corrupting
        # top-level fields like name: with nested key values.
        if line.startswith(" ") or line.startswith("\t"):
            continue

        # Handle list items (indent=0, starts with "- ")
        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list(list_values)
            continue

        # Handle inline list: tags: [a, b, c]
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

        m = re.match(r'^(\w[\w_-]*):\s*(.*)$', stripped)
        if m:
            current_key = m.group(1)
            val = m.group(2).strip().strip('"').strip("'")
            list_values = []
            if val:
                data[current_key] = val
            continue

    if in_folded and current_key and folded_lines:
        data[current_key] = " ".join(folded_lines)

    return data


# ---------------------------------------------------------------------------
# New: extract body (everything after frontmatter)
# ---------------------------------------------------------------------------

def extract_body(text):
    """Return the markdown body (everything after the YAML frontmatter)."""
    if not text.startswith("---"):
        return text
    end = text.find("---", 3)
    if end == -1:
        return text
    return text[end + 3:].strip()


# ---------------------------------------------------------------------------
# New: extract section headers from body
# ---------------------------------------------------------------------------

def get_sections(body):
    """Return list of (level, title) for all markdown headers in the body."""
    sections = []
    for line in body.split("\n"):
        m = re.match(r"^(#{1,6})\s+(.+)$", line)
        if m:
            sections.append((len(m.group(1)), m.group(2).strip()))
    return sections


def section_exists(sections, patterns):
    """Check whether any section title matches any of the regex patterns."""
    for _, title in sections:
        for pat in patterns:
            if re.match(pat, title, re.IGNORECASE):
                return True
    return False


# ---------------------------------------------------------------------------
# New: extract prerequisite libraries from Prerequisites section
# ---------------------------------------------------------------------------

def extract_prereq_libs(body):
    """Extract candidate library/tool names from the Prerequisites section.

    Looks for backtick-quoted names, pip install references, and common
    library naming patterns within the Prerequisites section.
    """
    # Find the Prerequisites section (between its header and the next ## header)
    prereq_section = []
    in_prereq = False
    for line in body.split("\n"):
        if re.match(r"^##\s+prereq", line, re.IGNORECASE):
            in_prereq = True
            continue
        if in_prereq and re.match(r"^##\s+", line):
            break
        if in_prereq:
            prereq_section.append(line)

    if not prereq_section:
        return []

    text = "\n".join(prereq_section)
    libs = set()

    # Match: pip install <name> or pip3 install <name>
    for m in re.finditer(r"pip3?\s+install\s+([a-zA-Z0-9_\-]+)", text):
        libs.add(m.group(1).lower())

    # Match: `name` (backtick-quoted)
    for m in re.finditer(r"`([a-zA-Z0-9_\-]+)`", text):
        candidate = m.group(1).lower()
        # Filter out obvious non-library terms
        if candidate not in {"python", "python3", "pip", "pip3", "git",
                             "windows", "linux", "macos", "docker",
                             "optional", "required", "recommended"}:
            libs.add(candidate)

    # Match: library name with library/requests/library in backticks
    for m in re.finditer(r"library\s+`?([a-zA-Z0-9_\-]+)`?", text, re.IGNORECASE):
        libs.add(m.group(1).lower())

    return list(libs)


# ---------------------------------------------------------------------------
# New: check if a library appears in the workflow body
# ---------------------------------------------------------------------------

def lib_in_body(lib_name, body_text):
    """Check whether a library name (or its known aliases) appears in the body."""
    aliases = _LIB_ALIASES.get(lib_name, [lib_name])
    for alias in aliases:
        # Case-insensitive search for the alias as a word
        if re.search(r'\b' + re.escape(alias) + r'\b', body_text, re.IGNORECASE):
            return True
    return False


# ---------------------------------------------------------------------------
# New: tag quality check
# ---------------------------------------------------------------------------

def check_tag_quality(tags, skill_name):
    """Return list of (severity, message) tuples for weak tags."""
    findings = []
    if isinstance(tags, str):
        tags = [tags]

    for tag in tags:
        tag_lower = tag.lower().strip()

        # Check against weak tags set
        if tag_lower in _WEAK_TAGS:
            findings.append(("warn", f"Weak tag '{tag}' — generic word with no routing value"))

        # Check for filename-split tags (tag is a word from the skill name)
        name_parts = set(skill_name.split("-"))
        if tag_lower in name_parts and tag_lower in _GENERIC_TAGS:
            findings.append(("warn", f"Weak tag '{tag}' — appears to be split from filename, not a domain term"))

        # Check for single-character or empty tags
        if len(tag_lower) <= 1:
            findings.append(("error", f"Tag '{tag}' is too short (min 2 chars)"))

    return findings


# ---------------------------------------------------------------------------
# New: workflow completeness check
# ---------------------------------------------------------------------------

def check_workflow_completeness(body, sections):
    """Return list of (severity, message) tuples for missing sections."""
    findings = []

    for section_name, patterns in _REQUIRED_SECTIONS.items():
        if not section_exists(sections, patterns):
            findings.append(("error", f"Missing required section: {section_name}"))

    for section_name, patterns in _RECOMMENDED_SECTIONS.items():
        if not section_exists(sections, patterns):
            findings.append(("warn", f"Missing recommended section: {section_name}"))

    # Check for stub workflows: skills that list code-based prerequisites
    # but have no code blocks (```), or very short bodies with no code.
    body_lines = body.split("\n")
    has_code = "```" in body
    prereq_libs = extract_prereq_libs(body)
    non_empty_lines = [l for l in body_lines if l.strip()]

    # Stub heuristic: lists Python/library prerequisites but has no code blocks
    if prereq_libs and not has_code:
        findings.append(("warn", "Prerequisites list code libraries but workflow has no code blocks — may be a stub"))

    # Stub heuristic: very short body with no code
    elif len(non_empty_lines) < 15 and not has_code:
        findings.append(("warn", "Workflow body is very short with no code blocks — may be a stub"))

    return findings


# ---------------------------------------------------------------------------
# New: prerequisite consistency check
# ---------------------------------------------------------------------------

def check_prereq_consistency(body):
    """Return list of (severity, message) tuples for unused prerequisites."""
    findings = []

    prereq_libs = extract_prereq_libs(body)
    if not prereq_libs:
        return findings

    # Get the workflow body (everything after Prerequisites section)
    # to avoid matching the prerequisite list itself
    workflow_body = []
    past_prereq = False
    for line in body.split("\n"):
        if re.match(r"^##\s+prereq", line, re.IGNORECASE):
            past_prereq = True
            continue
        if past_prereq and re.match(r"^##\s+", line):
            past_prereq = False
        if not past_prereq:
            workflow_body.append(line)

    workflow_text = "\n".join(workflow_body)

    for lib in prereq_libs:
        if not lib_in_body(lib, workflow_text):
            findings.append(("warn", f"Prerequisite '{lib}' listed but not referenced in workflow"))

    return findings


# ---------------------------------------------------------------------------
# New: safety gate check
# ---------------------------------------------------------------------------

def check_safety_gates(fm, body, sections, subdomain, tags):
    """Return list of (severity, message) tuples for missing safety language."""
    findings = []

    # Determine if this is a high-risk skill
    is_high_risk = False

    if subdomain and subdomain in _HIGH_RISK_SUBDOMAINS:
        is_high_risk = True

    if isinstance(tags, str):
        tags = [tags]
    for tag in tags:
        if tag.lower() in _HIGH_RISK_KEYWORDS:
            is_high_risk = True
            break

    # Also check skill name for high-risk keywords
    name = fm.get("name", "")
    for kw in _HIGH_RISK_KEYWORDS:
        if kw in name.lower():
            is_high_risk = True
            break

    # Also check subdomain aliases
    if subdomain:
        canonical = _ALIAS_TO_CANONICAL.get(subdomain, subdomain)
        if canonical in _HIGH_RISK_SUBDOMAINS:
            is_high_risk = True

    if not is_high_risk:
        return findings

    # Check for authorization / scope / legal-notice language
    body_lower = body.lower()
    has_auth = any(phrase in body_lower for phrase in _AUTH_PHRASES)

    if not has_auth:
        findings.append((
            "error",
            "High-risk skill (offensive/red-team/pentest) missing authorization, "
            "scope, or legal-notice language"
        ))

    return findings


# ---------------------------------------------------------------------------
# Core validation (frontmatter — same as base validator)
# ---------------------------------------------------------------------------

def validate_frontmatter(fm):
    """Validate frontmatter fields. Returns list of error strings."""
    errors = []

    for field in REQUIRED_FIELDS:
        if field not in fm:
            errors.append(f"Missing required field: {field}")

    name = fm.get("name", "")
    if name:
        if not KEBAB_RE.match(name):
            errors.append(f"Name '{name}' is not valid kebab-case")
        if len(name) > 64:
            errors.append(f"Name too long ({len(name)} chars, max 64)")

    desc = fm.get("description", "")
    if isinstance(desc, list):
        errors.append("Description must be a string value, not a list")
    elif isinstance(desc, str):
        if len(desc) < DESCRIPTION_MIN_CHARS:
            errors.append(f"Description too short ({len(desc)} chars, min {DESCRIPTION_MIN_CHARS})")

    domain = fm.get("domain", "")
    if domain and domain != "cybersecurity":
        errors.append(f"Domain must be 'cybersecurity', got '{domain}'")

    subdomain = fm.get("subdomain", "")
    if subdomain:
        if subdomain not in ALLOWED_SUBDOMAINS:
            errors.append(f"Unknown subdomain '{subdomain}'")

    tags = fm.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]
    if len(tags) < 2:
        errors.append(f"Need at least 2 tags, got {len(tags)}")

    return errors


# ---------------------------------------------------------------------------
# Full validation
# ---------------------------------------------------------------------------

def validate_skill(skill_dir, checks=None):
    """Validate a single skill directory.

    Args:
        skill_dir: path to the skill directory.
        checks: set of check names to run (None = all).
              Valid: 'body', 'prereqs', 'safety', 'tags'.

    Returns:
        (errors, warnings) lists of strings.
    """
    errors = []
    warnings = []

    if checks is None:
        checks = {"body", "prereqs", "safety", "tags"}

    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"SKILL.md not found in {skill_dir}"], []

    try:
        with open(skill_md, encoding="utf-8") as f:
            content = f.read()
    except IOError as e:
        return [f"Could not read SKILL.md: {e}"], []
    except UnicodeDecodeError as e:
        return [f"Encoding error in SKILL.md (not valid UTF-8): {e}"], []

    fm = parse_frontmatter(content)
    if fm is None:
        return ["No valid YAML frontmatter found (must start with ---)"], []

    # Frontmatter checks (always run)
    fm_errors = validate_frontmatter(fm)
    errors.extend(fm_errors)

    # Subdomain alias warning (non-blocking)
    subdomain = fm.get("subdomain", "")
    if subdomain and subdomain in ALLOWED_SUBDOMAINS:
        canonical = _ALIAS_TO_CANONICAL.get(subdomain, subdomain)
        if subdomain != canonical:
            warnings.append(f"subdomain '{subdomain}' is an alias; canonical form is '{canonical}'")

    # Extract body for new checks
    body = extract_body(content)
    sections = get_sections(body)

    # Tag quality check
    if "tags" in checks:
        tags = fm.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tag_findings = check_tag_quality(tags, fm.get("name", ""))
        for sev, msg in tag_findings:
            if sev == "error":
                errors.append(msg)
            else:
                warnings.append(msg)

    # Workflow completeness check
    if "body" in checks:
        body_findings = check_workflow_completeness(body, sections)
        for sev, msg in body_findings:
            if sev == "error":
                errors.append(msg)
            else:
                warnings.append(msg)

    # Prerequisite consistency check
    if "prereqs" in checks:
        prereq_findings = check_prereq_consistency(body)
        for sev, msg in prereq_findings:
            if sev == "error":
                errors.append(msg)
            else:
                warnings.append(msg)

    # Safety gate check
    if "safety" in checks:
        safety_findings = check_safety_gates(fm, body, sections, subdomain, fm.get("tags", []))
        for sev, msg in safety_findings:
            if sev == "error":
                errors.append(msg)
            else:
                warnings.append(msg)

    return errors, warnings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate SKILL.md files with enhanced quality checks."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to a skill directory, or '--all' to validate every skill.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all skills in the skills/ directory.",
    )
    parser.add_argument(
        "--check",
        default="all",
        help="Comma-separated checks to run: tags,body,prereqs,safety (default: all).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors (exit 1 if any warnings).",
    )
    args = parser.parse_args()

    # Resolve checks
    if args.check == "all":
        checks = {"body", "prereqs", "safety", "tags"}
    else:
        checks = set(c.strip() for c in args.check.split(","))
        valid = {"body", "prereqs", "safety", "tags"}
        invalid = checks - valid
        if invalid:
            print(f"Error: unknown check(s): {', '.join(invalid)}")
            print(f"Valid checks: {', '.join(sorted(valid))}")
            sys.exit(2)

    # Resolve skill directories
    if args.all:
        # Skip .bak backup directories — they are stale copies without a SKILL.md.
        # glob may return OS-native separators, so normalize before checking.
        skill_dirs = sorted(
            d for d in glob.glob("skills/*/")
            if not d.rstrip("/\\").endswith(".bak")
        )
        if not skill_dirs:
            print("ERROR: No skill directories found. Run from the repository root.")
            sys.exit(2)
    elif args.path:
        skill_dirs = [args.path.rstrip("/") + "/"]
    else:
        parser.print_help()
        sys.exit(2)

    total = 0
    passed = 0
    failed = 0
    warn_count = 0

    for skill_dir in skill_dirs:
        if not os.path.isdir(skill_dir.rstrip("/")):
            print(f"{RED}SKIP{RESET} {skill_dir} — not a directory")
            continue

        total += 1
        errors, warnings = validate_skill(skill_dir.rstrip("/"), checks)

        name = os.path.basename(skill_dir.rstrip("/"))
        if errors:
            failed += 1
            print(f"{RED}FAIL{RESET} {name}")
            for e in errors:
                print(f"      {RED}→ {e}{RESET}")
            for w in warnings:
                warn_count += 1
                print(f"      {YELLOW}⚠ {w}{RESET}")
        elif warnings:
            warn_count += len(warnings)
            if args.strict:
                failed += 1
                print(f"{RED}FAIL{RESET} {name} (strict mode: warnings are errors)")
                for w in warnings:
                    print(f"      {YELLOW}⚠ {w}{RESET}")
            else:
                passed += 1
                print(f"{YELLOW}PASS{RESET} {name} ({len(warnings)} warning(s))")
                for w in warnings:
                    print(f"      {YELLOW}⚠ {w}{RESET}")
        else:
            passed += 1
            print(f"{GREEN}PASS{RESET} {name}")

    print(f"\n{'='*60}")
    print(f"Total: {total}  {GREEN}Passed: {passed}{RESET}  {RED}Failed: {failed}{RESET}  {YELLOW}Warnings: {warn_count}{RESET}")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
