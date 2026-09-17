#!/usr/bin/env python3
"""Skill quality validator for Anthropic-Cybersecurity-Skills.

Usage:
    python tools/skill_quality_validator.py skills/
    python tools/skill_quality_validator.py --all
    python tools/skill_quality_validator.py skills/acquiring-disk-image-with-dd-and-dcfldd

The validator checks SKILL.md files for:
- frontmatter quality
- tag quality
- workflow completeness
- prerequisite consistency
- referenced asset/script existence
- framework mapping consistency
- high-risk safety gates

The default behavior exits non-zero only for FAIL findings. Use --strict to treat WARN as failures.
"""

import argparse
import glob
import os
import re
import sys
from collections import Counter, defaultdict

REQUIRED_FIELDS = [
    "name",
    "description",
    "domain",
    "subdomain",
    "tags",
    "version",
]
RECOMMENDED_FIELDS = ["author", "license"]
WEAK_TAG_DENYLIST = {
    "analyzing",
    "analysis",
    "with",
    "using",
    "logs",
    "block",
    "security",
    "assessment",
    "tooling",
    "process",
    "steps",
    "overview",
    "guide",
    "review",
    "investigation",
    "detection",
    "monitoring",
}
ALLOWED_SHORT_TAGS = {
    "dd",
    "os",
    "ip",
    "c2",
    "tls",
    "ssl",
    "rce",
    "xss",
    "sso",
    "idm",
    "api",
    "ids",
    "iot",
}

HIGH_RISK_TERMS = {
    "red teaming",
    "penetration testing",
    "malware analysis",
    "credential access",
    "phishing",
    "command and control",
    "c2",
    "exploit validation",
    "adversarial ai",
    "covert channel",
    "dropper",
    "shellcode",
    "backdoor",
    "persistence",
    "privilege escalation",
    "lateral movement",
    "impact assessment",
}

SAFETY_PHRASES = {
    "authorized",
    "authorization",
    "permission",
    "owned systems",
    "lab environment",
    "defensive investigation",
    "scope",
    "evidence handling",
    "do not target",
    "do not attack",
    "only on systems",
    "with permission",
    "lawful",
    "approval",
    "own systems",
    "defense-oriented",
    "responsible disclosure",
}

KNOWN_MAPPING_PATTERNS = {
    "mitre_attack": re.compile(r"^T\d{4}(?:\.\d+)?$", re.IGNORECASE),
    "nist_csf": re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$", re.IGNORECASE),
    "owasp": re.compile(r"^[A-Z]\d{2}$", re.IGNORECASE),
}

ALLOWED_SUBDOMAINS = {
    "identity-access-management",
    "identity-and-access-management",
    "identity-security",
    "zero-trust-architecture",
    "zero-trust",
    "ot-ics-security",
    "ot-security",
    "soc-operations",
    "security-operations",
    "red-teaming",
    "red-team",
    "web-application-security",
    "application-security",
    "network-security",
    "penetration-testing",
    "offensive-security",
    "digital-forensics",
    "malware-analysis",
    "threat-intelligence",
    "cloud-security",
    "container-security",
    "cryptography",
    "vulnerability-management",
    "compliance-governance",
    "governance-risk-compliance",
    "devsecops",
    "threat-hunting",
    "incident-response",
    "endpoint-security",
    "phishing-defense",
    "social-engineering-defense",
    "api-security",
    "mobile-security",
    "ransomware-defense",
    "threat-detection",
    "blockchain-security",
    "data-protection",
    "deception-technology",
    "firmware-analysis",
    "firmware-security",
    "privacy-compliance",
    "purple-team",
    "supply-chain-security",
    "wireless-security",
    "ai-security",
}

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
DESCRIPTION_MIN_CHARS = 50
FRONTMATTER_BOUNDARY = re.compile(r"^---\s*$", re.MULTILINE)
LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
EXPLICIT_PATH_PATTERN = re.compile(r"(?:^|\s)(scripts/[\w./-]+|assets/[\w./-]+|references/[\w./-]+|\./[\w./-]+|\../[\w./-]+)")


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    boundary = FRONTMATTER_BOUNDARY.findall(text)
    if len(boundary) < 2:
        return None
    # Find the first second boundary after the opening marker.
    end = text.find("---", 3)
    if end == -1:
        return None
    block = text[3:end].strip()
    data = {}
    current_key = None
    list_values = []
    in_folded = False
    folded_lines = []

    for line in block.splitlines():
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

        if stripped.startswith("- ") and current_key:
            list_values.append(stripped[2:].strip().strip('"').strip("'"))
            data[current_key] = list(list_values)
            continue

        inline_list = re.match(r"^(\w[\w_-]*):\s*\[(.+)\]\s*$", stripped)
        if inline_list:
            current_key = inline_list.group(1)
            items = [i.strip().strip('"').strip("'") for i in inline_list.group(2).split(",")]
            data[current_key] = items
            list_values = list(items)
            continue

        folded_start = re.match(r"^(\w[\w_-]*):\s*>[-|]?\s*$", stripped)
        if folded_start:
            current_key = folded_start.group(1)
            list_values = []
            in_folded = True
            folded_lines = []
            continue

        scalar = re.match(r"^(\w[\w_-]*):\s*(.*)$", stripped)
        if scalar:
            current_key = scalar.group(1)
            val = scalar.group(2).strip().strip('"').strip("'")
            list_values = []
            if val:
                data[current_key] = val
            continue

    if in_folded and current_key and folded_lines:
        data[current_key] = " ".join(folded_lines)

    return data


def get_body(text):
    if not text.startswith("---"):
        return text
    end = text.find("---", 3)
    if end == -1:
        return text
    return text[end + 3 :].strip()


def find_heading_section(body, heading):
    header_pattern = re.compile(rf"^(#+)\s*{re.escape(heading)}\s*$", re.MULTILINE | re.IGNORECASE)
    match = header_pattern.search(body)
    if not match:
        return None
    level = len(match.group(1))
    start = match.end()
    next_heading = re.compile(r"^#{1,%d}\s+" % level, re.MULTILINE)
    next_match = next_heading.search(body, start)
    return body[start: next_match.start() if next_match else len(body)].strip()


def extract_list_items(section_text):
    items = []
    if not section_text:
        return items
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("-") or stripped.startswith("*"):
            item = stripped[1:].strip()
            if item:
                items.append(item)
        elif re.match(r"^\d+\.\s+", stripped):
            item = re.sub(r"^\d+\.\s+", "", stripped)
            if item:
                items.append(item)
    return items


def normalize_term(value):
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def constant_word_search(text, token):
    return re.search(rf"\b{re.escape(token)}\b", text, flags=re.IGNORECASE) is not None


def find_relative_paths(text):
    paths = set()
    allowed_prefixes = (
        "assets/",
        "./assets/",
        "../assets/",
        "scripts/",
        "./scripts/",
        "../scripts/",
        "references/",
        "./references/",
        "../references/",
    )
    invalid_chars = set("{}[]()+*?<>|\\")

    for match in LINK_PATTERN.findall(text):
        target = match.split("#", 1)[0].strip()
        if not target or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
            continue
        if any(ch in target for ch in invalid_chars):
            continue
        if target.startswith(allowed_prefixes):
            paths.add(target)

    for match in EXPLICIT_PATH_PATTERN.findall(text):
        candidate = match.strip()
        if any(ch in candidate for ch in invalid_chars):
            continue
        if candidate.startswith(allowed_prefixes):
            paths.add(candidate)

    return paths


def is_high_risk_skill(name, tags, body):
    name_lower = name.lower()
    tags_lower = [t.lower() for t in tags]
    body_lower = body.lower()
    for term in HIGH_RISK_TERMS:
        if term in name_lower or term in body_lower or term in tags_lower:
            return True
    return False


def has_safety_language(body):
    content_lower = body.lower()
    return any(phrase in content_lower for phrase in SAFETY_PHRASES)


def is_tool_or_library_item(item):
    if not item:
        return False
    clean = item.strip('`"').strip()
    if not clean or len(clean) > 60:
        return False
    if " " in clean:
        return False
    if clean.lower().startswith(("linux", "windows", "macos", "mac", "unix", "knowledge", "experience", "access to", "permission", "understanding")):
        return False
    if re.search(r"[\/\\]", clean):
        return True
    if re.search(r"\.(py|sh|ps1|exe|bat|psm1|psd1)$", clean, re.IGNORECASE):
        return True
    if re.match(r"^[a-z0-9][a-z0-9._-]*$", clean, re.IGNORECASE):
        return True
    return False


def validate_skill(skill_dir):
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        return [("FAIL", "SKILL.md not found")]
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
    except (IOError, UnicodeDecodeError) as exc:
        return [("FAIL", f"Could not read SKILL.md: {exc}")]

    fm = parse_frontmatter(content)
    if fm is None:
        return [("FAIL", "No valid YAML frontmatter found (must start and end with ---)")]

    findings = []
    body = get_body(content)
    sections = {
        "when_to_use": find_heading_section(body, "When to Use"),
        "prerequisites": find_heading_section(body, "Prerequisites"),
        "workflow": find_heading_section(body, "Workflow"),
        "verification": find_heading_section(body, "Verification"),
        "output_format": find_heading_section(body, "Output Format"),
    }
    body_lower = body.lower()

    # Frontmatter fields.
    for field in REQUIRED_FIELDS:
        if field not in fm or fm[field] in (None, "") or (isinstance(fm[field], list) and not fm[field]):
            findings.append(("FAIL", f"Missing or empty required field: {field}"))

    for field in RECOMMENDED_FIELDS:
        if field not in fm or fm[field] in (None, "") or (isinstance(fm[field], list) and not fm[field]):
            findings.append(("WARN", f"Missing recommended field: {field}"))

    name = fm.get("name", "")
    if name:
        if not KEBAB_RE.match(name):
            findings.append(("FAIL", f"Name '{name}' is not valid kebab-case"))
        if len(name) > 64:
            findings.append(("FAIL", f"Name too long ({len(name)} chars, max 64)"))

    desc = fm.get("description", "")
    if isinstance(desc, list):
        findings.append(("FAIL", "Description must be a string, not a list"))
    elif isinstance(desc, str):
        if len(desc.strip()) < DESCRIPTION_MIN_CHARS:
            findings.append(("FAIL", f"Description too short ({len(desc.strip())} chars, min {DESCRIPTION_MIN_CHARS})"))

    domain = fm.get("domain", "")
    if domain and domain != "cybersecurity":
        findings.append(("FAIL", f"Domain must be 'cybersecurity', got '{domain}'"))

    subdomain = fm.get("subdomain", "")
    if subdomain:
        if subdomain not in ALLOWED_SUBDOMAINS:
            findings.append(("FAIL", f"Unknown subdomain '{subdomain}'"))

    tags = fm.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, list):
        findings.append(("FAIL", "Tags must be a list"))
        tags = []
    if len(tags) < 2:
        findings.append(("FAIL", f"At least 2 tags required, got {len(tags)}"))

    seen = Counter()
    for tag in tags:
        normalized = str(tag).strip()
        if normalized:
            seen[normalized.lower()] += 1
            weak_tag = normalized.lower() in WEAK_TAG_DENYLIST
            short_tag = len(normalized) < 3 and normalized.lower() not in ALLOWED_SHORT_TAGS
            if weak_tag:
                findings.append(("WARN", f"Weak tag: {normalized}"))
            elif short_tag:
                findings.append(("WARN", f"Tag is likely too short: {normalized}"))
    for tag, count in seen.items():
        if count > 1:
            findings.append(("WARN", f"Duplicate tag: {tag}"))

    if name and os.path.basename(skill_dir) != name:
        findings.append(("WARN", f"Directory name '{os.path.basename(skill_dir)}' does not match skill name '{name}'"))

    for label, section_text in sections.items():
        if label in ("when_to_use", "prerequisites", "workflow") and not section_text:
            findings.append(("WARN", f"Missing section: {label.replace('_', ' ').title()}"))
        if label in ("verification", "output_format") and not section_text:
            findings.append(("WARN", f"Recommended section missing: {label.replace('_', ' ').title()}"))

    if sections["prerequisites"]:
        prereq_items = extract_list_items(sections["prerequisites"])
        workflow_text = "\n".join(item for item in sections["workflow"].splitlines() if item) if sections["workflow"] else ""
        combined_text = f"{body_lower}\n{workflow_text.lower()}"
        for item in prereq_items:
            candidate = item.strip('`"').strip()
            if is_tool_or_library_item(candidate):
                if not constant_word_search(combined_text, candidate.lower()):
                    findings.append(("WARN", f"Prerequisite listed but not referenced in workflow/body: {candidate}"))

    for field, pattern in KNOWN_MAPPING_PATTERNS.items():
        values = fm.get(field)
        if values is None:
            continue
        if isinstance(values, str):
            values = [values]
        if not values:
            findings.append(("FAIL", f"Mapping field '{field}' present but empty"))
            continue
        duplicates = [value for value, count in Counter(values).items() if count > 1]
        for duplicate in duplicates:
            findings.append(("WARN", f"Duplicate mapping in '{field}': {duplicate}"))
        for value in values:
            if not pattern.match(str(value).strip()):
                findings.append(("WARN", f"Mapping '{field}' has unexpected format: {value}"))

    for path_ref in find_relative_paths(content):
        if path_ref.startswith("#") or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", path_ref):
            continue
        normalized = path_ref.lstrip("./")
        if not normalized or normalized.startswith("."):
            continue
        candidate = os.path.join(skill_dir, normalized)
        if not os.path.exists(candidate):
            findings.append(("FAIL", f"Referenced file does not exist: {path_ref}"))

    if is_high_risk_skill(name, tags, body):
        if not has_safety_language(body):
            findings.append(("WARN", "High-risk skill missing explicit authorization/scope/lab-use safety language"))

    return findings


def collect_skill_paths(root, recursive=True):
    root = os.path.abspath(root)
    if os.path.isfile(root) and os.path.basename(root).lower() == "skill.md":
        return [os.path.dirname(root)]
    if os.path.isdir(root):
        pattern = os.path.join(root, "**", "SKILL.md") if recursive else os.path.join(root, "SKILL.md")
        return sorted({os.path.dirname(path) for path in glob.glob(pattern, recursive=recursive)})
    return []


def print_findings(name, findings):
    if not findings:
        print(f"PASS {name}")
        return 1, 0
    had_fail = False
    had_warn = False
    print(f"{name}")
    for severity, message in findings:
        prefix = "FAIL" if severity == "FAIL" else "WARN"
        print(f"  {prefix}: {message}")
        if severity == "FAIL":
            had_fail = True
        else:
            had_warn = True
    return had_fail, had_warn


def main():
    parser = argparse.ArgumentParser(description="Validate skill quality for SKILL.md files.")
    parser.add_argument("root", nargs="?", default="skills", help="Skill root directory or path to a single skill folder")
    parser.add_argument("--all", action="store_true", help="Validate all SKILL.md files under the skills root")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    args = parser.parse_args()

    if args.all:
        if not os.path.isdir(args.root):
            print(f"ERROR: Path does not exist or is not a directory: {args.root}")
            sys.exit(2)
        skill_dirs = collect_skill_paths(args.root)
    else:
        path = os.path.abspath(args.root)
        if os.path.isdir(path):
            if os.path.basename(path).lower() == "skills":
                skill_dirs = collect_skill_paths(path)
            else:
                skill_dirs = [path]
        else:
            print(f"ERROR: Path does not exist or is not a directory: {args.root}")
            sys.exit(2)

    if not skill_dirs:
        print("No SKILL.md files found.")
        sys.exit(1)

    name_counts = Counter()
    skill_names = {}
    all_results = []
    for skill_dir in skill_dirs:
        skill_name = os.path.basename(skill_dir)
        findings = validate_skill(skill_dir)
        frontmatter = None
        if os.path.isfile(os.path.join(skill_dir, "SKILL.md")):
            with open(os.path.join(skill_dir, "SKILL.md"), encoding="utf-8") as f:
                content = f.read()
            fm = parse_frontmatter(content)
            if fm and fm.get("name"):
                skill_name = fm.get("name")
        name_counts[skill_name] += 1
        skill_names[skill_dir] = skill_name
        all_results.append((skill_dir, skill_name, findings))

    duplicates = [name for name, count in name_counts.items() if count > 1]
    if duplicates:
        for skill_dir, skill_name, findings in all_results:
            if skill_name in duplicates:
                findings.append(("FAIL", f"Duplicate skill name found: {skill_name}"))

    total = len(all_results)
    total_fail = 0
    total_warn = 0
    print("\nSkill quality report:\n")
    for skill_dir, skill_name, findings in all_results:
        fail, warn = print_findings(skill_name, findings)
        total_fail += int(fail)
        total_warn += int(warn)

    print("\nSummary:")
    print(f"  Skills checked: {total}")
    print(f"  Skills with FAILs: {total_fail}")
    print(f"  Skills with WARNs: {total_warn}")

    if total_fail > 0 or (args.strict and total_warn > 0):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
