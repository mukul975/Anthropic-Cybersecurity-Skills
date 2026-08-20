# Skill Validation Tools

## validate-skill.py

Validate SKILL.md metadata and quality before submitting a PR.

### Usage

```bash
# Validate a single skill
python tools/validate-skill.py skills/my-new-skill/

# Validate all skills
python tools/validate-skill.py --all

# Run only specific checks
python tools/validate-skill.py --all --check tags,body,prereqs,safety

# Treat warnings as errors (useful for CI)
python tools/validate-skill.py --all --strict
```

### What it checks

#### Frontmatter checks (always run)

- SKILL.md exists in the skill directory
- Valid YAML frontmatter (between `---` markers)
- Required fields present: `name`, `description`, `domain`, `subdomain`, `tags`
- Name is kebab-case, 1–64 characters
- Description is at least 50 characters (no upper limit; multi-line folded scalars are valid)
- Domain is `cybersecurity`
- Subdomain is from the allowed list (aliases accepted with a warning)
- Tags is a list with at least 2 items

#### Tag quality (`--check tags`)

- Flags generic stop-words and filename-split tags that provide no agent routing value
- Catches tags like `analyzing`, `with`, `block`, `logs` — words split from the skill filename rather than meaningful cybersecurity terms
- Identifies tags that are too short (single character or empty)

#### Workflow completeness (`--check body`)

- **Required**: verifies the skill has a workflow / instructions / steps section
- **Recommended**: checks for When to Use, Prerequisites, and Output sections
- **Stub detection**: flags skills that list code-based prerequisites (e.g. `pip install boto3`) but have no code blocks in the workflow body — a sign of a stub skill that needs fleshing out

#### Prerequisite consistency (`--check prereqs`)

- Extracts library/tool names from the Prerequisites section (backtick-quoted names, `pip install` references)
- Checks whether each listed library actually appears in the workflow body
- Warns when a prerequisite is declared but never used (e.g. `requests` listed but no HTTP calls in the workflow)

#### Safety gates (`--check safety`)

- Identifies high-risk skills by subdomain (red-teaming, penetration-testing, purple-team) and by tag/name keywords (exploit, malware, credential access, phishing simulation, C2, brute-force, etc.)
- Flags high-risk skills that lack authorization, scope, or legal-notice language
- Accepts phrases like "authorized", "written permission", "rules of engagement", "legal notice", "lab environment", "for educational purposes"

### Requirements

Python 3.8+ (stdlib only, no external dependencies)
