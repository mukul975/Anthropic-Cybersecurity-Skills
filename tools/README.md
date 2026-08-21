# Skill Validation Tools

## validate-skill.py

Validate SKILL.md metadata before submitting a PR.

### Usage

```bash
# Validate a single skill
python tools/validate-skill.py skills/my-new-skill/

# Validate all skills
python tools/validate-skill.py --all
```

### What it checks

- SKILL.md exists in the skill directory
- Valid YAML frontmatter (between `---` markers)
- Required fields present: `name`, `description`, `domain`, `subdomain`, `tags`
- Name is kebab-case, 1–64 characters
- Description is at least 50 characters (no upper limit; multi-line folded scalars are valid)
- Domain is `cybersecurity`
- Subdomain is from the allowed list
- Tags is a list with at least 2 items

## skill_quality_validator.py

Validate SKILL.md skill quality and workflow completeness.

### Usage

```bash
# Validate all skills with warnings allowed
python tools/skill_quality_validator.py --all

# Validate a specific skill folder
python tools/skill_quality_validator.py skills/my-new-skill/

# Treat warnings as failures
python tools/skill_quality_validator.py --all --strict
```

### What it checks

- Required frontmatter fields and useful values
- Weak or duplicate tags
- Required workflow-focused sections
- Prerequisite consistency with workflow content
- Referenced assets, scripts, and references exist
- Known framework mapping syntax
- High-risk skills include safety language

### Requirements

Python 3.8+ (stdlib only, no external dependencies)
