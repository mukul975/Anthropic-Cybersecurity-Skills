# Skill Validation Tools

## check-scripts.py

Compile-check every helper script so a broken one cannot ship. SCOPE.md
requires every script to run; this is the cheapest guard against the rot
where a script does not even parse.

### Usage

```bash
# Check every skill
python tools/check-scripts.py

# Check one skill
python tools/check-scripts.py skills/my-new-skill/

# Machine-readable
python tools/check-scripts.py --json
```

### What it checks

- Every `scripts/*.py` compiles with the builtin `compile()` — which runs the
  parser **and** the symbol-table pass, so it catches not only bad syntax but
  errors such as `name 'x' is assigned to before global declaration`.
- Every `scripts/*.ps1` parses, **when** a PowerShell parser (`pwsh`) is on
  `PATH`. Without `pwsh` the PowerShell scripts are skipped with a note, not
  failed.

It does **not** execute scripts, resolve imports, write `.pyc` files, or judge
behaviour. It only proves the source is compilable. Exit code is non-zero if
any script fails.

### Requirements

Python 3.8+ (pure stdlib). `pwsh` is optional and only enables PowerShell
checks.

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
- Required fields present: `name`, `description`, `domain`, `subdomain`, `tags`, `version`, `author`, `license`
- Name is kebab-case, 1–64 characters
- Description is at least 50 characters (agentskills.io caps it at 1024; `tools/validate-agentskills.py` enforces that)
- Domain is `cybersecurity`
- Subdomain is from the allowed list
- Tags is a list with at least 2 items

### Requirements

Python 3.8+ and PyYAML (`pip install pyyaml`).

All frontmatter is parsed by `skill_frontmatter.py`, the single PyYAML-backed loader. It replaced three hand-rolled regex parsers that silently truncated multi-line descriptions to their first line — that bug shipped 604 of 817 descriptions broken in `index.json`. Do not reintroduce regex frontmatter parsing; CI fails the build if it detects any.
