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
- Required fields present: `name`, `description`, `domain`, `subdomain`, `tags`, `version`, `author`, `license`
- Name is kebab-case, 1–64 characters
- Description is at least 50 characters (agentskills.io caps it at 1024; `tools/validate-agentskills.py` enforces that)
- Domain is `cybersecurity`
- Subdomain is from the allowed list
- Tags is a list with at least 2 items

### Requirements

Python 3.8+ and PyYAML (`pip install pyyaml`).

All frontmatter is parsed by `skill_frontmatter.py`, the single PyYAML-backed loader. It replaced three hand-rolled regex parsers that silently truncated multi-line descriptions to their first line — that bug shipped 604 of 817 descriptions broken in `index.json`. Do not reintroduce regex frontmatter parsing; CI fails the build if it detects any.

## Generated files

`index.json`, the skill count in `README.md` and the plugin manifests, and the contributor wall in `README.md` are all generated. Never edit them by hand. `.github/workflows/sync-generated.yml` regenerates all three on every push to `main` (and weekly) and pushes the result in a single commit, so no two writers race on `README.md`.

| Script | Writes | Run it yourself when |
|---|---|---|
| `generate-index.py` | `index.json` (`--check` verifies it; CI runs that on PRs) | your PR adds or changes a skill |
| `sync-skill-count.py` | the skill count in `README.md`, `.claude-plugin/*.json` | never needed in a PR; CI does it on merge |
| `update-contributors.py` | the block between `<!-- contributors:start -->` and `<!-- contributors:end -->` in `README.md`, from the GitHub API | never needed; set `GITHUB_TOKEN` to avoid rate limits if you do |
