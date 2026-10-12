# AGENTS.md

Instructions for AI agents working in this repository.

## What this repository is

A library of 817 cybersecurity skills. Each skill is a directory under `skills/` containing a `SKILL.md` — YAML frontmatter plus a Markdown procedure — following the [agentskills.io](https://agentskills.io) standard.

The layout is flat: `skills/<skill-name>/SKILL.md`. Do not nest skills by domain; agents discover them by scanning `skills/*/SKILL.md`.

## Reading a skill

Only `name` and `description` load at discovery time. The body loads once the description matches the request; `references/`, `scripts/` and `assets/` load only when referenced.

Read the description first. If it carries a negative trigger — "Do not use for X — use `other-skill`" — honour it. Those exist because two skills would otherwise compete for the same request.

## Changing a skill

Frontmatter is parsed by `tools/skill_frontmatter.py`, which uses PyYAML. Do not write a regex frontmatter parser; CI fails the build if it detects one. Three hand-rolled parsers previously truncated 604 of 817 descriptions to their first line.

After changing any `SKILL.md`:

```bash
pip install pyyaml
python tools/validate-skill.py --all
python tools/validate-agentskills.py --strict
python tools/generate-index.py          # regenerate index.json
python tools/lint-descriptions.py --all
python tools/detect-collisions.py
python tools/check-scripts.py           # compile every scripts/*.py
```

All of these run in CI. `index.json` is generated — never edit it by hand.

## Writing a description

The description is the only signal another agent sees when deciding whether to load the skill. It needs four things:

1. What it does, concretely.
2. `Use when …` — the phrasings a user would actually type.
3. `Keywords:` — tool names, event IDs, CVEs, API calls.
4. `Do not use for X — use other-skill.` — the negative trigger.

Keep it under 1024 characters. Keep the body under 500 lines; depth belongs in `references/`.

## Constraints

- `name` must equal the directory name, lowercase-kebab, ≤64 characters.
- `domain` is always `cybersecurity`. `subdomain` must be one the validator accepts — see CONTRIBUTING.md.
- Scripts must run. No placeholders, no invented API endpoints, no fabricated CVE numbers.
- Framework IDs must be real and current. A wrong mapping sends an investigation the wrong way; omit rather than guess.

## Scope

See [SCOPE.md](SCOPE.md). This repository holds skills. Runtimes, engines and applications belong elsewhere.
