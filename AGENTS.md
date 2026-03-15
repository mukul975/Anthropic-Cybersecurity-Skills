# Repository Agents

`.agents/skills` is the canonical skill root for this repository.

If the repo root `skills/` entry exists, treat it as a compatibility-only symlink for older links and tooling.

Keep existing skill content and directory structure intact unless a change is required for Codex compatibility or metadata validation.

Prefer instruction-only skills. Only keep or add `scripts/`, `references/`, or `assets/` when they are already essential to the skill.

Before finishing changes, validate that every skill has `SKILL.md`, the YAML front matter parses cleanly, skill names are unique, and descriptions are not empty or placeholder text.
